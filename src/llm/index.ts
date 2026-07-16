/**
 * T3MP3ST LLM Backbone
 *
 * Multi-provider LLM integration supporting:
 * - OpenRouter (recommended - access to Claude, GPT-4, Llama, etc.)
 * - Venice (OpenAI-compatible, privacy-focused / uncensored models)
 * - Anthropic (direct Claude access)
 * - OpenAI (GPT models)
 * - Mock (for testing)
 * - Local (Ollama, etc.)
 */

import { EventEmitter } from 'eventemitter3';
import { spawn } from 'child_process';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import type { LLMConfig, LLMMessage, LLMResponse, LLMProvider, LLMToolDefinition, LLMToolCall, FallbackEntry } from '../types/index.js';
import { config } from '../config/index.js';
import { localAgentChat } from '../agent/local-agents.js';

// =============================================================================
// LLM EVENTS
// =============================================================================

export interface LLMEvents {
  'request:start': { messages: LLMMessage[] };
  'request:complete': { response: LLMResponse; durationMs: number };
  'request:error': { error: Error; messages: LLMMessage[] };
  'request:retry': { attempt: number; maxAttempts: number; error: Error };
  /** Primary model returned a safety/policy refusal (a 200 that declined). */
  'request:refusal': { provider: string; model: string; preview: string };
  /** Fallback hop fired. reason = the failure that triggered it (refusal/empty/
   *  rate_limit/auth/timeout/server_error/context_length/…) or recovered_after:*. */
  'request:fallback': { fromModel: string; toModel: string | null; engaged: boolean; reason?: string };
  'token:stream': { token: string };
}

// =============================================================================
// PROVIDER ADAPTERS
// =============================================================================

export interface LLMProviderAdapter {
  name: string;
  chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse>;
  stream?(messages: LLMMessage[], options?: ChatOptions): AsyncGenerator<string, void, unknown>;
  validateConfig(): { valid: boolean; error?: string };
}

export interface ChatOptions {
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  stopSequences?: string[];
  systemPrompt?: string;
  /** Tool definitions for function calling */
  tools?: LLMToolDefinition[];
}

/**
 * Error class that carries HTTP status for rate-limit detection
 */
export class LLMApiError extends Error {
  status: number;
  retryAfterMs?: number;

  constructor(message: string, status: number, retryAfterMs?: number) {
    super(message);
    this.name = 'LLMApiError';
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

// API Response types
interface OpenRouterToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

interface OpenRouterResponse {
  choices: Array<{
    message?: { content?: string; tool_calls?: OpenRouterToolCall[] };
    delta?: { content?: string };
    finish_reason?: string;
  }>;
  model?: string;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

interface AnthropicContentBlock {
  type: 'text' | 'tool_use';
  text?: string;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
}

interface AnthropicResponse {
  content: AnthropicContentBlock[];
  model?: string;
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
  stop_reason?: string;
}

interface OllamaResponse {
  message?: { content?: string };
  model?: string;
  prompt_eval_count?: number;
  eval_count?: number;
}

// =============================================================================
// OPENROUTER ADAPTER
// =============================================================================

class OpenRouterAdapter implements LLMProviderAdapter {
  name = 'openrouter';
  protected config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = config;
  }

  validateConfig(): { valid: boolean; error?: string } {
    if (!this.config.apiKey) {
      return {
        valid: false,
        error: 'OpenRouter API key is required. Get one at https://openrouter.ai/keys',
      };
    }
    return { valid: true };
  }

  private formatMessages(messages: LLMMessage[]): Record<string, unknown>[] {
    return messages.map(m => {
      if (m.role === 'tool') {
        return { role: 'tool', content: m.content, tool_call_id: m.toolCallId, name: m.name };
      }
      if (m.role === 'assistant' && m.toolCalls?.length) {
        return {
          role: 'assistant',
          content: m.content || null,
          tool_calls: m.toolCalls.map(tc => ({
            id: tc.id, type: 'function' as const,
            function: { name: tc.name, arguments: JSON.stringify(tc.arguments) },
          })),
        };
      }
      return { role: m.role, content: m.content };
    });
  }

  private formatTools(tools?: LLMToolDefinition[]): Record<string, unknown>[] | undefined {
    if (!tools?.length) return undefined;
    return tools.map(t => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.parameters },
    }));
  }

  private parseToolCalls(raw?: OpenRouterToolCall[]): LLMToolCall[] | undefined {
    if (!raw?.length) return undefined;
    return raw.map(tc => ({
      id: tc.id,
      name: tc.function.name,
      arguments: JSON.parse(tc.function.arguments || '{}'),
    }));
  }

  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    const validation = this.validateConfig();
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const baseUrl = this.config.baseUrl || 'https://openrouter.ai/api/v1';
    const url = `${baseUrl}/chat/completions`;

    // Get site info from config
    const siteUrl = config.get('openrouter').siteUrl || 'https://github.com/tempest';
    const siteName = config.get('openrouter').siteName || 'T3MP3ST';

    const requestBody: Record<string, unknown> = {
      model: this.config.model,
      messages: this.formatMessages(messages),
      max_tokens: options?.maxTokens || this.config.maxTokens || 4096,
      temperature: options?.temperature ?? this.config.temperature ?? 0.7,
      top_p: options?.topP,
      stop: options?.stopSequences,
    };

    const tools = this.formatTools(options?.tools);
    if (tools) requestBody.tools = tools;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.config.apiKey}`,
        'HTTP-Referer': siteUrl,
        'X-Title': siteName,
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(this.config.timeout || 60000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `OpenRouter API error: ${response.status}`;

      try {
        const errorJson = JSON.parse(errorText);
        if (errorJson.error?.message) {
          errorMessage = errorJson.error.message;
        }
      } catch {
        errorMessage = `OpenRouter API error: ${response.status} - ${errorText}`;
      }

      // Parse Retry-After header for rate-limited responses
      const retryAfterHeader = response.headers.get('retry-after');
      const retryAfterMs = retryAfterHeader
        ? (parseInt(retryAfterHeader, 10) || 1) * 1000
        : undefined;

      throw new LLMApiError(errorMessage, response.status, retryAfterMs);
    }

    const data = await response.json() as OpenRouterResponse;
    const toolCalls = this.parseToolCalls(data.choices[0]?.message?.tool_calls);

    return {
      content: data.choices[0]?.message?.content || '',
      toolCalls,
      model: data.model || this.config.model,
      usage: data.usage
        ? {
            promptTokens: data.usage.prompt_tokens,
            completionTokens: data.usage.completion_tokens,
            totalTokens: data.usage.total_tokens,
          }
        : undefined,
      finishReason: data.choices[0]?.finish_reason,
    };
  }

  async *stream(messages: LLMMessage[], options?: ChatOptions): AsyncGenerator<string, void, unknown> {
    const validation = this.validateConfig();
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const baseUrl = this.config.baseUrl || 'https://openrouter.ai/api/v1';
    const url = `${baseUrl}/chat/completions`;

    const siteUrl = config.get('openrouter').siteUrl || 'https://github.com/tempest';
    const siteName = config.get('openrouter').siteName || 'T3MP3ST';

    const requestBody = {
      model: this.config.model,
      messages: messages.map(m => ({
        role: m.role,
        content: m.content,
      })),
      max_tokens: options?.maxTokens || this.config.maxTokens || 4096,
      temperature: options?.temperature ?? this.config.temperature ?? 0.7,
      stream: true,
    };

    // Stall guard: the streaming fetch previously had NO timeout, so a provider that opens the
    // connection then goes silent could hang the read loop forever. This is an INACTIVITY
    // (idle) timeout, deliberately NOT a total cap — it is reset on every received chunk, so a
    // legitimately long ACTIVE stream is never cut off; only a genuinely stalled/silent stream
    // is aborted (after config.timeout, default 60s of no data).
    const controller = new AbortController();
    const idleMs = this.config.timeout || 60000;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.config.apiKey}`,
        'HTTP-Referer': siteUrl,
        'X-Title': siteName,
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`OpenRouter API error: ${response.status}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';
    const idleTimer = setTimeout(() => { try { controller.abort(); } catch { /* noop */ } }, idleMs);

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        idleTimer.refresh(); // a chunk arrived — restart the inactivity countdown

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') return;

            try {
              const json = JSON.parse(data);
              const content = json.choices?.[0]?.delta?.content;
              if (content) yield content;
            } catch {
              // Ignore parse errors in stream
            }
          }
        }
      }
    } finally {
      clearTimeout(idleTimer);
      reader.releaseLock();
    }
  }
}

// =============================================================================
// VENICE ADAPTER
// =============================================================================
// Venice AI is OpenAI-compatible on the wire (Bearer auth, POST /chat/completions,
// identical request/response + tool-calling + SSE stream shape), so it reuses the entire
// OpenRouter adapter and only differs in its default base URL (set via the `venice` config
// block), its name, and the key-required error message. The optional HTTP-Referer/X-Title
// headers the parent sends are harmless (Venice ignores unknown headers).
class VeniceAdapter extends OpenRouterAdapter {
  name = 'venice';

  validateConfig(): { valid: boolean; error?: string } {
    if (!this.config.apiKey) {
      return {
        valid: false,
        error: 'Venice API key is required. Get one at https://venice.ai/settings/api',
      };
    }
    return { valid: true };
  }
}

// =============================================================================
// ANTHROPIC ADAPTER
// =============================================================================

class AnthropicAdapter implements LLMProviderAdapter {
  name = 'anthropic';
  private config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = config;
  }

  validateConfig(): { valid: boolean; error?: string } {
    if (!this.config.apiKey) {
      return {
        valid: false,
        error: 'Anthropic API key is required. Get one at https://console.anthropic.com/',
      };
    }
    return { valid: true };
  }

  private formatMessages(messages: LLMMessage[]): Record<string, unknown>[] {
    const formatted: Record<string, unknown>[] = [];
    for (const m of messages) {
      if (m.role === 'system') continue; // handled separately
      if (m.role === 'tool') {
        // Anthropic expects tool results as user messages with tool_result content blocks
        formatted.push({
          role: 'user',
          content: [{ type: 'tool_result', tool_use_id: m.toolCallId, content: m.content }],
        });
      } else if (m.role === 'assistant' && m.toolCalls?.length) {
        const content: Record<string, unknown>[] = [];
        if (m.content) content.push({ type: 'text', text: m.content });
        for (const tc of m.toolCalls) {
          content.push({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.arguments });
        }
        formatted.push({ role: 'assistant', content });
      } else {
        formatted.push({ role: m.role, content: m.content });
      }
    }
    return formatted;
  }

  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    const validation = this.validateConfig();
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const baseUrl = this.config.baseUrl || 'https://api.anthropic.com';
    const url = `${baseUrl}/v1/messages`;

    // Separate system message from other messages
    const systemMessage = messages.find(m => m.role === 'system');

    const requestBody: Record<string, unknown> = {
      model: this.config.model,
      messages: this.formatMessages(messages),
      max_tokens: options?.maxTokens || this.config.maxTokens || 4096,
      temperature: options?.temperature ?? this.config.temperature ?? 0.7,
    };

    if (systemMessage) {
      requestBody.system = systemMessage.content;
    }

    // Add tools in Anthropic format
    if (options?.tools?.length) {
      requestBody.tools = options.tools.map(t => ({
        name: t.name,
        description: t.description,
        input_schema: t.parameters,
      }));
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.config.apiKey ?? '',
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(this.config.timeout || 60000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = `Anthropic API error: ${response.status}`;

      try {
        const errorJson = JSON.parse(errorText);
        if (errorJson.error?.message) {
          errorMessage = errorJson.error.message;
        }
      } catch {
        errorMessage = `Anthropic API error: ${response.status} - ${errorText}`;
      }

      const retryAfterHeader = response.headers.get('retry-after');
      const retryAfterMs = retryAfterHeader
        ? (parseInt(retryAfterHeader, 10) || 1) * 1000
        : undefined;

      throw new LLMApiError(errorMessage, response.status, retryAfterMs);
    }

    const data = await response.json() as AnthropicResponse;

    // Extract text and tool calls from content blocks
    let textContent = '';
    const toolCalls: LLMToolCall[] = [];
    for (const block of data.content) {
      if (block.type === 'text' && block.text) {
        textContent += block.text;
      } else if (block.type === 'tool_use' && block.id && block.name) {
        toolCalls.push({ id: block.id, name: block.name, arguments: block.input || {} });
      }
    }

    return {
      content: textContent,
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      model: data.model || this.config.model,
      usage: data.usage
        ? {
            promptTokens: data.usage.input_tokens,
            completionTokens: data.usage.output_tokens,
            totalTokens: data.usage.input_tokens + data.usage.output_tokens,
          }
        : undefined,
      finishReason: data.stop_reason,
    };
  }
}

// =============================================================================
// OPENAI ADAPTER
// =============================================================================

class OpenAIAdapter implements LLMProviderAdapter {
  name = 'openai';
  private config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = config;
  }

  validateConfig(): { valid: boolean; error?: string } {
    if (!this.config.apiKey) {
      return {
        valid: false,
        error: 'OpenAI API key is required. Get one at https://platform.openai.com/api-keys',
      };
    }
    return { valid: true };
  }

  private formatMessages(messages: LLMMessage[]): Record<string, unknown>[] {
    return messages.map(m => {
      if (m.role === 'tool') {
        return { role: 'tool', content: m.content, tool_call_id: m.toolCallId, name: m.name };
      }
      if (m.role === 'assistant' && m.toolCalls?.length) {
        return {
          role: 'assistant',
          content: m.content || null,
          tool_calls: m.toolCalls.map(tc => ({
            id: tc.id, type: 'function' as const,
            function: { name: tc.name, arguments: JSON.stringify(tc.arguments) },
          })),
        };
      }
      return { role: m.role, content: m.content };
    });
  }

  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    const validation = this.validateConfig();
    if (!validation.valid) {
      throw new Error(validation.error);
    }

    const baseUrl = this.config.baseUrl || 'https://api.openai.com/v1';
    const url = `${baseUrl}/chat/completions`;

    const requestBody: Record<string, unknown> = {
      model: this.config.model,
      messages: this.formatMessages(messages),
      max_tokens: options?.maxTokens || this.config.maxTokens || 4096,
      temperature: options?.temperature ?? this.config.temperature ?? 0.7,
      top_p: options?.topP,
      stop: options?.stopSequences,
    };

    if (options?.tools?.length) {
      requestBody.tools = options.tools.map(t => ({
        type: 'function',
        function: { name: t.name, description: t.description, parameters: t.parameters },
      }));
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(this.config.timeout || 60000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json() as OpenRouterResponse;
    const rawToolCalls = data.choices[0]?.message?.tool_calls;
    const toolCalls: LLMToolCall[] | undefined = rawToolCalls?.length
      ? rawToolCalls.map(tc => ({
          id: tc.id,
          name: tc.function.name,
          arguments: JSON.parse(tc.function.arguments || '{}'),
        }))
      : undefined;

    return {
      content: data.choices[0]?.message?.content || '',
      toolCalls,
      model: data.model || this.config.model,
      usage: data.usage
        ? {
            promptTokens: data.usage.prompt_tokens,
            completionTokens: data.usage.completion_tokens,
            totalTokens: data.usage.total_tokens,
          }
        : undefined,
      finishReason: data.choices[0]?.finish_reason,
    };
  }
}

// =============================================================================
// MOCK ADAPTER (for testing)
// =============================================================================

class MockAdapter implements LLMProviderAdapter {
  name = 'mock';
  private responseDelay: number;
  private toolCallCounter: number = 0;

  constructor(_config: LLMConfig, responseDelay: number = 100) {
    this.responseDelay = responseDelay;
  }

  validateConfig(): { valid: boolean; error?: string } {
    return { valid: true };
  }

  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    await new Promise(resolve => setTimeout(resolve, this.responseDelay));

    const lastMessage = messages[messages.length - 1];

    // If tools are available and this isn't a tool result, simulate the LLM choosing a tool
    if (options?.tools?.length && lastMessage.role !== 'tool') {
      const content = lastMessage.content.toLowerCase();
      const tools = options.tools;

      // Smart tool selection based on context
      let selectedTool: LLMToolDefinition | undefined;
      let args: Record<string, unknown> = {};

      if (content.includes('dns') || content.includes('domain')) {
        selectedTool = tools.find(t => t.name === 'dns_lookup');
        const domainMatch = content.match(/(?:domain|target)[:\s]+(\S+)/i);
        args = { domain: domainMatch?.[1] || 'example.com', type: 'A' };
      } else if (content.includes('port') || content.includes('scan')) {
        selectedTool = tools.find(t => t.name === 'port_scan');
        const targetMatch = content.match(/(?:target|host|ip)[:\s]+(\S+)/i);
        args = { target: targetMatch?.[1] || '127.0.0.1', ports: '22,80,443,8080' };
      } else if (content.includes('header') || content.includes('security')) {
        selectedTool = tools.find(t => t.name === 'header_analysis');
        args = { url: 'http://example.com' };
      } else if (tools.length > 0) {
        // Default: pick the first relevant tool
        selectedTool = tools[0];
      }

      if (selectedTool) {
        this.toolCallCounter++;
        return {
          content: `Executing ${selectedTool.name} for reconnaissance...`,
          toolCalls: [{
            id: `mock_call_${this.toolCallCounter}`,
            name: selectedTool.name,
            arguments: args,
          }],
          model: 'mock-model',
          usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
          finishReason: 'tool_calls',
        };
      }
    }

    // Standard text response (no tools, or responding after tool results)
    const mockResponses: Record<string, string> = {
      recon: 'Reconnaissance complete. Identified 5 subdomains, 3 open ports, and 2 potential entry points.',
      scan: 'Vulnerability scan complete. Found 2 high-severity, 5 medium-severity vulnerabilities.',
      exploit: 'Exploitation attempt successful. Gained initial foothold via SQL injection.',
      default: `Mock response to: ${lastMessage.content.substring(0, 50)}...`,
    };

    const content = lastMessage.content.toLowerCase();
    let response = mockResponses.default;

    if (content.includes('recon') || content.includes('reconnaissance')) {
      response = mockResponses.recon;
    } else if (content.includes('scan') || content.includes('vulnerability')) {
      response = mockResponses.scan;
    } else if (content.includes('exploit')) {
      response = mockResponses.exploit;
    }

    return {
      content: response,
      model: 'mock-model',
      usage: {
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
      },
      finishReason: 'stop',
    };
  }
}

// =============================================================================
// LOCAL ADAPTER (Ollama, etc.)
// =============================================================================

// Local model over HTTP — a fully self-hosted, keyless backbone. Talks to Ollama's
// native /api/chat by default, or any OpenAI-compatible local server (LM Studio,
// vLLM, llama.cpp, Ollama's own /v1) when TEMPEST_LOCAL_BASE_URL is a /v1 endpoint.
// Tool-calling is done over TEXT (renderToolContract + parseTextToolCalls, defined
// below and shared with the CLI-agent adapters): it works on ANY local model,
// whether or not it supports native function-calling — without it a local model
// hits the keyless-path abstain bug (no toolCalls → ReAct bails turn 0 → Arsenal
// never runs).
class LocalAdapter implements LLMProviderAdapter {
  name = 'local';
  private config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = config;
  }

  validateConfig(): { valid: boolean; error?: string } {
    return { valid: true };
  }

  // A versioned base URL (/v1, /v2, /v4, …) means an OpenAI-compatible server
  // (/chat/completions, choices[]). Many OpenAI-compatible providers version their
  // API at paths other than /v1 (e.g. Zhipu/z.ai exposes /api/paas/v4), so match any
  // /vN rather than literally /v1.
  private isOpenAIWire(baseUrl: string): boolean {
    return /\/v\d+(\/|$)/.test(baseUrl);
  }

  // Inject the Arsenal contract as a system turn when tools are offered, and
  // sanitize prior tool-request / tool-result turns — a plain local model doesn't
  // understand role:'tool', and re-emitting a prior ```json``` block would get
  // re-parsed as a fresh live call (defeats termination). Its TEXT reply is parsed
  // back into tool calls after the round-trip.
  private buildMessages(messages: LLMMessage[], options?: ChatOptions): { role: string; content: string }[] {
    const contract = renderToolContract(options?.tools);
    const preamble = 'You are the planning brain for T3MP3ST, an authorized offensive-security harness.'
      + (contract
        ? ' You drive a ReAct loop: REQUEST tools, the harness runs them and returns results, you reason until the surface is exhausted.' + contract
        : ' Operate in planning and analysis mode; when JSON is requested, return ONLY the requested block — no preamble.');
    const systemParts = [preamble];
    const out: { role: string; content: string }[] = [];
    for (const m of messages) {
      if (m.role === 'system') {
        if (m.content.trim()) systemParts.push(m.content);
      } else if (m.role === 'assistant' && m.toolCalls?.length) {
        out.push({ role: 'assistant', content: `[requested tools: ${m.toolCalls.map(t => t.name).join(', ')}]` });
      } else if (m.role === 'tool') {
        out.push({ role: 'user', content: `TOOL RESULT (${m.name || 'tool'}):\n${m.content}` });
      } else {
        out.push({ role: m.role, content: m.content });
      }
    }
    return [{ role: 'system', content: systemParts.join('\n\n') }, ...out];
  }

  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    const baseUrl = (this.config.baseUrl || 'http://localhost:11434/api').replace(/\/$/, '');
    const openaiWire = this.isOpenAIWire(baseUrl);
    const url = `${baseUrl}/${openaiWire ? 'chat/completions' : 'chat'}`;
    const wireMessages = this.buildMessages(messages, options);
    const maxTokens = options?.maxTokens || this.config.maxTokens || 4096;
    const temperature = options?.temperature ?? this.config.temperature ?? 0.7;

    const requestBody = openaiWire
      ? { model: this.config.model, messages: wireMessages, max_tokens: maxTokens, temperature, stream: false }
      : { model: this.config.model, messages: wireMessages, stream: false, options: { num_predict: maxTokens, temperature } };

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Local OpenAI-compatible servers usually ignore auth, but LM Studio & co.
          // expect *some* bearer — send a dummy unless the operator set a real key.
          ...(openaiWire ? { Authorization: `Bearer ${this.config.apiKey || 'local'}` } : {}),
        },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(this.config.timeout || 120000),
      });

      if (!response.ok) {
        throw new Error(`Local LLM error: ${response.status}`);
      }

      const data = await response.json() as OllamaResponse & {
        choices?: Array<{ message?: { content?: string } }>;
        usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
      };
      const content = openaiWire ? (data.choices?.[0]?.message?.content || '') : (data.message?.content || '');

      // Tool-calling over text: if the Arsenal was offered, parse the model's tool
      // requests so the ReAct loop EXECUTES them instead of abstaining on turn 0.
      const toolCalls = options?.tools?.length ? parseTextToolCalls(content) : undefined;

      const usage = openaiWire
        ? (data.usage
            ? { promptTokens: data.usage.prompt_tokens, completionTokens: data.usage.completion_tokens, totalTokens: data.usage.total_tokens }
            : undefined)
        : (data.eval_count
            ? { promptTokens: data.prompt_eval_count || 0, completionTokens: data.eval_count || 0, totalTokens: (data.prompt_eval_count || 0) + (data.eval_count || 0) }
            : undefined);

      return {
        content,
        model: data.model || this.config.model,
        usage,
        finishReason: toolCalls?.length ? 'tool_calls' : 'stop',
        toolCalls,
      };
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error(
          'Could not connect to local LLM. Start Ollama (`ollama serve`), or point TEMPEST_LOCAL_BASE_URL at your OpenAI-compatible server (LM Studio / vLLM / llama.cpp).'
        );
      }
      throw error;
    }
  }
}

// =============================================================================
// CODEX ADAPTER (local Codex CLI/account subscription)
// =============================================================================

// ── tool-calling over a plain-text CLI agent (local-agent / codex backbones) ──
// These CLIs return TEXT, not structured tool_calls like an API — so historically
// the ReAct loop got no `toolCalls`, took its "final answer" branch on turn 0, and
// abstained without ever running the Arsenal (the keyless-path bug). Fix: describe
// the Arsenal + a strict JSON action-contract in the prompt, then parse the agent's
// text reply back into LLMToolCall[] so `arsenal.execute` actually runs the tools.
function renderToolContract(tools?: LLMToolDefinition[]): string {
  if (!tools?.length) return '';
  const lines = ['\n## ARSENAL — tools the HARNESS runs for you (you REQUEST them, it EXECUTES + returns the output):'];
  for (const t of tools) {
    const props = (t.parameters?.properties || {}) as Record<string, { type?: string }>;
    const req = new Set(t.parameters?.required || []);
    const sig = Object.entries(props).map(([k, v]) => `${k}${req.has(k) ? '*' : ''}: ${v.type || 'any'}`).join(', ');
    lines.push(`- ${t.name}(${sig}) — ${t.description}`);
  }
  lines.push(
    '',
    '## ACTION CONTRACT — follow EXACTLY:',
    '• To run one or more tools, reply with ONLY this fenced block, nothing else:',
    '```json',
    '{"tool_calls":[{"name":"<tool>","arguments":{ ... }}]}',
    '```',
    '  The harness runs them (scope-gated) and returns the results as new messages; then you reason again.',
    '• When the attack surface is exhausted and you are DONE, reply with your final debrief in prose (NO json block).',
    '• Never run these tools yourself — REQUEST them. Requesting is how you act.',
  );
  return lines.join('\n');
}

// Yield each brace-BALANCED {...} substring (string-aware). Linear + hard-budgeted, so it replaces a
// greedy /\{[\s\S]*\}/ that both over-matched (first-'{' to last-'}') and backtracked quadratically
// (ReDoS). Bounded work regardless of input shape (unbalanced braces, 80k '{', etc.).
function* balancedObjectSpans(text: string): Generator<string> {
  const n = text.length;
  let budget = 2_000_000; // total-scan cap → DoS-safe upper bound on worst-case work
  let spans = 0;
  for (let i = 0; i < n && spans < 200 && budget > 0; i++) {
    if (text[i] !== '{') continue;
    let depth = 0, inStr = false, esc = false;
    for (let j = i; j < n && budget > 0; j++, budget--) {
      const c = text[j];
      if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
      if (c === '"') inStr = true;
      else if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) { spans++; yield text.slice(i, j + 1); i = j; break; } }
    }
  }
}

// Parse an LLMToolCall[] out of a text-CLI reply. Tolerant of realistic model drift so a valid tool
// intent doesn't silently degrade to a zero-tool abstain: fenced blocks, balanced bare objects, a
// single un-wrapped {name,...}, {tool_calls|actions|calls|tools:[...]} wrappers, and trailing commas.
export function parseTextToolCalls(text: string): LLMToolCall[] | undefined {
  const coerceArgs = (a: unknown): Record<string, unknown> => {
    if (typeof a === 'string') {
      try { const p: unknown = JSON.parse(a); return p && typeof p === 'object' && !Array.isArray(p) ? (p as Record<string, unknown>) : {}; } catch { return {}; }
    }
    return a && typeof a === 'object' && !Array.isArray(a) ? (a as Record<string, unknown>) : {};
  };
  const build = (v: unknown): LLMToolCall[] | undefined => {
    let arr: unknown;
    if (Array.isArray(v)) arr = v;
    else if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      arr = o.tool_calls ?? o.toolCalls ?? o.actions ?? o.calls ?? o.tools;
      if (arr === undefined && typeof o.name === 'string') arr = [o]; // a single un-wrapped call
    }
    if (!Array.isArray(arr) || arr.length === 0) return undefined;
    const calls = arr
      .filter((tc): tc is { name: string } => !!tc && typeof (tc as { name?: unknown }).name === 'string')
      .map((tc, i) => {
        const o = tc as { name: string; arguments?: unknown; args?: unknown; parameters?: unknown; input?: unknown };
        return { id: `lc_${Date.now()}_${i}`, name: o.name, arguments: coerceArgs(o.arguments ?? o.args ?? o.parameters ?? o.input) };
      });
    return calls.length ? calls : undefined;
  };
  const tryParse = (s: string): LLMToolCall[] | undefined => {
    const cleaned = s.trim().replace(/,(\s*[}\]])/g, '$1'); // tolerate trailing commas
    let obj: unknown;
    try { obj = JSON.parse(cleaned); } catch { return undefined; }
    return build(obj);
  };
  // 1) fenced ```json / ```tool blocks (the contracted format)
  for (const m of text.matchAll(/```(?:json|tool)?\s*([\s\S]*?)```/g)) {
    const r = tryParse(m[1]); if (r) return r;
  }
  // 2) each brace-balanced object span (bounded scan — no greedy regex, no ReDoS)
  for (const span of balancedObjectSpans(text)) {
    const r = tryParse(span); if (r) return r;
  }
  // 3) the whole reply (e.g. a top-level array)
  return tryParse(text);
}

// Render one conversation message for a text-CLI prompt. A prior assistant TOOL REQUEST is rendered as
// a compact summary, NOT its raw ```json``` block — re-emitting the block let the CLI's next reply (or a
// final debrief that quotes what it ran) get re-parsed as a fresh live call, defeating termination.
function renderCliMessage(m: LLMMessage): string {
  if (m.role === 'assistant' && m.toolCalls?.length) {
    return `\n### ASSISTANT\n[requested tools: ${m.toolCalls.map((t) => t.name).join(', ')}]`;
  }
  if (m.role === 'tool') {
    return `\n### TOOL RESULT (${m.name || 'tool'})\n${m.content}`;
  }
  return `\n### ${m.role.toUpperCase()}\n${m.content}`;
}

class CodexAdapter implements LLMProviderAdapter {
  name = 'codex';
  private config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = config;
  }

  validateConfig(): { valid: boolean; error?: string } {
    return { valid: true };
  }

  private formatPrompt(messages: LLMMessage[], options?: ChatOptions): string {
    const parts = [
      'You are acting as the Codex-backed planning brain for T3MP3ST, an authorized offensive-security harness.',
      'Do not modify files and do not run active probes yourself.',
    ];
    const contract = renderToolContract(options?.tools);
    if (contract) {
      parts.push('You drive a ReAct loop: REQUEST tools via the contract below — the HARNESS runs them scope-gated and returns results — then reason until the surface is exhausted.');
      parts.push(contract);
    } else {
      parts.push('Operate in planning, critique, and evidence-contract mode only. If tools are available, use read-only inspection only.');
      parts.push('When the caller requests JSON, return only valid JSON or the exact requested fenced JSON block.');
    }
    if (options?.maxTokens) parts.push(`Target max output tokens: ${options.maxTokens}.`);
    for (const message of messages) parts.push(renderCliMessage(message));
    return parts.join('\n');
  }

  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    const workDir = await mkdtemp(join(tmpdir(), 't3mp3st-codex-'));
    const outputPath = join(workDir, 'last-message.txt');
    const prompt = this.formatPrompt(messages, options);
    const command = config.get('codex').command || 'codex';
    const args = [
      '--ask-for-approval',
      'never',
      'exec',
      '-c',
      'model_reasoning_effort="low"',
      '--ephemeral',
      '--skip-git-repo-check',
      '--sandbox',
      'read-only',
      '--color',
      'never',
      '-C',
      process.cwd(),
      '--output-last-message',
      outputPath,
    ];
    if (this.config.model && this.config.model !== 'codex-default') {
      args.push('-m', this.config.model);
    }
    args.push('-');

    try {
      const result = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
        const child = spawn(command, args, {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env, NO_COLOR: '1' },
        });

        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
          child.kill('SIGTERM');
          reject(new Error('Codex CLI timed out while planning'));
        }, this.config.timeout || 240000);

        child.stdout.on('data', chunk => { stdout += chunk.toString(); });
        child.stderr.on('data', chunk => { stderr += chunk.toString(); });
        child.on('error', error => {
          clearTimeout(timer);
          reject(error);
        });
        child.on('close', code => {
          clearTimeout(timer);
          if (code === 0) {
            resolve({ stdout, stderr });
          } else {
            reject(new Error(`Codex CLI exited ${code}: ${(stderr || stdout).trim().slice(0, 4000)}`));
          }
        });
        child.stdin.end(prompt);
      });

      let content = '';
      try {
        content = await readFile(outputPath, 'utf-8');
      } catch {
        content = result.stdout;
      }

      const trimmed = content.trim();
      // Tool-calling over text: parse the agent's tool requests so the ReAct loop EXECUTES them.
      const toolCalls = options?.tools?.length ? parseTextToolCalls(trimmed) : undefined;
      return {
        content: trimmed,
        model: this.config.model || 'codex-default',
        finishReason: toolCalls?.length ? 'tool_calls' : 'stop',
        toolCalls,
      };
    } finally {
      await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

// Generic adapter that drives a CONNECTED local agent CLI (Claude Code / Codex / Hermes) as the LLM
// backend — NO API key needed; each CLI uses its own login. The agent id travels in `config.model`.
class LocalAgentAdapter implements LLMProviderAdapter {
  name = 'local-agent';
  private config: LLMConfig;
  constructor(config: LLMConfig) { this.config = config; }
  validateConfig(): { valid: boolean; error?: string } {
    return this.config.model ? { valid: true } : { valid: false, error: 'local-agent requires the agent id in `model` (codex|claude|hermes)' };
  }
  private formatPrompt(messages: LLMMessage[], options?: ChatOptions): string {
    const parts = [
      'You are the local-agent planning brain for T3MP3ST, an authorized offensive-security harness.',
    ];
    const contract = renderToolContract(options?.tools);
    if (contract) {
      parts.push('You drive a ReAct loop: REQUEST tools, the harness runs them and returns results, you reason until the surface is exhausted.');
      parts.push(contract);
    } else {
      parts.push('Operate in planning, analysis, and evidence-contract mode. When the caller requests JSON, return ONLY valid JSON or the exact requested fenced block — no preamble.');
    }
    if (options?.maxTokens) parts.push(`Target max output tokens: ${options.maxTokens}.`);
    for (const m of messages) parts.push(renderCliMessage(m));
    return parts.join('\n');
  }
  async chat(messages: LLMMessage[], options?: ChatOptions): Promise<LLMResponse> {
    const agentId = this.config.model || 'codex';
    const prompt = this.formatPrompt(messages, options);
    const timeoutMs = typeof this.config.timeout === 'number' && this.config.timeout > 0 ? this.config.timeout : undefined;
    const content = (await localAgentChat(agentId, prompt, { timeoutMs })).trim();
    // Tool-calling over text: if the Arsenal was offered, parse the agent's tool requests so the
    // ReAct loop EXECUTES them instead of treating this planning turn as the (abstaining) final answer.
    const toolCalls = options?.tools?.length ? parseTextToolCalls(content) : undefined;
    return {
      content,
      model: `local-agent:${agentId}`,
      finishReason: toolCalls?.length ? 'tool_calls' : 'stop',
      toolCalls,
    };
  }
}

// =============================================================================
// LLM BACKBONE
// =============================================================================

// =============================================================================
// REFUSAL FALLBACK
// -----------------------------------------------------------------------------
// Models sometimes return a *refusal* — a 200-OK response that declines the task
// rather than an HTTP error — so the retry loop sails right past it and an
// authorized operation silently dead-ends. These helpers detect that case and
// drive an honest provider/model fallback.
//
// Honest by design: on refusal we restate the operation's REAL authorization
// (scope + human-approved gate + responsible disclosure) and try the next model.
// No jailbreak / guardrail-bypass prompts. A refusal that survives honest context
// is respected and returned as-is.
// =============================================================================

/**
 * Does this 200-OK response DECLINE the task (a safety/policy refusal) instead of
 * answering it? Conservative on purpose: fires only on short, decline-leading
 * text or explicit policy language — never on long substantive (exploit) output,
 * and not on technical "I can't find/reach X" progress notes (the decline verb
 * must bind to a help-class object like help/assist/provide/create).
 */
export function isLikelyRefusal(content?: string, finishReason?: string): boolean {
  if (finishReason === 'content_filter') return true;
  const raw = (content || '').trim();
  if (!raw) return false;
  if (raw.length > 1200) return false; // long substantive output is not a refusal
  const t = raw.toLowerCase();
  // A decline verb bound to a help-class object: "I can't help", "I'm sorry, but I
  // cannot assist", "I won't provide", "I must decline to participate". Crucially
  // NOT "I can't find the flag" / "I cannot reach the host" (technical progress).
  const declineToHelp = /\bi\s*(?:'?m|am)?\s*(?:(?:so\s+)?sorry|afraid)?[,.: ]*\s*(?:but\s+)?(?:i\s+)?(?:can'?t|cannot|can\s?not|could\s?not|won'?t|will\s+not|am\s+not\s+able\s+to|'?m\s+not\s+able\s+to|am\s+unable\s+to|unable\s+to|not\s+able\s+to|not\s+going\s+to|must\s+decline|have\s+to\s+decline|refuse\s+to|do\s+not\s+feel\s+comfortable|don'?t\s+feel\s+comfortable)\s+(?:to\s+)?(?:further\s+)?(?:you\s+)?(?:with\s+|in\s+)?(?:help|assist|compl|provid|creat|generat|engag|participat|writ|aid|enabl|fulfil|do\s+that|do\s+this)\w*/;
  // Explicit policy / values language.
  const policyLang = /(?:against\s+(?:my|our|the)\s+(?:guidelines|policy|policies|programming|principles|values)|violat\w*[^.]{0,25}(?:polic\w*|guideline)|i'?m\s+not\s+going\s+to\s+(?:help|assist|provide)|not\s+something\s+i\s+(?:can|will)\s+(?:help|assist|do))/;
  return declineToHelp.test(t) || policyLang.test(t);
}

/**
 * Prepend a TRUTHFUL restatement of the authorization already governing the op.
 * This is NOT a jailbreak — it adds honest context (the engagement is in-scope and
 * human-approved, for responsible disclosure) and asks the model to flag any
 * specific genuine concern rather than blanket-refusing an authorized task.
 */
export function reframeWithAuthorizedContext(messages: LLMMessage[]): LLMMessage[] {
  const note: LLMMessage = {
    role: 'system',
    content:
      'AUTHORIZATION CONTEXT (restated): This is an authorized, in-scope security ' +
      'assessment running under an explicit engagement scope and a human-approved ' +
      'authorization gate, for defensive and responsible-disclosure purposes — ' +
      'findings are reported to the asset owner to be fixed. Please proceed with the ' +
      'authorized task. If a SPECIFIC step is genuinely outside acceptable bounds, ' +
      'identify that step precisely rather than declining the overall task.',
  };
  return [note, ...messages];
}

/**
 * Classify a *successful* (200) response that is nonetheless unusable and should
 * trigger a model fallback: a refusal, or an empty/contentless reply (no text and
 * no tool calls). Returns null when the response is good.
 */
export function classifySoftFailure(r: LLMResponse): 'refusal' | 'empty' | null {
  if (isLikelyRefusal(r.content, r.finishReason)) return 'refusal';
  const hasContent = (r.content || '').trim().length > 0;
  const hasToolCalls = (r.toolCalls?.length || 0) > 0;
  if (!hasContent && !hasToolCalls) return 'empty';
  return null;
}

/**
 * Label a thrown LLM error for fallback telemetry / routing. Distinguishes the
 * failure modes a *different model or provider* can route around (auth on a dead
 * key, a model-specific 404, a context-length blowout) from transient ones.
 */
export function classifyErrorKind(error: Error | null): string {
  if (!error) return 'unknown';
  if (error instanceof LLMApiError) {
    if (/context length|maximum context|too many tokens|context_length|reduce the length/i.test(error.message)) return 'context_length';
    if (error.status === 429) return 'rate_limit';
    if (error.status === 401 || error.status === 403) return 'auth';
    if (error.status === 404) return 'model_unavailable';
    if (error.status >= 500) return 'server_error';
    if (error.status === 400) return 'bad_request';
    return `http_${error.status}`;
  }
  const m = error.message || '';
  if (/abort|timed? ?out|timeout/i.test(m)) return 'timeout';
  if (/fetch failed|network|ENOTFOUND|ECONNREFUSED|ECONNRESET|EAI_AGAIN|socket/i.test(m)) return 'network';
  return 'unknown';
}

export class LLMBackbone extends EventEmitter<LLMEvents> {
  private adapter: LLMProviderAdapter;
  private config: LLMConfig;
  private conversationHistory: LLMMessage[] = [];
  private retryAttempts: number = 3;
  private retryDelayMs: number = 1000;

  constructor(config: LLMConfig) {
    super();
    this.config = config;
    this.adapter = this.createAdapter(config);
    if (config.provider === 'codex') {
      this.retryAttempts = 1;
    }
  }

  private createAdapter(config: LLMConfig): LLMProviderAdapter {
    switch (config.provider) {
      case 'openrouter':
        return new OpenRouterAdapter(config);
      case 'venice':
        return new VeniceAdapter(config);
      case 'anthropic':
        return new AnthropicAdapter(config);
      case 'openai':
        return new OpenAIAdapter(config);
      case 'xai':
        return new OpenAIAdapter(config); // xAI (Grok Build / grok-*) is OpenAI-compatible
      case 'gemini':
        return new OpenAIAdapter(config); // Gemini via Google's OpenAI-compatible endpoint (baseUrl ends in /v1beta/openai)
      case 'codex':
        return new CodexAdapter(config);
      case 'mock':
        return new MockAdapter(config);
      case 'local':
        return new LocalAdapter(config);
      case 'local-agent':
        return new LocalAgentAdapter(config);
      default:
        throw new Error(`Unknown LLM provider: ${config.provider}`);
    }
  }

  /**
   * Get the provider name
   */
  getProvider(): LLMProvider {
    return this.config.provider;
  }

  /**
   * Get the model name
   */
  getModel(): string {
    return this.config.model;
  }

  /**
   * Validate the configuration
   */
  validateConfig(): { valid: boolean; error?: string } {
    return this.adapter.validateConfig();
  }

  /**
   * Send a chat message and get a response
   */
  async chat(
    messages: LLMMessage[],
    options?: ChatOptions
  ): Promise<LLMResponse> {
    const startTime = Date.now();
    this.emit('request:start', { messages });

    // The model ladder: primary first, then each configured fallback hop. A hop is
    // tried when the rung above fails for ANY reason that model can't fix itself —
    // hard errors that survive same-model retries (rate-limit, 5xx, timeout, auth,
    // 404, context-length) OR soft failures on a 200 (a refusal, or empty output).
    const ladder: FallbackEntry[] = [
      { provider: this.config.provider, model: this.config.model, apiKey: this.config.apiKey, baseUrl: this.config.baseUrl },
      ...(this.config.fallbackChain || []),
    ];

    let lastError: Error | null = null;
    let reframeNext = false; // honest authz restatement on the hop after a refusal
    const trail: string[] = [];

    for (let rung = 0; rung < ladder.length; rung++) {
      const hop = ladder[rung];
      const onFallback = rung > 0;
      const hasNext = rung < ladder.length - 1;
      const adapter = onFallback ? this.createAdapter({ ...this.config, ...hop }) : this.adapter;
      const msgs = reframeNext ? reframeWithAuthorizedContext(messages) : messages;

      // ── same-model retry loop: only transient hard errors retry in place ──
      let response: LLMResponse | null = null;
      for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
        try {
          response = await adapter.chat(msgs, options);
          break;
        } catch (error) {
          lastError = error as Error;
          // auth / forbidden / missing-model won't fix on retry — bail to next hop
          const permanent = error instanceof LLMApiError &&
            (error.status === 401 || error.status === 403 || error.status === 404);
          if (permanent || attempt >= this.retryAttempts) break;
          let delayMs = this.retryDelayMs * Math.pow(2, attempt - 1);
          if (error instanceof LLMApiError && error.retryAfterMs) {
            // Honor Retry-After but CAP it (2 min) so a hostile/oversized header can't pin the
            // call for a long time; a normal Retry-After (seconds) is honored unchanged.
            delayMs = Math.max(delayMs, Math.min(error.retryAfterMs, 120_000));
          }
          this.emit('request:retry', { attempt, maxAttempts: this.retryAttempts, error: lastError });
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }

      // ── hard failure: this model gave no usable response ──
      if (!response) {
        const reason = classifyErrorKind(lastError);
        trail.push(`${hop.model}:${reason}`);
        reframeNext = false;
        if (hasNext) {
          this.emit('request:fallback', { fromModel: hop.model, toModel: ladder[rung + 1].model, engaged: true, reason });
          continue;
        }
        break; // bottom of the ladder, still failing → throw below
      }

      // ── soft failure on a 200: refusal or empty/contentless ──
      const soft = classifySoftFailure(response);
      if (soft) {
        trail.push(`${hop.model}:${soft}`);
        if (soft === 'refusal') {
          this.emit('request:refusal', { provider: hop.provider, model: hop.model, preview: (response.content || '').slice(0, 160) });
        }
        reframeNext = soft === 'refusal';
        if (hasNext) {
          this.emit('request:fallback', { fromModel: hop.model, toModel: ladder[rung + 1].model, engaged: true, reason: soft });
          continue;
        }
        // bottom of the ladder: surface the best-effort / honest response, don't throw
        this.emit('request:complete', { response, durationMs: Date.now() - startTime });
        return response;
      }

      // ── success ──
      this.emit('request:complete', { response, durationMs: Date.now() - startTime });
      if (onFallback) {
        this.emit('request:fallback', { fromModel: this.config.model, toModel: hop.model, engaged: true, reason: `recovered_after:${trail.join('>')}` });
      }
      return response;
    }

    this.emit('request:error', { error: lastError as Error, messages });
    throw lastError ?? new Error(`All ${ladder.length} model(s) in the fallback ladder failed: ${trail.join(' > ')}`);
  }

  /**
   * Send a simple prompt and get a response
   */
  async prompt(
    userMessage: string,
    systemPrompt?: string,
    options?: ChatOptions
  ): Promise<string> {
    const messages: LLMMessage[] = [];

    if (systemPrompt) {
      messages.push({ role: 'system', content: systemPrompt });
    }
    messages.push({ role: 'user', content: userMessage });

    const response = await this.chat(messages, options);
    return response.content;
  }

  /**
   * Continue a conversation
   */
  async continue(
    userMessage: string,
    options?: ChatOptions
  ): Promise<string> {
    this.conversationHistory.push({ role: 'user', content: userMessage });

    const response = await this.chat(this.conversationHistory, options);

    this.conversationHistory.push({
      role: 'assistant',
      content: response.content,
    });

    return response.content;
  }

  /**
   * Set the system prompt for conversation
   */
  setSystemPrompt(systemPrompt: string): void {
    // Remove existing system prompt if any
    this.conversationHistory = this.conversationHistory.filter(
      m => m.role !== 'system'
    );
    // Add new system prompt at the beginning
    this.conversationHistory.unshift({ role: 'system', content: systemPrompt });
  }

  /**
   * Clear conversation history
   */
  clearHistory(): void {
    this.conversationHistory = [];
  }

  /**
   * Get conversation history
   */
  getHistory(): LLMMessage[] {
    return [...this.conversationHistory];
  }

  /**
   * Send a chat with tool definitions and get back tool calls or text
   */
  async chatWithTools(
    messages: LLMMessage[],
    tools: LLMToolDefinition[],
    options?: Omit<ChatOptions, 'tools'>
  ): Promise<LLMResponse> {
    return this.chat(messages, { ...options, tools });
  }

  /**
   * Stream a response (if supported)
   */
  async *stream(
    messages: LLMMessage[],
    options?: ChatOptions
  ): AsyncGenerator<string, void, unknown> {
    if (this.adapter.stream) {
      for await (const token of this.adapter.stream(messages, options)) {
        this.emit('token:stream', { token });
        yield token;
      }
    } else {
      // Fallback: simulate streaming with the full response
      const response = await this.chat(messages, options);
      yield response.content;
    }
  }

  /**
   * Get the underlying client for advanced usage
   */
  getClient(): LLMProviderAdapter {
    return this.adapter;
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<LLMConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.adapter = this.createAdapter(this.config);
  }

  /**
   * Set retry configuration
   */
  setRetryConfig(attempts: number, delayMs: number): void {
    this.retryAttempts = attempts;
    this.retryDelayMs = delayMs;
  }
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

export function createAnthropicBackbone(apiKey?: string, model?: string): LLMBackbone {
  const llmConfig = config.getLLMConfig('anthropic', model);
  if (apiKey) llmConfig.apiKey = apiKey;
  return new LLMBackbone(llmConfig);
}

export function createOpenRouterBackbone(apiKey?: string, model?: string): LLMBackbone {
  const llmConfig = config.getLLMConfig('openrouter', model);
  if (apiKey) llmConfig.apiKey = apiKey;
  return new LLMBackbone(llmConfig);
}

export function createVeniceBackbone(apiKey?: string, model?: string): LLMBackbone {
  const llmConfig = config.getLLMConfig('venice', model);
  if (apiKey) llmConfig.apiKey = apiKey;
  return new LLMBackbone(llmConfig);
}

export function createOpenAIBackbone(apiKey?: string, model?: string): LLMBackbone {
  const llmConfig = config.getLLMConfig('openai', model);
  if (apiKey) llmConfig.apiKey = apiKey;
  return new LLMBackbone(llmConfig);
}

export function createMockBackbone(): LLMBackbone {
  return new LLMBackbone({
    provider: 'mock',
    model: 'mock-model',
    maxTokens: 4096,
    temperature: 0.7,
  });
}

export function createLocalBackbone(model?: string, baseUrl?: string): LLMBackbone {
  return new LLMBackbone({
    provider: 'local',
    model: model || 'llama3',
    baseUrl: baseUrl || 'http://localhost:11434/api',
    maxTokens: 4096,
    temperature: 0.7,
  });
}

/**
 * Create the best available backbone based on configured API keys
 */
export function createBestAvailableBackbone(): LLMBackbone {
  // Priority: OpenRouter > Venice > Anthropic > OpenAI > Local > Mock
  const providers = config.getConfiguredProviders();

  if (providers.includes('openrouter')) {
    return createOpenRouterBackbone();
  }
  if (providers.includes('venice')) {
    return createVeniceBackbone();
  }
  if (providers.includes('anthropic')) {
    return createAnthropicBackbone();
  }
  if (providers.includes('openai')) {
    return createOpenAIBackbone();
  }

  // Default to mock if no API keys configured
  console.warn('No API keys configured. Using mock provider.');
  return createMockBackbone();
}

// Re-export types for convenience
export type { LLMMessage, LLMResponse, LLMConfig, LLMToolDefinition, LLMToolCall } from '../types/index.js';
