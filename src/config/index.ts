/**
 * T3MP3ST Configuration Management
 *
 * Handles API keys, settings, and persistent configuration.
 * Supports multiple LLM providers with easy key management.
 */

import Conf from 'conf';
import { homedir } from 'os';
import { join } from 'path';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import type { LLMProvider, LLMConfig, FallbackEntry, OpsecLevel } from '../types/index.js';

// =============================================================================
// CONFIGURATION SCHEMA
// =============================================================================

export interface TempestSettings {
  // API Keys
  apiKeys: {
    openrouter?: string;
    venice?: string;
    anthropic?: string;
    openai?: string;
  };

  // Default LLM settings
  defaultProvider: LLMProvider;
  defaultModel: string;

  // OpenRouter specific
  openrouter: {
    baseUrl: string;
    defaultModel: string;
    siteUrl?: string;
    siteName?: string;
  };

  // Venice AI — OpenAI-compatible, privacy-focused (same wire shape as OpenRouter)
  venice: {
    baseUrl: string;
    defaultModel: string;
  };

  // Anthropic specific
  anthropic: {
    baseUrl: string;
    defaultModel: string;
  };

  // OpenAI specific
  openai: {
    baseUrl: string;
    defaultModel: string;
  };

  // Codex CLI/account subscription backend
  codex: {
    command: string;
    defaultModel: string;
  };

  // General settings
  maxTokens: number;
  temperature: number;
  timeout: number;

  // OPSEC defaults
  opsec: {
    level: OpsecLevel;
    maxDetectionEvents: number;
    cleanupOnComplete: boolean;
  };

  // UI preferences
  ui: {
    showBanner: boolean;
    colorOutput: boolean;
    verboseLogging: boolean;
  };
}

// =============================================================================
// DEFAULT CONFIGURATION
// =============================================================================

const DEFAULT_SETTINGS: TempestSettings = {
  apiKeys: {},

  defaultProvider: 'openrouter',
  defaultModel: 'anthropic/claude-opus-4.6',

  openrouter: {
    baseUrl: 'https://openrouter.ai/api/v1',
    defaultModel: 'anthropic/claude-opus-4.6',
    siteUrl: 'https://github.com/tempest',
    siteName: 'T3MP3ST',
  },

  venice: {
    baseUrl: 'https://api.venice.ai/api/v1',
    defaultModel: 'llama-3.3-70b',
  },

  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    defaultModel: 'claude-opus-4-6',
  },

  openai: {
    baseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4-turbo-preview',
  },

  codex: {
    command: 'codex',
    defaultModel: 'codex-default',
  },

  maxTokens: 4096,
  temperature: 0.7,
  timeout: 60000,

  opsec: {
    level: 'covert',
    maxDetectionEvents: 3,
    cleanupOnComplete: true,
  },

  ui: {
    showBanner: true,
    colorOutput: true,
    verboseLogging: false,
  },
};

// =============================================================================
// MODEL REGISTRY
// =============================================================================

export interface ModelInfo {
  id: string;
  name: string;
  provider: string;
  contextWindow: number;
  maxOutput: number;
  pricing?: {
    prompt: number;
    completion: number;
  };
  capabilities: string[];
}

export const AVAILABLE_MODELS: Record<LLMProvider, ModelInfo[]> = {
  venice: [
    {
      id: 'llama-3.3-70b',
      name: 'Llama 3.3 70B (Venice)',
      provider: 'Venice',
      contextWindow: 65536,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'uncensored', 'tools'],
    },
    {
      id: 'venice-uncensored',
      name: 'Venice Uncensored',
      provider: 'Venice',
      contextWindow: 32768,
      maxOutput: 8192,
      capabilities: ['reasoning', 'uncensored'],
    },
  ],

  openrouter: [
    // Anthropic (Feb 2026)
    {
      id: 'anthropic/claude-opus-4.6',
      name: 'Claude Opus 4.6',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 32000,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'complex-tasks', 'agents', 'tools'],
    },
    {
      id: 'anthropic/claude-sonnet-4.5',
      name: 'Claude Sonnet 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 16384,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'agents', 'tools'],
    },
    {
      id: 'anthropic/claude-haiku-4.5',
      name: 'Claude Haiku 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'fast', 'tools'],
    },
    {
      id: 'anthropic/claude-sonnet-4',
      name: 'Claude Sonnet 4',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    // OpenAI
    {
      id: 'openai/gpt-4o',
      name: 'GPT-4o',
      provider: 'OpenAI',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast'],
    },
    {
      id: 'openai/o1',
      name: 'o1',
      provider: 'OpenAI',
      contextWindow: 200000,
      maxOutput: 100000,
      capabilities: ['reasoning', 'code', 'analysis', 'complex-tasks'],
    },
    // Google (Dec 2025)
    {
      id: 'google/gemini-3-pro-preview',
      name: 'Gemini 3 Pro',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'multimodal'],
    },
    {
      id: 'google/gemini-3-flash-preview',
      name: 'Gemini 3 Flash',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast'],
    },
    {
      id: 'google/gemini-2.5-flash',
      name: 'Gemini 2.5 Flash',
      provider: 'Google',
      contextWindow: 1000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    // xAI (Dec 2025)
    {
      id: 'x-ai/grok-4',
      name: 'Grok 4',
      provider: 'xAI',
      contextWindow: 256000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    {
      id: 'x-ai/grok-4-fast',
      name: 'Grok 4 Fast',
      provider: 'xAI',
      contextWindow: 2000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'fast'],
    },
    {
      id: 'x-ai/grok-4.1-fast',
      name: 'Grok 4.1 Fast',
      provider: 'xAI',
      contextWindow: 2000000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'tools'],
    },
    // Z.AI (Dec 2025)
    {
      id: 'z-ai/glm-4.7',
      name: 'GLM 4.7',
      provider: 'Z.AI',
      contextWindow: 203000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents'],
    },
    // Meta
    {
      id: 'meta-llama/llama-3.3-70b',
      name: 'Llama 3.3 70B',
      provider: 'Meta',
      contextWindow: 131072,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis'],
    },
    // DeepSeek (Dec 2025)
    {
      id: 'deepseek/deepseek-r1',
      name: 'DeepSeek R1',
      provider: 'DeepSeek',
      contextWindow: 64000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'complex-tasks'],
    },
    {
      id: 'deepseek/deepseek-chat',
      name: 'DeepSeek V3',
      provider: 'DeepSeek',
      contextWindow: 64000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis'],
    },
    // Mistral
    {
      id: 'mistralai/mistral-large',
      name: 'Mistral Large',
      provider: 'Mistral',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis'],
    },
  ],
  anthropic: [
    {
      id: 'claude-opus-4-6',
      name: 'Claude Opus 4.6',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 32000,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'complex-tasks', 'agents', 'tools'],
    },
    {
      id: 'claude-sonnet-4-5-20250929',
      name: 'Claude Sonnet 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 16384,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'agents', 'tools'],
    },
    {
      id: 'claude-haiku-4-5-20251001',
      name: 'Claude Haiku 4.5',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'fast', 'tools'],
    },
    {
      id: 'claude-sonnet-4-20250514',
      name: 'Claude Sonnet 4',
      provider: 'Anthropic',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
  ],
  openai: [
    {
      id: 'gpt-4-turbo-preview',
      name: 'GPT-4 Turbo',
      provider: 'OpenAI',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision'],
    },
    {
      id: 'gpt-4o',
      name: 'GPT-4o',
      provider: 'OpenAI',
      contextWindow: 128000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code', 'analysis', 'vision', 'fast'],
    },
  ],
  codex: [
    {
      id: 'codex-default',
      name: 'Codex Account Default',
      provider: 'Codex',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'local-cli'],
    },
  ],
  mock: [
    {
      id: 'mock-model',
      name: 'Mock Model',
      provider: 'Mock',
      contextWindow: 100000,
      maxOutput: 4096,
      capabilities: ['testing'],
    },
  ],
  local: [
    {
      id: 'local-model',
      name: 'Local Model',
      provider: 'Local',
      contextWindow: 32000,
      maxOutput: 4096,
      capabilities: ['reasoning', 'code'],
    },
  ],
  'local-agent': [
    // Connected local agent CLIs used AS the LLM backend — no API key (each uses its own login).
    // The chosen agent id (codex|claude|hermes) travels in the `model` field.
    {
      id: 'codex',
      name: 'Codex (local CLI)',
      provider: 'LocalAgent',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'local-cli'],
    },
    {
      id: 'claude',
      name: 'Claude Code (local CLI)',
      provider: 'LocalAgent',
      contextWindow: 200000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'analysis', 'agents', 'local-cli'],
    },
    {
      id: 'hermes',
      name: 'Hermes (local CLI)',
      provider: 'LocalAgent',
      contextWindow: 32000,
      maxOutput: 8192,
      capabilities: ['reasoning', 'code', 'agents', 'local-cli'],
    },
  ],
};

// =============================================================================
// CONFIGURATION MANAGER
// =============================================================================

class ConfigManager {
  private config: Conf<TempestSettings>;
  private envLoaded: boolean = false;

  constructor() {
    this.config = new Conf<TempestSettings>({
      projectName: 't3mp3st',
      defaults: DEFAULT_SETTINGS,
    });

    this.loadEnvVariables();
  }

  /**
   * Load API keys from environment variables
   */
  private loadEnvVariables(): void {
    if (this.envLoaded) return;

    // Try to load from .env file in current directory or home
    const envPaths = [
      join(process.cwd(), '.env'),
      join(homedir(), '.t3mp3st', '.env'),
      join(homedir(), '.env'),
    ];

    for (const envPath of envPaths) {
      if (existsSync(envPath)) {
        const envContent = readFileSync(envPath, 'utf-8');
        const lines = envContent.split('\n');

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            const [key, ...valueParts] = trimmed.split('=');
            const value = valueParts.join('=').replace(/^["']|["']$/g, '');
            // Real env vars take precedence over the .env file (standard dotenv
            // semantics): only fill a key that is not already set. This also lets a
            // caller force an UNCONFIGURED server (e.g. arsenal:smoke) by exporting an
            // empty OPENROUTER_API_KEY= — the .env file no longer clobbers it.
            if (key && value && process.env[key] === undefined) {
              process.env[key] = value;
            }
          }
        }
        break;
      }
    }

    // Check environment variables for API keys
    const envKeys = {
      openrouter: process.env.OPENROUTER_API_KEY,
      venice: process.env.VENICE_API_KEY,
      anthropic: process.env.ANTHROPIC_API_KEY,
      openai: process.env.OPENAI_API_KEY,
    };

    // Only set from env if not already set in config
    const currentKeys = this.config.get('apiKeys');

    for (const [provider, envKey] of Object.entries(envKeys)) {
      if (envKey && !currentKeys[provider as keyof typeof currentKeys]) {
        this.setApiKey(provider as 'openrouter' | 'venice' | 'anthropic' | 'openai', envKey);
      }
    }

    this.envLoaded = true;
  }

  /**
   * Get all settings
   */
  getAll(): TempestSettings {
    return this.config.store;
  }

  /**
   * Get a specific setting
   */
  get<K extends keyof TempestSettings>(key: K): TempestSettings[K] {
    return this.config.get(key);
  }

  /**
   * Set a specific setting
   */
  set<K extends keyof TempestSettings>(key: K, value: TempestSettings[K]): void {
    this.config.set(key, value);
  }

  /**
   * Set an API key for a provider
   */
  setApiKey(provider: 'openrouter' | 'venice' | 'anthropic' | 'openai', key: string): void {
    const apiKeys = this.config.get('apiKeys');
    apiKeys[provider] = key;
    this.config.set('apiKeys', apiKeys);
  }

  /**
   * Get an API key for a provider
   */
  getApiKey(provider: 'openrouter' | 'venice' | 'anthropic' | 'openai'): string | undefined {
    // First check environment variables (highest priority)
    const envVarMap = {
      openrouter: 'OPENROUTER_API_KEY',
      venice: 'VENICE_API_KEY',
      anthropic: 'ANTHROPIC_API_KEY',
      openai: 'OPENAI_API_KEY',
    };

    // Force a fully UNCONFIGURED server (no key from env OR the saved store) — used by
    // arsenal:smoke so the key-required / fail-closed paths are exercisable. Gated behind
    // an explicit flag so a normal operator's STORED key is NEVER silently disabled by an
    // empty exported env var (round-2 code-sweep regression fix).
    if (/^(1|true|yes|on)$/i.test((process.env.T3MP3ST_FORCE_UNCONFIGURED || '').trim())) return undefined;

    const envKey = process.env[envVarMap[provider]];
    if (envKey) return envKey;   // a non-empty env var wins; empty/unset falls through

    // Otherwise fall back to the stored config
    return this.config.get('apiKeys')[provider];
  }

  /**
   * Check if a provider has a valid API key configured
   */
  hasApiKey(provider: 'openrouter' | 'venice' | 'anthropic' | 'openai'): boolean {
    const key = this.getApiKey(provider);
    return !!key && key.length > 10;
  }

  /**
   * Remove an API key
   */
  removeApiKey(provider: 'openrouter' | 'venice' | 'anthropic' | 'openai'): void {
    const apiKeys = this.config.get('apiKeys');
    delete apiKeys[provider];
    this.config.set('apiKeys', apiKeys);
  }

  /**
   * Get configured providers (those with API keys)
   */
  getConfiguredProviders(): LLMProvider[] {
    const providers: LLMProvider[] = [];

    if (this.hasApiKey('openrouter')) providers.push('openrouter');
    if (this.hasApiKey('venice')) providers.push('venice');
    if (this.hasApiKey('anthropic')) providers.push('anthropic');
    if (this.hasApiKey('openai')) providers.push('openai');

    // Codex uses the local Codex CLI/account auth instead of API-key storage.
    providers.push('codex');

    // Mock and local are always available
    providers.push('mock', 'local');

    return providers;
  }

  /**
   * Get the LLM configuration for the default or specified provider
   */
  getLLMConfig(provider?: LLMProvider, model?: string): LLMConfig {
    const actualProvider = provider || this.config.get('defaultProvider');

    let apiKey: string | undefined;
    let baseUrl: string | undefined;
    let actualModel: string;

    switch (actualProvider) {
      case 'openrouter':
        apiKey = this.getApiKey('openrouter');
        baseUrl = this.config.get('openrouter').baseUrl;
        actualModel = model || this.config.get('openrouter').defaultModel;
        break;
      case 'venice':
        apiKey = this.getApiKey('venice');
        baseUrl = this.config.get('venice').baseUrl;
        actualModel = model || this.config.get('venice').defaultModel;
        break;
      case 'anthropic':
        apiKey = this.getApiKey('anthropic');
        baseUrl = this.config.get('anthropic').baseUrl;
        actualModel = model || this.config.get('anthropic').defaultModel;
        break;
      case 'openai':
        apiKey = this.getApiKey('openai');
        baseUrl = this.config.get('openai').baseUrl;
        actualModel = model || this.config.get('openai').defaultModel;
        break;
      case 'codex':
        actualModel = model || this.config.get('codex').defaultModel;
        break;
      case 'mock':
        actualModel = 'mock-model';
        break;
      case 'local':
        baseUrl = 'http://localhost:11434/api';
        actualModel = model || 'llama3';
        break;
      default:
        throw new Error(`Unknown provider: ${actualProvider}`);
    }

    return {
      provider: actualProvider,
      model: actualModel,
      apiKey,
      baseUrl,
      maxTokens: this.config.get('maxTokens'),
      temperature: this.config.get('temperature'),
      timeout: this.config.get('timeout'),
      fallbackChain: this.buildFallbackChain(actualProvider),
    };
  }

  /**
   * Opt-in model fallback ladder. When TEMPEST_MODEL_FALLBACK is set, any primary-
   * model failure that the model can't self-recover from — a refusal, an empty 200,
   * or a hard error that survives same-model retries (rate-limit, 5xx, timeout, dead
   * key, missing model, context blowout) — escalates across the OTHER configured
   * providers in priority order (openrouter → venice → anthropic → openai), each with its own
   * key/model. OFF by default (no surprise model-switching). On a refusal the real
   * authorization context is restated — honest escalation, no jailbreak prompts
   * (see LLMBackbone.chat).
   */
  private buildFallbackChain(primary: LLMProvider): FallbackEntry[] {
    const flag = (process.env.TEMPEST_MODEL_FALLBACK || '').trim().toLowerCase();
    if (!flag || ['0', 'false', 'off', 'no'].includes(flag)) return [];
    const chain: FallbackEntry[] = [];
    const add = (p: 'openrouter' | 'venice' | 'anthropic' | 'openai') => {
      if (p === primary || !this.hasApiKey(p)) return;
      chain.push({
        provider: p,
        model: this.config.get(p).defaultModel,
        apiKey: this.getApiKey(p),
        baseUrl: this.config.get(p).baseUrl,
      });
    };
    add('openrouter');
    add('venice');
    add('anthropic');
    add('openai');
    return chain;
  }

  /**
   * Set the default provider
   */
  setDefaultProvider(provider: LLMProvider): void {
    this.config.set('defaultProvider', provider);

    // Also set the appropriate default model
    switch (provider) {
      case 'openrouter':
        this.config.set('defaultModel', this.config.get('openrouter').defaultModel);
        break;
      case 'venice':
        this.config.set('defaultModel', this.config.get('venice').defaultModel);
        break;
      case 'anthropic':
        this.config.set('defaultModel', this.config.get('anthropic').defaultModel);
        break;
      case 'openai':
        this.config.set('defaultModel', this.config.get('openai').defaultModel);
        break;
      case 'codex':
        this.config.set('defaultModel', this.config.get('codex').defaultModel);
        break;
    }
  }

  /**
   * Set the default model for a provider
   */
  setDefaultModel(provider: LLMProvider, model: string): void {
    switch (provider) {
      case 'openrouter':
        this.config.set('openrouter', { ...this.config.get('openrouter'), defaultModel: model });
        break;
      case 'venice':
        this.config.set('venice', { ...this.config.get('venice'), defaultModel: model });
        break;
      case 'anthropic':
        this.config.set('anthropic', { ...this.config.get('anthropic'), defaultModel: model });
        break;
      case 'openai':
        this.config.set('openai', { ...this.config.get('openai'), defaultModel: model });
        break;
      case 'codex':
        this.config.set('codex', { ...this.config.get('codex'), defaultModel: model });
        break;
    }

    if (this.config.get('defaultProvider') === provider) {
      this.config.set('defaultModel', model);
    }
  }

  /**
   * Reset to default settings
   */
  reset(): void {
    this.config.clear();
  }

  /**
   * Get the config file path
   */
  getConfigPath(): string {
    return this.config.path;
  }

  /**
   * Export configuration to a file
   */
  exportConfig(filePath: string): void {
    const settings = this.getAll();
    // Remove sensitive data
    const safeSettings = {
      ...settings,
      apiKeys: {
        openrouter: settings.apiKeys.openrouter ? '***REDACTED***' : undefined,
        anthropic: settings.apiKeys.anthropic ? '***REDACTED***' : undefined,
        openai: settings.apiKeys.openai ? '***REDACTED***' : undefined,
      },
    };
    writeFileSync(filePath, JSON.stringify(safeSettings, null, 2));
  }

  /**
   * Create a .env template file
   */
  createEnvTemplate(filePath: string = join(process.cwd(), '.env.template')): void {
    const template = `# T3MP3ST Environment Configuration
# Copy this file to .env and fill in your API keys

# OpenRouter API Key (recommended - access to multiple models)
# Get your key at: https://openrouter.ai/keys
OPENROUTER_API_KEY=

# Anthropic API Key (direct Claude access)
# Get your key at: https://console.anthropic.com/
ANTHROPIC_API_KEY=

# OpenAI API Key
# Get your key at: https://platform.openai.com/api-keys
OPENAI_API_KEY=
`;
    writeFileSync(filePath, template);
  }
}

// =============================================================================
// SINGLETON EXPORT
// =============================================================================

export const config = new ConfigManager();

// Helper functions for quick access
export const getApiKey = (provider: 'openrouter' | 'venice' | 'anthropic' | 'openai') => config.getApiKey(provider);
export const setApiKey = (provider: 'openrouter' | 'venice' | 'anthropic' | 'openai', key: string) => config.setApiKey(provider, key);
export const hasApiKey = (provider: 'openrouter' | 'venice' | 'anthropic' | 'openai') => config.hasApiKey(provider);
export const getLLMConfig = (provider?: LLMProvider, model?: string) => config.getLLMConfig(provider, model);
export const getConfiguredProviders = () => config.getConfiguredProviders();
