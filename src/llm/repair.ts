/**
 * Toolcall & JSON Repair Middleware
 * Ported & adapted from PentAGI (pkg/templates/prompts/toolcall_fixer.tmpl)
 * 
 * Recovers, sanitizes, and repairs malformed tool calls, unescaped JSON,
 * trailing commas, and mixed free-form responses from smaller/local models.
 */

export interface ParsedToolCall {
  name: string;
  args: Record<string, any>;
  raw?: string;
  error?: string;
}

export class ToolcallRepairer {
  /**
   * Attempts to parse raw tool argument strings, fixing common JSON syntax errors.
   */
  public static repairJSON(input: string): Record<string, any> {
    if (!input || typeof input !== 'string') return {};
    let str = input.trim();

    // 1. Direct parse attempt
    try {
      return JSON.parse(str);
    } catch (_) {}

    // 2. Strip surrounding markdown code blocks (```json ... ``` or ``` ...)
    str = str.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
    try {
      return JSON.parse(str);
    } catch (_) {}

    // 3. Extract outermost curly brace pair
    const firstBrace = str.indexOf('{');
    const lastBrace = str.lastIndexOf('}');
    if (firstBrace >= 0 && lastBrace > firstBrace) {
      str = str.substring(firstBrace, lastBrace + 1);
      try {
        return JSON.parse(str);
      } catch (_) {}
    }

    // 4. Common LLM syntax repairs:
    // - Remove trailing commas before } or ]
    let repaired = str.replace(/,\s*([\}\]])/g, '$1');
    // - Convert single-quoted keys and values to double quotes
    repaired = repaired.replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, '"$1"');
    // - Fix unquoted object keys: { key: "value" } -> { "key": "value" }
    repaired = repaired.replace(/([{\s,])([a-zA-Z0-9_-]+)\s*:/g, '$1"$2":');

    try {
      return JSON.parse(repaired);
    } catch (_) {}

    // 5. If JSON parsing still fails, attempt key-value regex extraction
    const fallbackObj: Record<string, any> = {};
    const kvRegex = /["']?([a-zA-Z0-9_-]+)["']?\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|(\d+(?:\.\d+)?)|(true|false|null))/g;
    let match;
    while ((match = kvRegex.exec(str)) !== null) {
      const key = match[1];
      const val = match[2] !== undefined ? match[2] : (
        match[3] !== undefined ? match[3] : (
          match[4] !== undefined ? Number(match[4]) : (
            match[5] === 'true' ? true : (match[5] === 'false' ? false : null)
          )
        )
      );
      fallbackObj[key] = val;
    }

    if (Object.keys(fallbackObj).length > 0) {
      return fallbackObj;
    }

    return { raw: input };
  }

  /**
   * Parses and repairs tool invocations from an LLM response string.
   */
  public static extractToolCalls(response: string): ParsedToolCall[] {
    const calls: ParsedToolCall[] = [];
    if (!response || typeof response !== 'string') return calls;

    // Pattern A: ```json { "tool": "name", "args": { ... } } ```
    const codeBlockRegex = /```(?:json)?\s*(\{[\s\S]*?\})\s*```/gi;
    let blockMatch;
    while ((blockMatch = codeBlockRegex.exec(response)) !== null) {
      const parsed = ToolcallRepairer.repairJSON(blockMatch[1]);
      if (parsed.tool || parsed.name || parsed.action) {
        calls.push({
          name: parsed.tool || parsed.name || parsed.action,
          args: parsed.args || parsed.params || parsed.parameters || parsed,
          raw: blockMatch[0]
        });
      }
    }

    if (calls.length > 0) return calls;

    // Pattern B: Bare JSON object with tool/action key
    if (response.trim().startsWith('{') && response.trim().endsWith('}')) {
      const parsed = ToolcallRepairer.repairJSON(response);
      if (parsed.tool || parsed.name || parsed.action) {
        calls.push({
          name: parsed.tool || parsed.name || parsed.action,
          args: parsed.args || parsed.params || parsed.parameters || parsed,
          raw: response
        });
      }
    }

    return calls;
  }
}
