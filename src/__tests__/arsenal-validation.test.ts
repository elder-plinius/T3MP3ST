/**
 * Arsenal Validation Gate Tests
 *
 * Tests for the validation gate in Arsenal.execute() — validates tool args
 * against parameter schema before handler execution, and categorizes errors
 * using ToolError with proper ToolErrorCategory.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Arsenal, createToolContext } from '../arsenal/index.js';
import { ToolError, ToolErrorCategory } from '../types/index.js';
import type { CustomTool, ToolParameter } from '../types/index.js';

// ─── Helper: create a minimal tool with a schema ──────────────────────────────

function makeTool(
  name: string,
  params: ToolParameter[],
  handler?: (ctx: any) => Promise<any>,
): CustomTool {
  return {
    name,
    description: `Test tool: ${name}`,
    category: 'test',
    parameters: params,
    handler: handler || (async (ctx) => ({
      success: true,
      output: `Executed ${name} with ${JSON.stringify(ctx.parameters)}`,
    })),
  };
}

// ─── Shared schemas ───────────────────────────────────────────────────────────

const echoSchema: ToolParameter[] = [
  { name: 'message', type: 'string', description: 'Message to echo', required: true },
  { name: 'count', type: 'number', description: 'Repeat count', required: false, default: 1 },
];

const enumSchema: ToolParameter[] = [
  {
    name: 'method',
    type: 'string',
    description: 'HTTP method',
    required: true,
    enum: ['GET', 'POST', 'PUT'],
  },
];

const nestedSchema: ToolParameter[] = [
  {
    name: 'config',
    type: 'object',
    description: 'Config object',
    required: true,
    properties: {
      host: { name: 'host', type: 'string', description: 'Host', required: true },
      port: { name: 'port', type: 'number', description: 'Port', required: false },
    },
  },
];

// =============================================================================
// Tests
// =============================================================================

describe('Arsenal Validation Gate', () => {
  let arsenal: Arsenal;

  beforeEach(() => {
    arsenal = new Arsenal();
  });

  // ── 1. Valid args pass validation gate ────────────────────────────────────────

  describe('valid args pass validation', () => {
    it('should execute tool when all required fields are present', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      const result = await arsenal.execute('echo', createToolContext(undefined, { message: 'hello' }));
      expect(result.success).toBe(true);
      expect(result.output).toContain('echo');
    });

    it('should execute tool with only optional fields omitted', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      const result = await arsenal.execute('echo', createToolContext(undefined, { message: 'test', count: 3 }));
      expect(result.success).toBe(true);
    });

    it('should execute tool with no parameters defined (empty schema)', async () => {
      arsenal.register(makeTool('noop', []));
      const result = await arsenal.execute('noop', createToolContext(undefined, { anything: 'goes' }));
      expect(result.success).toBe(true);
    });

    it('should pass validation for valid enum value', async () => {
      arsenal.register(makeTool('http', enumSchema));
      const result = await arsenal.execute('http', createToolContext(undefined, { method: 'GET' }));
      expect(result.success).toBe(true);
    });
  });

  // ── 2. Missing required field → ToolError(ValidationError) ────────────────────

  describe('missing required field', () => {
    it('should throw ToolError with ValidationError when required field is missing', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      await expect(
        arsenal.execute('echo', createToolContext(undefined, {}))
      ).rejects.toThrow(ToolError);

      try {
        await arsenal.execute('echo', createToolContext(undefined, {}));
      } catch (e) {
        expect(e).toBeInstanceOf(ToolError);
        expect((e as ToolError).category).toBe(ToolErrorCategory.ValidationError);
        expect((e as ToolError).toolName).toBe('echo');
      }
    });

    it('should include field name in error message', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      try {
        await arsenal.execute('echo', createToolContext(undefined, {}));
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ToolError);
        expect((e as ToolError).message).toContain('message');
      }
    });
  });

  // ── 3. Wrong type → ToolError(ValidationError) ────────────────────────────────

  describe('wrong type', () => {
    it('should throw ToolError with ValidationError for wrong type', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      await expect(
        arsenal.execute('echo', createToolContext(undefined, { message: 123 }))
      ).rejects.toThrow(ToolError);

      try {
        await arsenal.execute('echo', createToolContext(undefined, { message: 123 }));
      } catch (e) {
        expect(e).toBeInstanceOf(ToolError);
        expect((e as ToolError).category).toBe(ToolErrorCategory.ValidationError);
      }
    });

    it('should throw ToolError for invalid enum value', async () => {
      arsenal.register(makeTool('http', enumSchema));
      try {
        await arsenal.execute('http', createToolContext(undefined, { method: 'PATCH' }));
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ToolError);
        expect((e as ToolError).category).toBe(ToolErrorCategory.ValidationError);
      }
    });
  });

  // ── 4. Unknown tool → ToolError(ToolNotFound) ────────────────────────────────

  describe('unknown tool', () => {
    it('should throw ToolError with ToolNotFound for unregistered tool', async () => {
      try {
        await arsenal.execute('nonexistent_tool', createToolContext(undefined, {}));
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ToolError);
        expect((e as ToolError).category).toBe(ToolErrorCategory.ToolNotFound);
        expect((e as ToolError).toolName).toBe('nonexistent_tool');
      }
    });
  });

  // ── 5. Scope denied → ToolError(ScopeDenied) ─────────────────────────────────

  describe('scope denied', () => {
    it('should return ToolResult with scope denial for out-of-scope target', async () => {
      arsenal.register(makeTool('http', [
        { name: 'url', type: 'string', description: 'URL', required: true },
      ]));
      arsenal.setScope({
        allowedHosts: ['example.com'],
        allowLoopback: false,
        allowPrivate: false,
      });

      const result = await arsenal.execute('http', createToolContext(
        undefined,
        { url: 'https://evil.com/attack' }
      ));
      expect(result.success).toBe(false);
      expect(result.error).toContain('SCOPE DENIED');
    });

    it('should allow in-scope targets to pass', async () => {
      arsenal.register(makeTool('http', [
        { name: 'url', type: 'string', description: 'URL', required: true },
      ]));
      arsenal.setScope({
        allowedHosts: ['example.com'],
        allowLoopback: false,
        allowPrivate: false,
      });

      const result = await arsenal.execute('http', createToolContext(
        undefined,
        { url: 'https://example.com/page' }
      ));
      expect(result.success).toBe(true);
    });
  });

  // ── 6. Error category is accessible on ToolError instances ────────────────────

  describe('error category accessibility', () => {
    it('should have category property on ToolError', () => {
      const err = new ToolError(ToolErrorCategory.ValidationError, 'test');
      expect(err.category).toBe(ToolErrorCategory.ValidationError);
    });

    it('should have category property on ToolError for each category', () => {
      const categories = [
        ToolErrorCategory.ScopeDenied,
        ToolErrorCategory.ToolNotFound,
        ToolErrorCategory.Timeout,
        ToolErrorCategory.ExecutionError,
        ToolErrorCategory.ValidationError,
      ];
      for (const cat of categories) {
        const err = new ToolError(cat, `msg for ${cat}`);
        expect(err.category).toBe(cat);
      }
    });

    it('should throw ToolError (catchable as Error) for validation failure', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      try {
        await arsenal.execute('echo', createToolContext(undefined, {}));
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(ToolError);
        const toolErr = e as ToolError;
        expect(toolErr.category).toBeDefined();
        expect(typeof toolErr.category).toBe('string');
      }
    });
  });

  // ── 7. Execution error → ToolError(ExecutionError) ────────────────────────────

  describe('execution error categorization', () => {
    it('should throw ToolError with ExecutionError when handler throws', async () => {
      const failingTool = makeTool('boom', echoSchema, async () => {
        throw new Error('handler crashed');
      });
      arsenal.register(failingTool);

      try {
        await arsenal.execute('boom', createToolContext(undefined, { message: 'hi' }));
        expect.fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ToolError);
        expect((e as ToolError).category).toBe(ToolErrorCategory.ExecutionError);
      }
    });
  });

  // ── 8. Validation error emits tool:error event ────────────────────────────────

  describe('events', () => {
    it('should emit tool:error on validation failure', async () => {
      arsenal.register(makeTool('echo', echoSchema));
      const errors: any[] = [];
      arsenal.on('tool:error', (evt) => errors.push(evt));

      try {
        await arsenal.execute('echo', createToolContext(undefined, {}));
      } catch {
        // expected
      }

      expect(errors).toHaveLength(1);
      expect(errors[0].tool.name).toBe('echo');
    });

    it('should emit tool:error on tool not found', async () => {
      const errors: any[] = [];
      arsenal.on('tool:error', (evt) => errors.push(evt));

      try {
        await arsenal.execute('nope', createToolContext(undefined, {}));
      } catch {
        // expected
      }

      expect(errors).toHaveLength(1);
      expect(errors[0].error).toBeInstanceOf(ToolError);
    });
  });
});

// =============================================================================
// getToolDefinitions with buildJsonSchema
// =============================================================================

describe('Arsenal.getToolDefinitions with buildJsonSchema', () => {
  let arsenal: Arsenal;

  beforeEach(() => {
    arsenal = new Arsenal();
  });

  it('should include enum in tool definitions', () => {
    arsenal.register(makeTool('http', enumSchema));
    const defs = arsenal.getToolDefinitions();
    expect(defs).toHaveLength(1);
    const methodProp = defs[0].parameters.properties.method;
    expect(methodProp).toBeDefined();
    // The property should have the enum field from buildJsonSchema
    expect((methodProp as any).enum).toEqual(['GET', 'POST', 'PUT']);
  });

  it('should include default values in tool definitions', () => {
    arsenal.register(makeTool('echo', echoSchema));
    const defs = arsenal.getToolDefinitions();
    const countProp = defs[0].parameters.properties.count;
    expect(countProp).toBeDefined();
    expect((countProp as any).default).toBe(1);
  });

  it('should include required fields', () => {
    arsenal.register(makeTool('echo', echoSchema));
    const defs = arsenal.getToolDefinitions();
    expect(defs[0].parameters.required).toEqual(['message']);
  });

  it('should include nested object properties', () => {
    arsenal.register(makeTool('config', nestedSchema));
    const defs = arsenal.getToolDefinitions();
    const configProp = defs[0].parameters.properties.config as any;
    expect(configProp.properties).toBeDefined();
    expect(configProp.properties.host).toEqual({
      type: 'string',
      description: 'Host',
    });
  });
});
