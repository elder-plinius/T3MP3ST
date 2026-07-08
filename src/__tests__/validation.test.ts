/**
 * Schema Validation Utility Tests
 *
 * Tests for validateToolArgs() — AJV-based argument validation with
 * schema depth enforcement and lazy loading.
 */

import { describe, it, expect } from 'vitest';
import type { ToolParameter } from '../types/index.js';

// Import will fail until validation/index.ts exists
import { validateToolArgs, assertSchemaDepth, buildJsonSchema } from '../validation/index.js';

describe('validateToolArgs', () => {
  describe('valid args pass validation', () => {
    it('should return empty array for valid string arg', () => {
      const schema: ToolParameter[] = [
        { name: 'target', type: 'string', description: 'Target host', required: true },
      ];
      const errors = validateToolArgs('test_tool', { target: 'example.com' }, schema);
      expect(errors).toEqual([]);
    });

    it('should return empty array for valid number arg', () => {
      const schema: ToolParameter[] = [
        { name: 'port', type: 'number', description: 'Port', required: true },
      ];
      const errors = validateToolArgs('test_tool', { port: 8080 }, schema);
      expect(errors).toEqual([]);
    });

    it('should return empty array for valid boolean arg', () => {
      const schema: ToolParameter[] = [
        { name: 'verbose', type: 'boolean', description: 'Verbose output', required: false },
      ];
      const errors = validateToolArgs('test_tool', { verbose: true }, schema);
      expect(errors).toEqual([]);
    });

    it('should return empty array for valid array arg', () => {
      const schema: ToolParameter[] = [
        {
          name: 'domains',
          type: 'array',
          description: 'Domain list',
          required: true,
          items: { type: 'string' },
        },
      ];
      const errors = validateToolArgs('test_tool', { domains: ['a.com', 'b.com'] }, schema);
      expect(errors).toEqual([]);
    });

    it('should return empty array for valid object arg', () => {
      const schema: ToolParameter[] = [
        {
          name: 'config',
          type: 'object',
          description: 'Config',
          required: false,
          properties: {
            host: { name: 'host', type: 'string', description: 'Host', required: true },
            port: { name: 'port', type: 'number', description: 'Port', required: false },
          },
        },
      ];
      const errors = validateToolArgs('test_tool', { config: { host: 'localhost' } }, schema);
      expect(errors).toEqual([]);
    });
  });

  describe('missing required field', () => {
    it('should return validation error for missing required string', () => {
      const schema: ToolParameter[] = [
        { name: 'target', type: 'string', description: 'Target host', required: true },
      ];
      const errors = validateToolArgs('test_tool', {}, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('target');
      expect(errors[0].expected).toContain('required');
    });

    it('should return multiple errors for multiple missing required fields', () => {
      const schema: ToolParameter[] = [
        { name: 'host', type: 'string', description: 'Host', required: true },
        { name: 'port', type: 'number', description: 'Port', required: true },
      ];
      const errors = validateToolArgs('test_tool', {}, schema);
      expect(errors).toHaveLength(2);
      expect(errors.map(e => e.field)).toEqual(expect.arrayContaining(['host', 'port']));
    });
  });

  describe('wrong type', () => {
    it('should return validation error for string when number expected', () => {
      const schema: ToolParameter[] = [
        { name: 'port', type: 'number', description: 'Port', required: true },
      ];
      const errors = validateToolArgs('test_tool', { port: 'abc' }, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('port');
    });

    it('should return validation error for number when string expected', () => {
      const schema: ToolParameter[] = [
        { name: 'target', type: 'string', description: 'Target', required: true },
      ];
      const errors = validateToolArgs('test_tool', { target: 123 }, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('target');
    });

    it('should return validation error for wrong array item type', () => {
      const schema: ToolParameter[] = [
        {
          name: 'ports',
          type: 'array',
          description: 'Ports',
          required: true,
          items: { type: 'number' },
        },
      ];
      const errors = validateToolArgs('test_tool', { ports: ['a', 'b'] }, schema);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('enum constraint', () => {
    it('should return validation error for value not in enum', () => {
      const schema: ToolParameter[] = [
        {
          name: 'method',
          type: 'string',
          description: 'HTTP method',
          required: true,
          enum: ['GET', 'POST', 'PUT', 'DELETE'],
        },
      ];
      const errors = validateToolArgs('test_tool', { method: 'PATCH' }, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toBe('method');
    });

    it('should return empty array for valid enum value', () => {
      const schema: ToolParameter[] = [
        {
          name: 'method',
          type: 'string',
          description: 'HTTP method',
          required: true,
          enum: ['GET', 'POST', 'PUT', 'DELETE'],
        },
      ];
      const errors = validateToolArgs('test_tool', { method: 'GET' }, schema);
      expect(errors).toEqual([]);
    });
  });

  describe('nested object validation', () => {
    it('should validate depth 1 nested object', () => {
      const schema: ToolParameter[] = [
        {
          name: 'config',
          type: 'object',
          description: 'Config',
          required: true,
          properties: {
            host: { name: 'host', type: 'string', description: 'Host', required: true },
          },
        },
      ];
      const errors = validateToolArgs('test_tool', { config: {} }, schema);
      expect(errors).toHaveLength(1);
      expect(errors[0].field).toContain('config');
    });

    it('should validate depth 2 nested object', () => {
      const schema: ToolParameter[] = [
        {
          name: 'config',
          type: 'object',
          description: 'Config',
          required: true,
          properties: {
            server: {
              name: 'server',
              type: 'object',
              description: 'Server config',
              required: true,
              properties: {
                host: { name: 'host', type: 'string', description: 'Host', required: true },
              },
            },
          },
        },
      ];
      // Missing required 'server' inside config
      const errors = validateToolArgs('test_tool', { config: {} }, schema);
      expect(errors).toHaveLength(1);
      // AJV error path is the parent object path for required properties
      expect(errors[0].field).toBe('config');
      expect(errors[0].expected).toContain('required');
    });

    it('should validate depth 3 nested object', () => {
      const schema: ToolParameter[] = [
        {
          name: 'level1',
          type: 'object',
          description: 'L1',
          required: true,
          properties: {
            level2: {
              name: 'level2',
              type: 'object',
              description: 'L2',
              required: true,
              properties: {
                level3: {
                  name: 'level3',
                  type: 'object',
                  description: 'L3',
                  required: true,
                  properties: {
                    value: { name: 'value', type: 'string', description: 'Value', required: true },
                  },
                },
              },
            },
          },
        },
      ];
      // Missing required 'level3' inside level1.level2
      const errors = validateToolArgs('test_tool', { level1: { level2: {} } }, schema);
      expect(errors).toHaveLength(1);
      // AJV error path is the parent object path
      expect(errors[0].field).toBe('level1.level2');
      expect(errors[0].expected).toContain('required');
    });
  });

  describe('empty schema', () => {
    it('should return no errors for empty schema', () => {
      const errors = validateToolArgs('test_tool', {}, []);
      expect(errors).toEqual([]);
    });

    it('should return no errors when no parameters defined', () => {
      const errors = validateToolArgs('test_tool', { anything: 'goes' }, []);
      expect(errors).toEqual([]);
    });
  });
});

describe('assertSchemaDepth', () => {
  it('should pass for flat parameters (depth 1)', () => {
    const schema: ToolParameter[] = [
      { name: 'target', type: 'string', description: 'Target', required: true },
    ];
    expect(() => assertSchemaDepth(schema)).not.toThrow();
  });

  it('should pass for depth 2 (object with properties)', () => {
    const schema: ToolParameter[] = [
      {
        name: 'config',
        type: 'object',
        description: 'Config',
        required: true,
        properties: {
          host: { name: 'host', type: 'string', description: 'Host', required: true },
        },
      },
    ];
    expect(() => assertSchemaDepth(schema)).not.toThrow();
  });

  it('should pass for depth 3 (object → object → object)', () => {
    const schema: ToolParameter[] = [
      {
        name: 'level1',
        type: 'object',
        description: 'L1',
        required: true,
        properties: {
          level2: {
            name: 'level2',
            type: 'object',
            description: 'L2',
            required: true,
            properties: {
              level3: {
                name: 'level3',
                type: 'object',
                description: 'L3',
                required: true,
                properties: {
                  value: { name: 'value', type: 'string', description: 'Value', required: true },
                },
              },
            },
          },
        },
      },
    ];
    expect(() => assertSchemaDepth(schema)).not.toThrow();
  });

  it('should throw for depth 4 (exceeds max depth)', () => {
    const schema: ToolParameter[] = [
      {
        name: 'level1',
        type: 'object',
        description: 'L1',
        required: true,
        properties: {
          level2: {
            name: 'level2',
            type: 'object',
            description: 'L2',
            required: true,
            properties: {
              level3: {
                name: 'level3',
                type: 'object',
                description: 'L3',
                required: true,
                properties: {
                  level4: {
                    name: 'level4',
                    type: 'object',
                    description: 'L4',
                    required: true,
                    properties: {
                      value: { name: 'value', type: 'string', description: 'Value', required: true },
                    },
                  },
                },
              },
            },
          },
        },
      },
    ];
    expect(() => assertSchemaDepth(schema)).toThrow(/exceeds maximum/);
  });

  it('should throw for depth 4 via array items', () => {
    const schema: ToolParameter[] = [
      {
        name: 'matrix',
        type: 'array',
        description: 'Matrix',
        required: true,
        items: {
          type: 'object',
          properties: {
            row: {
              name: 'row',
              type: 'array',
              description: 'Row',
              required: true,
              items: {
                type: 'object',
                properties: {
                  cell: {
                    name: 'cell',
                    type: 'object',
                    description: 'Cell',
                    required: true,
                    properties: {
                      value: { name: 'value', type: 'string', description: 'Value', required: true },
                    },
                  },
                },
              },
            },
          },
        },
      },
    ];
    expect(() => assertSchemaDepth(schema)).toThrow(/exceeds maximum/);
  });

  it('should accept custom maxDepth', () => {
    const schema: ToolParameter[] = [
      {
        name: 'level1',
        type: 'object',
        description: 'L1',
        required: true,
        properties: {
          level2: {
            name: 'level2',
            type: 'object',
            description: 'L2',
            required: true,
            properties: {
              level3: {
                name: 'level3',
                type: 'object',
                description: 'L3',
                required: true,
                properties: {},
              },
            },
          },
        },
      },
    ];
    // With maxDepth=2, depth 3 should throw
    expect(() => assertSchemaDepth(schema, 2)).toThrow(/exceeds maximum/);
    // With maxDepth=4, depth 3 should pass
    expect(() => assertSchemaDepth(schema, 4)).not.toThrow();
  });
});

describe('buildJsonSchema', () => {
  it('should convert flat parameters to JSON Schema', () => {
    const schema = buildJsonSchema([
      { name: 'target', type: 'string', description: 'Target host', required: true },
      { name: 'port', type: 'number', description: 'Port', required: false, default: 80 },
    ]);
    expect(schema).toEqual({
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target host' },
        port: { type: 'number', description: 'Port', default: 80 },
      },
      required: ['target'],
    });
  });

  it('should convert enum parameters', () => {
    const schema = buildJsonSchema([
      { name: 'method', type: 'string', description: 'HTTP method', required: true, enum: ['GET', 'POST'] },
    ]);
    const props = schema.properties as Record<string, Record<string, unknown>>;
    expect(props.method).toEqual({
      type: 'string',
      description: 'HTTP method',
      enum: ['GET', 'POST'],
    });
  });

  it('should convert array parameters with items', () => {
    const schema = buildJsonSchema([
      {
        name: 'domains',
        type: 'array',
        description: 'Domains',
        required: true,
        items: { type: 'string' },
      },
    ]);
    const props = schema.properties as Record<string, Record<string, unknown>>;
    expect(props.domains).toEqual({
      type: 'array',
      description: 'Domains',
      items: { type: 'string' },
    });
  });

  it('should convert object parameters with nested properties', () => {
    const schema = buildJsonSchema([
      {
        name: 'config',
        type: 'object',
        description: 'Config',
        required: false,
        properties: {
          host: { name: 'host', type: 'string', description: 'Host', required: true },
        },
        additionalProperties: false,
      },
    ]);
    const props = schema.properties as Record<string, Record<string, unknown>>;
    expect(props.config).toEqual({
      type: 'object',
      description: 'Config',
      properties: {
        host: { type: 'string', description: 'Host' },
      },
      required: ['host'],
      additionalProperties: false,
    });
  });
});
