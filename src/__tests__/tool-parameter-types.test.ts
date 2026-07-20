/**
 * ToolParameter Type Tests
 *
 * Tests for the extended ToolParameter type supporting richer JSON Schema:
 * flat primitives, array with items, object with properties, and enum constraints.
 */

import { describe, it, expect } from 'vitest';
import type { ToolParameter } from '../types/index.js';

describe('ToolParameter types', () => {
  describe('flat primitive parameter', () => {
    it('should accept a string parameter with all base fields', () => {
      const param: ToolParameter = {
        name: 'target',
        type: 'string',
        description: 'The target host',
        required: true,
      };
      expect(param.name).toBe('target');
      expect(param.type).toBe('string');
      expect(param.required).toBe(true);
    });

    it('should accept optional default value', () => {
      const param: ToolParameter = {
        name: 'port',
        type: 'number',
        description: 'Port number',
        required: false,
        default: 8080,
      };
      expect(param.default).toBe(8080);
    });
  });

  describe('enum constraint', () => {
    it('should accept string enum values', () => {
      const param: ToolParameter = {
        name: 'method',
        type: 'string',
        description: 'HTTP method',
        required: true,
        enum: ['GET', 'POST', 'PUT', 'DELETE'],
      };
      expect(param.enum).toEqual(['GET', 'POST', 'PUT', 'DELETE']);
    });

    it('should accept numeric enum values', () => {
      const param: ToolParameter = {
        name: 'level',
        type: 'number',
        description: 'Verbosity level',
        required: false,
        enum: [0, 1, 2, 3],
      };
      expect(param.enum).toEqual([0, 1, 2, 3]);
    });
  });

  describe('array parameter with items', () => {
    it('should accept array type with items schema', () => {
      const param: ToolParameter = {
        name: 'domains',
        type: 'array',
        description: 'List of domains to scan',
        required: true,
        items: {
          type: 'string',
          description: 'A domain name',
        },
      };
      expect(param.type).toBe('array');
      expect(param.items?.type).toBe('string');
    });

    it('should accept array of objects via nested properties', () => {
      const param: ToolParameter = {
        name: 'headers',
        type: 'array',
        description: 'HTTP headers',
        required: false,
        items: {
          type: 'object',
          properties: {
            key: {
              name: 'key',
              type: 'string',
              description: 'Header name',
              required: true,
            },
            value: {
              name: 'value',
              type: 'string',
              description: 'Header value',
              required: true,
            },
          },
        },
      };
      expect(param.items?.properties?.key.type).toBe('string');
      expect(param.items?.properties?.value.type).toBe('string');
    });
  });

  describe('object parameter with properties', () => {
    it('should accept object type with nested properties', () => {
      const param: ToolParameter = {
        name: 'config',
        type: 'object',
        description: 'Connection configuration',
        required: false,
        properties: {
          host: {
            name: 'host',
            type: 'string',
            description: 'Target host',
            required: true,
          },
          port: {
            name: 'port',
            type: 'number',
            description: 'Target port',
            required: false,
            default: 443,
          },
        },
        additionalProperties: false,
      };
      expect(param.type).toBe('object');
      expect(param.properties?.host.required).toBe(true);
      expect(param.properties?.port.default).toBe(443);
      expect(param.additionalProperties).toBe(false);
    });

    it('should allow additionalProperties to be true', () => {
      const param: ToolParameter = {
        name: 'metadata',
        type: 'object',
        description: 'Arbitrary metadata',
        required: false,
        additionalProperties: true,
      };
      expect(param.additionalProperties).toBe(true);
    });
  });

  describe('type safety — new fields should not compile without extended type', () => {
    it('enum field is part of ToolParameter shape', () => {
      const param: ToolParameter = { name: 'x', type: 'string', description: '', required: false, enum: ['a'] };
      expect(param.enum).toBeDefined();
      expect(param.enum?.[0]).toBe('a');
    });

    it('items field is part of ToolParameter shape', () => {
      const param: ToolParameter = { name: 'x', type: 'array', description: '', required: false, items: { type: 'string' } };
      expect(param.items).toBeDefined();
      expect(param.items?.type).toBe('string');
    });

    it('properties field is part of ToolParameter shape', () => {
      const param: ToolParameter = { name: 'x', type: 'object', description: '', required: false, properties: {} };
      expect(param.properties).toBeDefined();
    });

    it('additionalProperties field is part of ToolParameter shape', () => {
      const param: ToolParameter = { name: 'x', type: 'object', description: '', required: false, additionalProperties: true };
      expect(param.additionalProperties).toBe(true);
    });
  });

  describe('backward compatibility — base fields still work', () => {
    it('existing string parameter without new fields compiles', () => {
      const param: ToolParameter = {
        name: 'domain',
        type: 'string',
        description: 'Target domain',
        required: true,
      };
      expect(param.enum).toBeUndefined();
      expect(param.items).toBeUndefined();
      expect(param.properties).toBeUndefined();
      expect(param.additionalProperties).toBeUndefined();
    });

    it('existing parameter with default still works', () => {
      const param: ToolParameter = {
        name: 'timeout',
        type: 'number',
        description: 'Timeout in seconds',
        required: false,
        default: 30,
      };
      expect(param.default).toBe(30);
    });
  });

  describe('deeply nested schemas', () => {
    it('should support 3-level nesting via items.properties.items', () => {
      const param: ToolParameter = {
        name: 'matrix',
        type: 'array',
        description: 'A matrix of rows',
        required: true,
        items: {
          type: 'object',
          properties: {
            row: {
              name: 'row',
              type: 'array',
              description: 'A row of values',
              required: true,
              items: {
                type: 'object',
                properties: {
                  value: {
                    name: 'value',
                    type: 'string',
                    description: 'Cell value',
                    required: true,
                  },
                },
              },
            },
          },
        },
      };
      // Level 1: array
      expect(param.type).toBe('array');
      // Level 2: object with row property
      expect(param.items?.properties?.row.type).toBe('array');
      // Level 3: array of objects with value property
      const rowParam = param.items?.properties?.row;
      expect(rowParam?.items?.properties?.value.type).toBe('string');
    });
  });
});
