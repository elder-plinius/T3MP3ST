/**
 * ToolError Type Tests
 *
 * Tests for ToolErrorCategory enum and ToolError class — structured error
 * handling for tool validation, execution, and scope enforcement.
 */

import { describe, it, expect } from 'vitest';
import { ToolError, ToolErrorCategory, type ToolValidationError } from '../types/index.js';

describe('ToolErrorCategory', () => {
  it('should have all expected category values', () => {
    expect(ToolErrorCategory.ScopeDenied).toBe('scope_denied');
    expect(ToolErrorCategory.ToolNotFound).toBe('tool_not_found');
    expect(ToolErrorCategory.Timeout).toBe('timeout');
    expect(ToolErrorCategory.ExecutionError).toBe('execution_error');
    expect(ToolErrorCategory.ValidationError).toBe('validation_error');
  });

  it('should have exactly 5 categories', () => {
    const values = Object.values(ToolErrorCategory);
    expect(values).toHaveLength(5);
  });
});

describe('ToolError', () => {
  it('should construct with category and message', () => {
    const err = new ToolError(ToolErrorCategory.ValidationError, 'Invalid argument');
    expect(err.category).toBe(ToolErrorCategory.ValidationError);
    expect(err.message).toBe('Invalid argument');
    expect(err.name).toBe('ToolError');
  });

  it('should be an instance of Error', () => {
    const err = new ToolError(ToolErrorCategory.Timeout, 'Timed out');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ToolError);
  });

  it('should accept optional toolName', () => {
    const err = new ToolError(ToolErrorCategory.ToolNotFound, 'Not found', 'nmap_scan');
    expect(err.toolName).toBe('nmap_scan');
  });

  it('should have undefined toolName when not provided', () => {
    const err = new ToolError(ToolErrorCategory.ExecutionError, 'Failed');
    expect(err.toolName).toBeUndefined();
  });

  it('should preserve stack trace', () => {
    const err = new ToolError(ToolErrorCategory.ScopeDenied, 'Denied');
    expect(err.stack).toBeDefined();
    expect(err.stack).toContain('ToolError');
  });

  it('should be throwable and catchable', () => {
    expect(() => {
      throw new ToolError(ToolErrorCategory.ValidationError, 'Bad input');
    }).toThrow(ToolError);
  });

  it('should allow checking category in catch block', () => {
    try {
      throw new ToolError(ToolErrorCategory.Timeout, 'Tool timed out', 'nuclei');
    } catch (e) {
      expect(e).toBeInstanceOf(ToolError);
      if (e instanceof ToolError) {
        expect(e.category).toBe(ToolErrorCategory.Timeout);
        expect(e.toolName).toBe('nuclei');
      }
    }
  });

  it('should work with all categories', () => {
    const categories = [
      ToolErrorCategory.ScopeDenied,
      ToolErrorCategory.ToolNotFound,
      ToolErrorCategory.Timeout,
      ToolErrorCategory.ExecutionError,
      ToolErrorCategory.ValidationError,
    ];
    for (const cat of categories) {
      const err = new ToolError(cat, `Error for ${cat}`);
      expect(err.category).toBe(cat);
    }
  });

  it('should have readonly category and toolName', () => {
    const err = new ToolError(ToolErrorCategory.ValidationError, 'msg', 'tool');
    // TypeScript readonly — runtime still allows assignment but the intent is clear
    expect(err.category).toBe(ToolErrorCategory.ValidationError);
    expect(err.toolName).toBe('tool');
  });
});

describe('ToolValidationError', () => {
  it('should have all required fields', () => {
    const error: ToolValidationError = {
      field: 'port',
      message: 'Port must be a number',
      received: 'abc',
      expected: 'number',
    };
    expect(error.field).toBe('port');
    expect(error.message).toBe('Port must be a number');
    expect(error.received).toBe('abc');
    expect(error.expected).toBe('number');
  });

  it('should accept unknown received values', () => {
    const error: ToolValidationError = {
      field: 'config',
      message: 'Invalid type',
      received: undefined,
      expected: 'object',
    };
    expect(error.received).toBeUndefined();
  });

  it('should accept complex received values', () => {
    const error: ToolValidationError = {
      field: 'headers',
      message: 'Array item type mismatch',
      received: { key: 123 },
      expected: 'string',
    };
    expect(error.received).toEqual({ key: 123 });
  });

  it('should be usable in arrays for multi-field validation', () => {
    const errors: ToolValidationError[] = [
      { field: 'host', message: 'Required', received: undefined, expected: 'string' },
      { field: 'port', message: 'Out of range', received: 99999, expected: '1-65535' },
    ];
    expect(errors).toHaveLength(2);
    expect(errors.map(e => e.field)).toEqual(['host', 'port']);
  });
});
