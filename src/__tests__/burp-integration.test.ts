import { describe, it, expect } from 'vitest';
import { burpManager } from '../tools/burp.js';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';

describe('Burp Suite Integration', () => {
  it('registers burpsuite in TOOL_ADAPTERS catalog', () => {
    const burp = TOOL_ADAPTERS.find(t => t.id === 'burpsuite');
    expect(burp).toBeDefined();
    expect(burp?.binary).toBe('burpsuite');
    expect(burp?.category).toBe('web');
    expect(burp?.networked).toBe(true);
  });

  it('retrieves Burp Suite status via burpManager', async () => {
    const status = await burpManager.getStatus();
    expect(status).toHaveProperty('installed');
    expect(status).toHaveProperty('listening');
    expect(status).toHaveProperty('proxyHost');
    expect(status).toHaveProperty('proxyPort');
    expect(status).toHaveProperty('proxyActive');
    expect(status).toHaveProperty('summary');
  });

  it('handles proxy enable and disable cleanly', async () => {
    const enableRes = await burpManager.enableInterception('127.0.0.1', 8080);
    expect(enableRes.ok).toBe(true);
    expect(enableRes.proxyUrl).toBe('http://127.0.0.1:8080');

    const disableRes = burpManager.disableInterception();
    expect(disableRes.ok).toBe(true);
  });
});

