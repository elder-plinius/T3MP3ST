import { describe, it, expect } from 'vitest';
import {
  planPinKeyevents,
  getLockState,
  probeLockPin,
  MAX_PIN_ATTEMPTS,
  ANDROID_TOOLS,
  ANDROID_UNLOCK_SOURCE,
} from '../tools/android-forensics.js';

// The probe's whole safety story is that it is ONE attempt, gated, and reachable
// only with an explicit authorization acknowledgement. These tests pin all three,
// plus the parser that reads the verdict out of `dumpsys trust`.

describe('lock-state reading (dumpsys trust oracle)', () => {
  it('returns an honest unknown when adb is unavailable or no device is attached', async () => {
    // No device in CI: the contract is an honest `locked: null` + a reason, never
    // a throw and never a fabricated "unlocked".
    const s = await getLockState();
    expect(s.locked).toBeNull();
    expect(s.detail).toBeTruthy();
    expect(typeof s.raw).toBe('string');
  });
});

describe('PIN keycode planning', () => {
  it('maps each digit to its KEYCODE', () => {
    expect(planPinKeyevents('1234').keyevents).toEqual(['KEYCODE_1', 'KEYCODE_2', 'KEYCODE_3', 'KEYCODE_4']);
  });

  it('handles a longer PIN', () => {
    expect(planPinKeyevents('000000').keyevents).toEqual(Array(6).fill('KEYCODE_0'));
  });

  it('rejects anything that is not 4-12 digits', () => {
    for (const bad of ['', '123', 'abcd', '12 34', '12;34', '1234567890123', '*#!@']) {
      expect(planPinKeyevents(bad).error, bad).toBeTruthy();
      expect(planPinKeyevents(bad).keyevents).toEqual([]);
    }
  });
});

describe('probe gating — the safety invariants', () => {
  it('caps a single probe at exactly one attempt', () => {
    expect(MAX_PIN_ATTEMPTS).toBe(1);
  });

  it('refuses without an authorization acknowledgement and sends nothing', async () => {
    const r = await probeLockPin({ pin: '1234', confirmAuthorized: false });
    expect(r.ok).toBe(false);
    expect(r.attempts).toBe(0);
    expect(r.steps).toEqual([]);
    expect(r.error).toMatch(/authorization/i);
  });

  it('refuses a malformed PIN before touching the device', async () => {
    const r = await probeLockPin({ pin: 'nope', confirmAuthorized: true });
    expect(r.ok).toBe(false);
    expect(r.steps).toEqual([]);
    expect(r.attempts).toBe(0);
    expect(r.error).toMatch(/4-12 digits/);
  });

  it('reports the upstream source on every result', async () => {
    const r = await probeLockPin({ pin: '1234', confirmAuthorized: false });
    expect(r.upstream).toBe(ANDROID_UNLOCK_SOURCE);
    expect(ANDROID_UNLOCK_SOURCE).toContain('UnlockAndroid');
  });
});

describe('tool registration', () => {
  const lockProbe = ANDROID_TOOLS.find((t) => t.name === 'android_adb_lock_probe');
  const lockState = ANDROID_TOOLS.find((t) => t.name === 'android_adb_lock_state');

  it('registers both tools', () => {
    expect(lockProbe).toBeDefined();
    expect(lockState).toBeDefined();
  });

  it('gates the probe at the intrusive tier so it needs operator approval', () => {
    expect(lockProbe!.riskTier).toBe('intrusive');
  });

  it('keeps the read-only state check ungated', () => {
    expect(lockState!.riskTier).toBe('local_read');
  });

  it('requires the pin AND the authorization acknowledgement as parameters', () => {
    const required = (lockProbe!.parameters || []).filter((p) => p.required).map((p) => p.name);
    expect(required).toEqual(expect.arrayContaining(['pin', 'confirmAuthorized']));
  });

  it('states the authorized-device line in the description', () => {
    expect(lockProbe!.description).toMatch(/authorized/i);
    expect(lockProbe!.description).toMatch(/no PIN enumeration|brute force/i);
  });
});
