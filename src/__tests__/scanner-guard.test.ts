import { describe, expect, it } from 'vitest';
import { detectScannerObservation } from '../detection/scanner-guard.js';

describe('scanner guard', () => {
  it('reports the ARTEX image reference', () => {
    expect(detectScannerObservation('pulled ghcr.io/baarai/artex:latest')).toEqual([
      { kind: 'image', name: 'ghcr.io/baarai/artex' },
    ]);
  });

  it('reports a bundled tool name as a whole word', () => {
    expect(detectScannerObservation('started nuclei against the range')).toEqual([
      { kind: 'tool', name: 'nuclei' },
    ]);
  });

  it('returns no hit for ordinary text', () => {
    expect(detectScannerObservation('ordinary browser')).toEqual([]);
  });

  it('does not match a tool name glued inside another token', () => {
    expect(detectScannerObservation('nothttpxtool')).toEqual([]);
  });
});
