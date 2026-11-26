/**
 * Recognize the ARTEX scanner image and the tool names that image ships.
 * Identity only: no flags, scripts, or request templates.
 */

const SCANNER_TOOLS = ['nmap', 'nuclei', 'httpx', 'katana', 'ffuf', 'dalfox', 'sqlmap'] as const;
const IMAGE_REF = 'ghcr.io/baarai/artex';

export interface ScannerHit {
  kind: 'tool' | 'image';
  name: string;
}

export function detectScannerObservation(text: string): ScannerHit[] {
  const hits: ScannerHit[] = [];
  const haystack = text.toLowerCase();
  if (haystack.includes(IMAGE_REF)) {
    hits.push({ kind: 'image', name: IMAGE_REF });
  }
  for (const tool of SCANNER_TOOLS) {
    const pattern = new RegExp(`\\b${tool}\\b`, 'i');
    if (pattern.test(text)) {
      hits.push({ kind: 'tool', name: tool });
    }
  }
  return hits;
}
