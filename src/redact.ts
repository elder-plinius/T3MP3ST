/**
 * redact — strip high-entropy tokens that look like secrets before sending
 * source text to an LLM. This is a best-effort filter, not a guarantee.
 */

const SECRET_PATTERNS: RegExp[] = [
  // Generic high-entropy strings that appear as assignment values
  /(?:password|passwd|secret|token|api_key|apikey|auth|credential|private_key)\s*[=:]\s*["']([^"']{8,})["']/gi,
  // AWS-style access keys
  /AKIA[0-9A-Z]{16}/g,
  // JWT tokens
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  // Generic hex secrets (32+ chars)
  /\b[0-9a-f]{32,64}\b/gi,
];

export function redactString(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match) => {
      // Preserve the key name if present; replace just the value portion
      const equalsIdx = match.search(/[=:]\s*["']/);
      if (equalsIdx !== -1) {
        return match.slice(0, equalsIdx + 1) + ' "***REDACTED***"';
      }
      return '***REDACTED***';
    });
  }
  return out;
}
