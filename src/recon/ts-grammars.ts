/**
 * Multi-language grammar registry for white-box ingest.
 *
 * Wraps web-tree-sitter (WASM) so `parseFileMultiLang` can extract CodeBlocks
 * from ~8 languages, replacing the Python-only regex parser. Grammars are
 * loaded ONCE at bootstrap (`initGrammars`) — `Parser.init()`/`Language.load()`
 * are async, but `parser.parse()` is sync, so the ingest path stays sync.
 *
 * Fail-open by design: if init throws (bad/missing wasm, version skew), the
 * registry is left empty and every file routes to the Python-regex `parseFile`
 * fallback — ingest never crashes a mission.
 */
import { Parser, Language, Query } from 'web-tree-sitter';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

/** A loaded grammar: the tree-sitter Language plus the compiled def-query. */
export interface GrammarEntry {
  language: Language;
  query: Query;
  /** Language id, for param-splitting dialect (py/js/ts/go/java/c/cpp). */
  lang: string;
}

/**
 * Per-extension spec: which prebuilt wasm (from tree-sitter-wasms) and the
 * tree-sitter query capturing function/method/class definitions. Every pattern
 * binds `@name` (the identifier) and `@def` (the whole definition node);
 * `@params` is bound where the grammar exposes a parameter list.
 */
const SPECS: Record<string, { wasm: string; lang: string; query: string }> = {
  '.py': {
    wasm: 'tree-sitter-python', lang: 'py',
    query: `
      (function_definition name: (identifier) @name parameters: (parameters) @params) @def
      (class_definition name: (identifier) @name) @def
    `,
  },
  '.js': {
    wasm: 'tree-sitter-javascript', lang: 'js',
    query: `
      (function_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (method_definition name: (property_identifier) @name parameters: (formal_parameters) @params) @def
      (class_declaration name: (identifier) @name) @def
    `,
  },
  '.ts': {
    wasm: 'tree-sitter-typescript', lang: 'ts',
    query: `
      (function_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (method_definition name: (property_identifier) @name parameters: (formal_parameters) @params) @def
      (class_declaration name: (type_identifier) @name) @def
    `,
  },
  '.tsx': {
    wasm: 'tree-sitter-tsx', lang: 'ts',
    query: `
      (function_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (method_definition name: (property_identifier) @name parameters: (formal_parameters) @params) @def
      (class_declaration name: (type_identifier) @name) @def
    `,
  },
  '.go': {
    wasm: 'tree-sitter-go', lang: 'go',
    query: `
      (function_declaration name: (identifier) @name parameters: (parameter_list) @params) @def
      (method_declaration name: (field_identifier) @name parameters: (parameter_list) @params) @def
    `,
  },
  '.java': {
    wasm: 'tree-sitter-java', lang: 'java',
    query: `
      (method_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (constructor_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (class_declaration name: (identifier) @name) @def
    `,
  },
  '.c': {
    wasm: 'tree-sitter-c', lang: 'c',
    query: `
      (function_definition declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @params)) @def
    `,
  },
  '.cpp': {
    wasm: 'tree-sitter-cpp', lang: 'cpp',
    query: `
      (function_definition declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @params)) @def
    `,
  },
};

const registry = new Map<string, GrammarEntry>();
let initialized = false;

/** Extensions (with leading dot) the registry can parse. */
export function supportedExts(): string[] {
  return Object.keys(SPECS);
}

/**
 * Load grammars once. Idempotent. Fail-open: any error leaves the (possibly
 * partial) registry in place and marks init done — callers fall back to
 * `parseFile` for exts that never loaded. `wasmDirOverride` lets a test force a
 * bad path to exercise the failure branch.
 */
export async function initGrammars(
  exts: string[] = supportedExts(),
  wasmResolve: (name: string) => string = (name) => require.resolve(`tree-sitter-wasms/out/${name}.wasm`),
  init: () => Promise<void> = () => Parser.init(),
): Promise<void> {
  if (initialized) return;
  try {
    await init();
    for (const ext of exts) {
      const spec = SPECS[ext];
      if (!spec) continue;
      try {
        const language = await Language.load(wasmResolve(spec.wasm));
        const query = new Query(language, spec.query);
        registry.set(ext, { language, query, lang: spec.lang });
      } catch {
        // per-ext fail-open: skip this grammar, keep the rest
      }
    }
  } catch {
    // global fail-open: registry stays empty → Python fallback everywhere
  } finally {
    initialized = true;
  }
}

/** A loaded grammar for `ext`, or undefined (→ caller falls back to parseFile). */
export function getGrammar(ext: string): GrammarEntry | undefined {
  return registry.get(ext);
}

/** Test-only: reset init state + registry so a fresh `initGrammars` runs. */
export function __resetGrammarsForTest(): void {
  registry.clear();
  initialized = false;
}
