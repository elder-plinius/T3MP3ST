/**
 * Multi-language grammar registry for white-box ingest.
 *
 * Wraps web-tree-sitter (WASM) so `parseFileMultiLang` can extract CodeBlocks
 * from ~8 languages, replacing the Python-only regex parser. Grammars are
 * loaded ONCE at bootstrap (`initGrammars`) — `Parser.init()`/`Language.load()`
 * are async, but `parser.parse()` is sync, so the ingest path stays sync.
 *
 * Fail-open by design: if init throws (bad/missing wasm, version skew), the
 * registry is left empty. Python still routes to `parseFile`; non-Python files
 * yield no blocks — ingest never crashes a mission.
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
 * A JS/TS function *value* — arrow or function-expression — in the three param
 * shapes the grammars expose: a parenthesized list, a single un-parenthesized
 * arrow parameter (`x => …`), and a function expression (named or not). Every
 * branch binds `@params`, so the caller always gets the parameter names the
 * risky-parameter heuristic keys on.
 */
const JS_FN_VALUE = `[(arrow_function parameters: (formal_parameters) @params)
                      (arrow_function parameter: (identifier) @params)
                      (function_expression parameters: (formal_parameters) @params)]`;

/**
 * The JS/TS shapes that bind a name to a function value. Declarations alone miss
 * these, which is idiomatic modern JS/TS — `const f = () => …`,
 * `module.exports.handler = …`, route tables, class-field handlers — so their
 * sinks went unranked (issue #141). Property-assigned and object-literal forms
 * are named by the property, consistent with how `method_definition` is named:
 * it is the name the call graph and the entry-point heuristic match on.
 *
 * Deliberately NOT matched — no direct name-to-function binding, and guessing
 * one is worse than honest absence: HOC-wrapped definitions
 * (`const h = withAuth(async (req) => …)`, value is a `call_expression`) and
 * anonymous callbacks (`app.get('/x', (req, res) => …)`).
 *
 * The class-field node differs by dialect — `field_definition` with a `property`
 * field (js) vs `public_field_definition` with a `name` field (ts/tsx) — so both
 * are parameters. A `#private` field uses a different identifier node in both
 * dialects; it is captured too (name keeps the `#`), since a sink in a private
 * handler is exactly as dangerous as one in a public handler.
 */
const jsNamedFnValues = (fieldNode: string, fieldNameLabel: string): string => `
      (variable_declarator name: (identifier) @name value: ${JS_FN_VALUE}) @def
      (assignment_expression
        left: [(identifier) @name (member_expression property: (property_identifier) @name)]
        right: ${JS_FN_VALUE}) @def
      (pair key: (property_identifier) @name value: ${JS_FN_VALUE}) @def
      (${fieldNode} ${fieldNameLabel}: [(property_identifier) @name (private_property_identifier) @name]
        value: ${JS_FN_VALUE}) @def
`;

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
    ` + jsNamedFnValues('field_definition', 'property'),
  },
  '.ts': {
    wasm: 'tree-sitter-typescript', lang: 'ts',
    query: `
      (function_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (method_definition name: (property_identifier) @name parameters: (formal_parameters) @params) @def
      (class_declaration name: (type_identifier) @name) @def
    ` + jsNamedFnValues('public_field_definition', 'name'),
  },
  '.tsx': {
    wasm: 'tree-sitter-tsx', lang: 'ts',
    query: `
      (function_declaration name: (identifier) @name parameters: (formal_parameters) @params) @def
      (method_definition name: (property_identifier) @name parameters: (formal_parameters) @params) @def
      (class_declaration name: (type_identifier) @name) @def
    ` + jsNamedFnValues('public_field_definition', 'name'),
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
      (function_definition declarator: (pointer_declarator declarator: (function_declarator declarator: (identifier) @name parameters: (parameter_list) @params))) @def
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
 * partial) registry in place and marks init done — callers extract nothing for
 * exts that never loaded (non-.py fail-open is empty, not the Python regex).
 * `wasmResolve` lets a test force a bad path to exercise the failure branch.
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
    // global fail-open: registry stays empty → non-.py ingest extracts nothing.
    // Log once so an operator scanning a non-Python repo sees the degradation
    // (the `initialized` guard means this never retries for the process).
    console.warn(
      '[ts-grammars] grammar init failed; multi-language ingest disabled for this process ' +
        '(non-Python files will yield no blocks). Python ingest is unaffected.',
    );
  } finally {
    initialized = true;
  }
}

/** A loaded grammar for `ext`, or undefined (→ caller returns [] for non-.py; .py uses parseFile). */
export function getGrammar(ext: string): GrammarEntry | undefined {
  return registry.get(ext);
}

/** Test-only: reset init state + registry so a fresh `initGrammars` runs. */
export function __resetGrammarsForTest(): void {
  registry.clear();
  initialized = false;
}
