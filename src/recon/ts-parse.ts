/**
 * Multi-language CodeBlock extractor — the tree-sitter replacement for the
 * Python-only `parseFile`. Emits the SAME `CodeBlock` shape so the downstream
 * security-ranking pipeline (classify/prioritize/reachability) is reused
 * verbatim.
 *
 * Fail-open on every path: unsupported/unloaded ext, parse timeout, or any
 * parser error routes the file to the Python-regex `parseFile`. A hostile input
 * cannot crash or hang a mission — the parse is time-bounded.
 */
import { Parser, type Node } from 'web-tree-sitter';
import { getGrammar } from './ts-grammars.js';
import { splitParamList } from './param-split.js';
import { parseFile, type CodeBlock } from './code-ingest.js';

/** Hard per-file parse bound (wall-clock ms). A pathological input hits this and fail-opens. */
const PARSE_BUDGET_MS = 5000;

let sharedParser: Parser | null = null;
function getParser(): Parser {
  if (!sharedParser) sharedParser = new Parser();
  return sharedParser;
}
/** Drop the parser after a timeout/error so the next parse starts clean. */
function resetParser(): void {
  sharedParser = null;
}

function kindOf(nodeType: string): CodeBlock['kind'] {
  if (nodeType.includes('class')) return 'class';
  if (nodeType.includes('method') || nodeType.includes('constructor')) return 'method';
  return 'function';
}

/** Map a captured definition node (+ its name/params captures) to a CodeBlock. */
export function nodeToCodeBlock(
  def: Node,
  nameNode: Node,
  paramsNode: Node | undefined,
  path: string,
  lang: string,
): CodeBlock {
  const name = nameNode.text;
  const lineStart = def.startPosition.row + 1; // tree-sitter rows are 0-indexed
  const lineEnd = def.endPosition.row + 1;
  return {
    id: `${path}::${name}@${lineStart}`,
    path,
    name,
    kind: kindOf(def.type),
    lineStart,
    lineEnd,
    params: paramsNode ? splitParamList(paramsNode.text, lang) : [],
    decorators: [],
    body: def.text,
  };
}

/**
 * Extract CodeBlocks from one file. `.py` keeps the regex parser (benchmark
 * stability); other languages use tree-sitter; everything else fail-opens.
 * ponytail: unify Python onto tree-sitter only if CVE-Zero is re-baselined.
 */
export function parseFileMultiLang(
  path: string,
  content: string,
  ext: string,
  makeParser: () => Parser = getParser,
): CodeBlock[] {
  if (ext === '.py') return parseFile(path, content);
  const g = getGrammar(ext);
  if (!g) return parseFile(path, content); // unsupported / grammars not loaded
  try {
    const p = makeParser();
    p.setLanguage(g.language);
    // Bound parse wall-time: progressCallback returning true cancels the parse
    // (→ parse returns null). setTimeoutMicros is deprecated/broken in 0.25.
    const start = Date.now();
    const tree = p.parse(content, undefined, {
      progressCallback: () => Date.now() - start > PARSE_BUDGET_MS,
    });
    if (!tree) {
      resetParser(); // parse cancelled (budget exceeded)
      return parseFile(path, content);
    }
    const blocks: CodeBlock[] = [];
    for (const match of g.query.matches(tree.rootNode)) {
      const caps: Record<string, Node> = {};
      for (const c of match.captures) caps[c.name] = c.node;
      blocks.push(nodeToCodeBlock(caps.def, caps.name, caps.params, path, g.lang));
    }
    return blocks;
  } catch {
    resetParser();
    return parseFile(path, content); // any parser error → fail-open
  }
}
