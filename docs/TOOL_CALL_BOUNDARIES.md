# Tool-call repair and reflection boundaries

Text-model tool calls pass through `enforceToolCallBoundary` before reaching the agent loop. The boundary accepts only explicit JSON action-contract payloads, removes trailing commas as its sole syntax repair, and validates the call against the exact tool definitions offered for that request. It never guesses a tool name, argument, target, authorization value, or schema default.

Malformed JSON, unknown tools, absent or invalid arguments, extra fields forbidden by a schema, and duplicate calls raise an observable `ToolCallBoundaryError`. Because this occurs inside the provider request, the existing bounded LLM retry policy handles retries and exposes retry events; exhaustion remains a hard error. Ordinary prose without a tool-call shape remains a valid final response.

`reflectStrategy` is advisory only. Its output always sets `mayExecute: false`, copies the current scope, approval, receipt, evidence, iteration, and token boundaries, and marks proposed out-of-scope targets or unapproved tools as requiring approval. A caller must still submit any later action through the normal Arsenal scope, schema, approval, receipt, budget, and evidence gates.

Model text and tool output are untrusted content. Neither repair nor reflection interprets instructions embedded in that content as authority.
