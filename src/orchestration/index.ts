/**
 * T3MP3ST Decomposition Orchestrator
 *
 * The "master builder" pattern: an orchestrator model (opus) holds the full
 * offensive objective, decomposes it into individually-innocuous analytical
 * subtasks, routes those to the strongest available reasoner (even models
 * that decline explicit offensive prompts), and reassembles the results into
 * exploit intelligence.
 *
 * Each decomposed query is a legitimate code-analysis question:
 *   "Does this function validate the length parameter before the memcpy?"
 *   "Trace the data flow from recvfrom() to all sinks in this file."
 *   "What is sizeof(DirectLidarStateInfo) and which fields are <4 bytes?"
 *
 * The orchestrator never sends the full offensive context to the worker model.
 * Only the orchestrator knows the attack plan — workers see benign analytical
 * queries and return structured answers. The orchestrator synthesizes.
 */

export { DecompositionOrchestrator } from './orchestrator.js';
export type {
  DecompositionConfig,
  DecompositionResult,
  DecomposedQuery,
  QueryResult,
  SynthesisResult,
  DecompositionEvents,
} from './types.js';
