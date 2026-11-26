/**
 * Per-mission lineage. Stores finding id strings. It does not write the evidence vault.
 */

import { randomUUID } from 'node:crypto';
import type { InvestigationAnchor, InvestigationEdge, InvestigationEdgeKind, InvestigationKind, InvestigationNode } from './types.js';

const LEGAL: Record<InvestigationEdgeKind, [InvestigationKind, InvestigationKind]> = {
  spawns: ['goal', 'intent'],
  yields: ['intent', 'fact'],
  derived_from: ['fact', 'intent'],
  proves: ['intent', 'finding'],
};

const ANCHORABLE: ReadonlySet<InvestigationKind> = new Set(['intent', 'fact', 'finding']);

export class InvestigationGraph {
  private readonly nodes = new Map<string, InvestigationNode>();
  private readonly edges: InvestigationEdge[] = [];
  private readonly anchors: InvestigationAnchor[] = [];
  private readonly knownAssets: ReadonlySet<string>;

  constructor(assetIds: readonly string[]) {
    this.knownAssets = new Set(assetIds);
  }

  addNode(kind: InvestigationKind, ref?: string): InvestigationNode {
    const node: InvestigationNode = { id: randomUUID(), kind, ref };
    this.nodes.set(node.id, node);
    return { ...node };
  }

  link(from: string, to: string, kind: InvestigationEdgeKind): InvestigationEdge {
    const source = this.nodes.get(from);
    const target = this.nodes.get(to);
    const [expectFrom, expectTo] = LEGAL[kind];
    if (!source || !target || source.kind !== expectFrom || target.kind !== expectTo) {
      throw new Error(`illegal ${kind} edge`);
    }
    const edge: InvestigationEdge = { from, to, kind };
    this.edges.push(edge);
    return { ...edge };
  }

  anchor(nodeId: string, assetId: string): InvestigationAnchor {
    const node = this.nodes.get(nodeId);
    if (!node || !ANCHORABLE.has(node.kind) || !this.knownAssets.has(assetId)) {
      throw new Error('anchor rejected');
    }
    const pair: InvestigationAnchor = { nodeId, assetId };
    this.anchors.push(pair);
    return { ...pair };
  }

  listEdges(): InvestigationEdge[] {
    return this.edges.map((edge) => ({ ...edge }));
  }

  listAnchors(): InvestigationAnchor[] {
    return this.anchors.map((anchor) => ({ ...anchor }));
  }
}

export type { InvestigationAnchor, InvestigationEdge, InvestigationEdgeKind, InvestigationKind, InvestigationNode } from './types.js';
