/**
 * In-memory containment ledger. Callers submit observations.
 * This module owns ids and dedupe. It does not replace Target or the attack graph.
 */

import { randomUUID } from 'node:crypto';
import { isTargetInAuthorizedScope } from '../governance/scope-match.js';
import type { AssetKind, AssetNode, AssetObservation } from './types.js';

const PARENT: Record<AssetKind, AssetKind | null> = {
  root: null,
  host: 'root',
  service: 'host',
  endpoint: 'service',
};

const SCOPED: ReadonlySet<AssetKind> = new Set(['host', 'service', 'endpoint']);

export class AssetGraph {
  private readonly nodes = new Map<string, AssetNode>();
  private readonly byKey = new Map<string, string>();

  constructor(private readonly scope: readonly string[]) {}

  list(): AssetNode[] {
    return [...this.nodes.values()].map((node) => ({ ...node }));
  }

  get(id: string): AssetNode | undefined {
    const node = this.nodes.get(id);
    return node ? { ...node } : undefined;
  }

  submit(observation: AssetObservation): AssetNode {
    const name = observation.name.trim().toLowerCase();
    if (!name) {
      throw new Error('asset name is empty');
    }
    if (SCOPED.has(observation.kind) && !isTargetInAuthorizedScope(name, this.scope)) {
      throw new Error(`out of scope: ${name}`);
    }
    const expectedParent = PARENT[observation.kind];
    let parentId: string | undefined;
    if (expectedParent) {
      if (!observation.parentId || !this.nodes.has(observation.parentId)) {
        throw new Error(`missing ${expectedParent} parent`);
      }
      const parent = this.nodes.get(observation.parentId);
      if (!parent || parent.kind !== expectedParent) {
        throw new Error(`parent must be ${expectedParent}`);
      }
      parentId = parent.id;
    } else if (observation.parentId) {
      throw new Error('root cannot have a parent');
    }

    const key = `${observation.kind}|${name}|${parentId ?? ''}`;
    const existingId = this.byKey.get(key);
    if (existingId) {
      const existing = this.nodes.get(existingId);
      if (!existing) throw new Error('dedupe key missing node');
      return { ...existing };
    }

    const node: AssetNode = { id: randomUUID(), kind: observation.kind, name, parentId };
    this.nodes.set(node.id, node);
    this.byKey.set(key, node.id);
    return { ...node };
  }
}

export type { AssetKind, AssetNode, AssetObservation } from './types.js';
