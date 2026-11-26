export type InvestigationKind = 'goal' | 'intent' | 'fact' | 'finding';

export type InvestigationEdgeKind = 'spawns' | 'yields' | 'derived_from' | 'proves';

export interface InvestigationNode {
  id: string;
  kind: InvestigationKind;
  ref?: string;
}

export interface InvestigationEdge {
  from: string;
  to: string;
  kind: InvestigationEdgeKind;
}

export interface InvestigationAnchor {
  nodeId: string;
  assetId: string;
}
