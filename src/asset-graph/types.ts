export type AssetKind = 'root' | 'host' | 'service' | 'endpoint';

export interface AssetNode {
  id: string;
  kind: AssetKind;
  name: string;
  parentId?: string;
}

export interface AssetObservation {
  kind: AssetKind;
  name: string;
  parentId?: string;
}
