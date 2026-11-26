/**
 * Scope-list coverage. A scope name is tested only when an anchor cites a
 * ledger node with that name. Missing anchor targets fail the report.
 */

import type { AssetNode } from "../asset-graph/types.js";
import type { InvestigationAnchor } from "../investigation/types.js";

export interface CoverageRow {
  name: string;
  status: "tested" | "untested";
}

export type CoverageReport =
  | { ok: true; tested: number; untested: number; rows: CoverageRow[] }
  | { ok: false; reason: string };

export function coverageReport(
  assets: readonly AssetNode[],
  anchors: readonly InvestigationAnchor[],
  scope: readonly string[],
): CoverageReport {
  const byId = new Map(assets.map((asset) => [asset.id, asset]));
  for (const anchor of anchors) {
    if (!byId.has(anchor.assetId)) {
      return { ok: false, reason: `anchor cites missing asset ${anchor.assetId}` };
    }
  }
  const testedNames = new Set<string>();
  for (const anchor of anchors) {
    const asset = byId.get(anchor.assetId);
    if (asset) testedNames.add(asset.name);
  }
  const rows: CoverageRow[] = scope.map((name) => {
    const normalized = name.trim().toLowerCase();
    return {
      name: normalized,
      status: testedNames.has(normalized) ? "tested" : "untested",
    };
  });
  const tested = rows.filter((row) => row.status === "tested").length;
  return { ok: true, tested, untested: rows.length - tested, rows };
}
