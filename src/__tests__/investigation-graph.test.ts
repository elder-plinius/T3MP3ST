import { describe, expect, it } from 'vitest';
import { AssetGraph } from '../asset-graph/index.js';
import { InvestigationGraph } from '../investigation/index.js';

function seeded() {
  const assets = new AssetGraph(['app.example']);
  const root = assets.submit({ kind: 'root', name: 'mission' });
  const host = assets.submit({ kind: 'host', name: 'app.example', parentId: root.id });
  return { assets, host };
}

describe('investigation graph', () => {
  it('records the lineage chain', () => {
    const { host } = seeded();
    const graph = new InvestigationGraph([host.id]);
    const goal = graph.addNode('goal');
    const intent = graph.addNode('intent');
    const fact = graph.addNode('fact');
    const next = graph.addNode('intent');
    const finding = graph.addNode('finding', 'finding-1');
    graph.link(goal.id, intent.id, 'spawns');
    graph.link(intent.id, fact.id, 'yields');
    graph.link(fact.id, next.id, 'derived_from');
    graph.link(next.id, finding.id, 'proves');
    expect(graph.listEdges().map((edge) => edge.kind)).toEqual(['spawns', 'yields', 'derived_from', 'proves']);
  });

  it('rejects proves from a fact to a finding', () => {
    const { host } = seeded();
    const graph = new InvestigationGraph([host.id]);
    const fact = graph.addNode('fact');
    const finding = graph.addNode('finding', 'finding-1');
    expect(() => graph.link(fact.id, finding.id, 'proves')).toThrow(/illegal/);
    expect(graph.listEdges()).toHaveLength(0);
  });

  it('rejects an anchor to an unknown asset', () => {
    const graph = new InvestigationGraph([]);
    const intent = graph.addNode('intent');
    expect(() => graph.anchor(intent.id, 'missing-asset')).toThrow(/anchor/);
    expect(graph.listAnchors()).toHaveLength(0);
  });

  it('anchors a finding id to an endpoint asset', () => {
    const { assets, host } = seeded();
    const service = assets.submit({ kind: 'service', name: 'app.example', parentId: host.id });
    const endpoint = assets.submit({ kind: 'endpoint', name: 'app.example/health', parentId: service.id });
    const graph = new InvestigationGraph(assets.list().map((node) => node.id));
    const finding = graph.addNode('finding', 'finding-9');
    graph.anchor(finding.id, endpoint.id);
    expect(graph.listAnchors()).toEqual([{ nodeId: finding.id, assetId: endpoint.id }]);
  });
});
