import { describe, expect, it } from 'vitest';
import { AssetGraph } from '../asset-graph/index.js';

describe('asset graph', () => {
  it('dedupes a host submitted twice under the same root', () => {
    const graph = new AssetGraph(['app.example']);
    const root = graph.submit({ kind: 'root', name: 'mission' });
    const first = graph.submit({ kind: 'host', name: 'App.Example', parentId: root.id });
    const second = graph.submit({ kind: 'host', name: 'app.example', parentId: root.id });
    expect(second.id).toBe(first.id);
    expect(graph.list().filter((node) => node.kind === 'host')).toHaveLength(1);
  });

  it('rejects an endpoint whose parent service does not exist', () => {
    const graph = new AssetGraph(['app.example']);
    expect(() => graph.submit({ kind: 'endpoint', name: 'app.example/health', parentId: 'missing' })).toThrow(/parent/);
    expect(graph.list()).toHaveLength(0);
  });

  it('rejects an out-of-scope host and leaves the store empty', () => {
    const graph = new AssetGraph(['app.example']);
    expect(() => graph.submit({ kind: 'host', name: 'evil.example' })).toThrow(/scope/);
    expect(graph.list()).toHaveLength(0);
  });

  it('rejects an out-of-scope service under an in-scope host', () => {
    const graph = new AssetGraph(['app.example']);
    const root = graph.submit({ kind: 'root', name: 'mission' });
    const host = graph.submit({ kind: 'host', name: 'app.example', parentId: root.id });
    const before = graph.list().length;
    expect(() => graph.submit({ kind: 'service', name: 'evil.example', parentId: host.id })).toThrow(/scope/);
    expect(graph.list()).toHaveLength(before);
  });

  it('links an in-scope endpoint to its host through the service', () => {
    const graph = new AssetGraph(['app.example']);
    const root = graph.submit({ kind: 'root', name: 'mission' });
    const host = graph.submit({ kind: 'host', name: 'app.example', parentId: root.id });
    const service = graph.submit({ kind: 'service', name: 'app.example', parentId: host.id });
    const endpoint = graph.submit({ kind: 'endpoint', name: 'app.example/health', parentId: service.id });
    expect(endpoint.parentId).toBe(service.id);
  });
});
