import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

const html = readFileSync('docs/index.html', 'utf8');
const shell = readFileSync('docs/app-shell.js', 'utf8');
const css = readFileSync('docs/cve-vault.css', 'utf8');

class FakeClassList {
  values = new Set<string>();
  constructor(...initial: string[]) { initial.forEach(value => this.values.add(value)); }
  toggle(value: string, force: boolean) { if (force) this.values.add(value); else this.values.delete(value); }
  remove(value: string) { this.values.delete(value); }
}

class FakeElement {
  classList: FakeClassList;
  dataset: Record<string, string>;
  id: string;
  hidden = false;
  tabIndex = -1;
  textContent = '';
  attributes = new Map<string, string>();
  listeners = new Map<string, (event: { key?: string; preventDefault(): void }) => void>();
  constructor(id: string, page?: string, active = false) {
    this.id = id;
    this.dataset = page ? { page } : {};
    this.classList = new FakeClassList(...(active ? ['active'] : []));
  }
  setAttribute(name: string, value: string) { this.attributes.set(name, value); }
  removeAttribute(name: string) { this.attributes.delete(name); }
  addEventListener(name: string, listener: (event: { key?: string; preventDefault(): void }) => void) { this.listeners.set(name, listener); }
}

function shellHarness(hash: string) {
  const navs = [new FakeElement('nav-warroom', 'warroom', true), new FakeElement('nav-cve', 'cve-vault')];
  const pages = [new FakeElement('page-warroom'), new FakeElement('page-cve-vault')];
  const title = new FakeElement('pageTitle');
  const sidebar = new FakeElement('sidebar');
  const readiness = new FakeElement('readiness');
  const ids = new Map([...pages, title, sidebar].map(node => [node.id, node]));
  const location = { hash };
  const windowListeners = new Map<string, () => void>();
  const document = {
    readyState: 'complete',
    getElementById: (id: string) => ids.get(id) || null,
    querySelector: (selector: string) => selector === '.nav-item.active[data-page]' ? navs.find(nav => nav.classList.values.has('active')) || null : null,
    querySelectorAll: (selector: string) => selector === '.page' ? pages : selector === '[data-shell-readiness]' ? [readiness] : navs,
    addEventListener: () => undefined,
    dispatchEvent: () => true,
  };
  const window = {
    location,
    history: {
      pushState: (_state: null, _title: string, value: string) => { location.hash = value; },
      replaceState: (_state: null, _title: string, value: string) => { location.hash = value; },
    },
    setTimeout: (callback: () => void) => callback(),
    clearTimeout: () => undefined,
    addEventListener: (name: string, listener: () => void) => windowListeners.set(name, listener),
  };
  class FakeCustomEvent { constructor(_name: string, _init: { detail: { page: string } }) {} }
  const fetch = async () => { throw new Error('offline test harness'); };
  class FakeAbortController { signal = {}; abort() {} }
  vm.runInNewContext(shell, { window, document, CustomEvent: FakeCustomEvent, fetch, AbortController: FakeAbortController });
  return { window, navs, pages, title, readiness };
}

describe('incremental application shell', () => {
  it('loads one self-hosted shared shell and marks CVE Vault as the representative module', () => {
    expect(html.match(/<script src="app-shell\.js"><\/script>/g)).toHaveLength(1);
    expect(html).toContain('data-page="cve-vault" data-shell-module="true"');
    expect(shell).toContain("'cve-vault': 'CVE Vault'");
    expect(html).toContain('id="page-cve-vault"');
    expect(html).toContain('<noscript>CVE Vault search requires JavaScript.');
  });

  it('parses as a classic external script and stays compatible with self-only script CSP', () => {
    expect(() => new vm.Script(shell, { filename: 'docs/app-shell.js' })).not.toThrow();
    expect(shell).not.toMatch(/\beval\s*\(|new Function|innerHTML|document\.write/);
    const moduleStart = html.indexOf('<div class="page" id="page-cve-vault">');
    const moduleEnd = html.indexOf('</main>', moduleStart);
    expect(html.slice(moduleStart, moduleEnd)).not.toMatch(/\son[a-z]+=/i);
  });

  it('provides deterministic deep links and keyboard activation without trusting arbitrary hashes', () => {
    expect(shell).toContain("var hash = '#/' + page");
    expect(shell).toContain("event.key !== 'Enter' && event.key !== ' '");
    expect(shell).toContain("if (!titles[page] || !document.getElementById('page-' + page)) return false");
    expect(shell).toContain("window.addEventListener('hashchange'");
    expect(shell).toContain("item.setAttribute('aria-current'");
  });

  it('activates a deep link and supports keyboard route changes', () => {
    const harness = shellHarness('#/cve-vault');
    expect(harness.pages[1].hidden).toBe(false);
    expect(harness.pages[0].hidden).toBe(true);
    expect(harness.title.textContent).toBe('CVE Vault');
    expect(harness.navs[1].attributes.get('aria-current')).toBe('page');

    let prevented = false;
    harness.navs[0].listeners.get('keydown')?.({ key: 'Enter', preventDefault: () => { prevented = true; } });
    expect(prevented).toBe(true);
    expect(harness.window.location.hash).toBe('#/warroom');
    expect(harness.pages[0].hidden).toBe(false);
  });

  it('rejects unknown hashes and renders server-authoritative readiness states', () => {
    const harness = shellHarness('#/not-a-route');
    expect(harness.title.textContent).toBe('War Room');
    expect(harness.window.location.hash).toBe('#/not-a-route');
    const shellApi = (harness.window as typeof harness.window & { T3MP3STShell: { updateReadiness(payload: object): void } }).T3MP3STShell;
    shellApi.updateReadiness({ status: 'operational', llm: { connected: true } });
    expect(harness.readiness.textContent).toBe('API and LLM ready (server verified)');
    expect(harness.readiness.dataset.state).toBe('ready');
  });

  it('derives API and LLM readiness only from server health payloads', () => {
    expect(shell).toContain("payload.status === 'operational'");
    expect(shell).toContain('payload.llm && payload.llm.connected');
    expect(shell).not.toMatch(/localStorage|sessionStorage|apiKey|secret/i);
    expect(shell).toContain("fetch('/api/health'");
    expect(html).toContain('data-shell-readiness');
  });

  it('keeps the representative visual and responsive contract stable', () => {
    expect({
      layout: css.includes('grid-template-columns:minmax(18rem,1fr) minmax(18rem,1fr)'),
      responsive: css.includes('@media (max-width:800px)'),
      focus: css.includes(':focus-visible'),
      ready: css.includes('[data-state="ready"]'),
      limited: css.includes('[data-state="limited"]'),
      offline: css.includes('[data-state="offline"]'),
    }).toEqual({ layout: true, responsive: true, focus: true, ready: true, limited: true, offline: true });
  });
});
