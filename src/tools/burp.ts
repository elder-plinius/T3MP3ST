/**
 * T3MP3ST — Burp Suite Integration & Proxy Bridge
 * ========================================================
 * Provides Burp Suite binary detection (host & Kali WSL),
 * proxy listener probing (default 127.0.0.1:8080), and 1-click
 * upstream interception routing for autonomous agent scan traffic.
 */

import { Socket } from 'net';
import { findBinaryLocation, type BinaryLocation } from '../arsenal/index.js';
import { configureProxy, getProxyStatus } from '../net/proxy.js';

export interface BurpStatus {
  installed: boolean;
  path: string | null;
  inWsl: boolean;
  distro?: string;
  listening: boolean;
  proxyHost: string;
  proxyPort: number;
  proxyUrl: string;
  proxyActive: boolean;
  summary: string;
}

export class BurpManager {
  private defaultHost: string = '127.0.0.1';
  private defaultPort: number = 8080;

  constructor(host?: string, port?: number) {
    if (host) this.defaultHost = host;
    if (port) this.defaultPort = port;
  }

  /**
   * Probe TCP listener with short timeout to check if Burp Proxy is running
   */
  public async isProxyListening(host = this.defaultHost, port = this.defaultPort, timeoutMs = 1500): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const socket = new Socket();
      let isResolved = false;

      const finish = (open: boolean) => {
        if (!isResolved) {
          isResolved = true;
          socket.destroy();
          resolve(open);
        }
      };

      socket.setTimeout(timeoutMs);
      socket.once('connect', () => finish(true));
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));

      try {
        socket.connect(port, host);
      } catch {
        finish(false);
      }
    });
  }

  /**
   * Get full Burp Suite readiness and proxy status
   */
  public async getStatus(host = this.defaultHost, port = this.defaultPort): Promise<BurpStatus> {
    const loc: BinaryLocation = await findBinaryLocation('burpsuite');
    const listening = await this.isProxyListening(host, port);
    const proxyState = getProxyStatus();
    const proxyUrl = `http://${host}:${port}`;
    const proxyActive = proxyState.enabled && (proxyState.url?.includes(`:${port}`) || false);

    let summary = 'Burp Suite is not installed.';
    if (loc.available) {
      if (listening) {
        summary = proxyActive
          ? `Burp Suite is running on ${host}:${port} with active T3MP3ST traffic interception.`
          : `Burp Suite proxy is listening on ${host}:${port}. Interception routing is ready.`;
      } else {
        summary = `Burp Suite binary is installed (${loc.inWsl ? 'Kali WSL' : 'Host'}), but proxy listener on ${host}:${port} is inactive.`;
      }
    }

    return {
      installed: loc.available,
      path: loc.path,
      inWsl: loc.inWsl,
      distro: loc.distro,
      listening,
      proxyHost: host,
      proxyPort: port,
      proxyUrl,
      proxyActive,
      summary,
    };
  }

  /**
   * Route T3MP3ST outbound agent traffic through Burp Proxy
   */
  public async enableInterception(host = this.defaultHost, port = this.defaultPort): Promise<{ ok: boolean; proxyUrl: string; message: string }> {
    const proxyUrl = `http://${host}:${port}`;
    try {
      configureProxy(proxyUrl);
      return {
        ok: true,
        proxyUrl,
        message: `T3MP3ST outbound traffic now routing through Burp Suite at ${proxyUrl}. All agent requests will appear in HTTP History.`,
      };
    } catch (err: unknown) {
      const msg = (err as Error).message || String(err);
      return {
        ok: false,
        proxyUrl,
        message: `Failed to configure Burp proxy: ${msg}`,
      };
    }
  }

  /**
   * Disable interception and return to direct / default connection
   */
  public disableInterception(): { ok: boolean; message: string } {
    try {
      configureProxy(null);
      return {
        ok: true,
        message: 'Burp Suite interception disabled. Outbound traffic restored to direct mode.',
      };
    } catch (err: unknown) {
      const msg = (err as Error).message || String(err);
      return {
        ok: false,
        message: `Failed to disable proxy: ${msg}`,
      };
    }
  }
}

export const burpManager = new BurpManager();

