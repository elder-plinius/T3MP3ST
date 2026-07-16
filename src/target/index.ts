/**
 * T3MP3ST Target Environment
 *
 * Manages target systems and attack surface modeling.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type {
  Target,
  TargetType,
  TargetZone,
  TargetStatus,
  Service,
  Vulnerability,
} from '../types/index.js';

// =============================================================================
// EVENTS
// =============================================================================

export interface TargetEvents {
  'target:added': Target;
  'target:updated': Target;
  'target:status_changed': { target: Target; oldStatus: TargetStatus };
  'target:owned': Target;
  'service:discovered': { target: Target; service: Service };
  'vulnerability:found': { target: Target; vulnerability: Vulnerability };
}

// =============================================================================
// TARGET ENVIRONMENT
// =============================================================================

export class TargetEnvironment extends EventEmitter<TargetEvents> {
  private targets: Map<string, Target> = new Map();

  /**
   * Add a target
   */
  addTarget(params: {
    name: string;
    type: TargetType;
    zone: TargetZone;
    address: string;
    port?: number;
    protocol?: string;
    metadata?: Record<string, unknown>;
  }): Target {
    const target: Target = {
      id: randomUUID(),
      name: params.name,
      type: params.type,
      zone: params.zone,
      status: 'discovered',
      address: params.address,
      port: params.port,
      protocol: params.protocol,
      services: [],
      vulnerabilities: [],
      credentials: [],
      metadata: params.metadata,
      discoveredAt: Date.now(),
    };

    this.targets.set(target.id, target);
    this.emit('target:added', target);

    return target;
  }

  /**
   * Update a target
   */
  updateTarget(targetId: string, updates: Partial<Target>): Target | undefined {
    const target = this.targets.get(targetId);
    if (target) {
      Object.assign(target, updates);
      this.emit('target:updated', target);
    }
    return target;
  }

  /**
   * Set target status
   */
  setStatus(targetId: string, status: TargetStatus): Target | undefined {
    const target = this.targets.get(targetId);
    if (target) {
      const oldStatus = target.status;
      target.status = status;
      this.emit('target:status_changed', { target, oldStatus });

      if (status === 'owned') {
        target.ownedAt = Date.now();
        this.emit('target:owned', target);
      }
    }
    return target;
  }

  /**
   * Add a service to a target
   */
  addService(targetId: string, service: Service): Target | undefined {
    const target = this.targets.get(targetId);
    if (target) {
      target.services = target.services || [];
      target.services.push(service);
      this.emit('service:discovered', { target, service });
    }
    return target;
  }

  /**
   * Add a vulnerability to a target
   */
  addVulnerability(targetId: string, vulnerability: Vulnerability): Target | undefined {
    const target = this.targets.get(targetId);
    if (target) {
      target.vulnerabilities = target.vulnerabilities || [];
      target.vulnerabilities.push(vulnerability);
      target.status = 'vulnerable';
      this.emit('vulnerability:found', { target, vulnerability });
    }
    return target;
  }

  /**
   * Get a target by ID
   */
  getTarget(targetId: string): Target | undefined {
    return this.targets.get(targetId);
  }

  /**
   * Get a target by address
   */
  getTargetByAddress(address: string): Target | undefined {
    for (const target of this.targets.values()) {
      if (target.address === address) {
        return target;
      }
    }
    return undefined;
  }

  /**
   * Get all targets
   */
  getAllTargets(): Target[] {
    return Array.from(this.targets.values());
  }

  /**
   * Get targets by zone
   */
  getTargetsByZone(zone: TargetZone): Target[] {
    return this.getAllTargets().filter(t => t.zone === zone);
  }

  /**
   * Get targets by type
   */
  getTargetsByType(type: TargetType): Target[] {
    return this.getAllTargets().filter(t => t.type === type);
  }

  /**
   * Get targets by status
   */
  getTargetsByStatus(status: TargetStatus): Target[] {
    return this.getAllTargets().filter(t => t.status === status);
  }

  /**
   * Get owned targets
   */
  getOwnedTargets(): Target[] {
    return this.getAllTargets().filter(t => t.status === 'owned');
  }

  /**
   * Get vulnerable targets
   */
  getVulnerableTargets(): Target[] {
    return this.getAllTargets().filter(t => t.status === 'vulnerable');
  }

  /**
   * Remove a target
   */
  removeTarget(targetId: string): boolean {
    return this.targets.delete(targetId);
  }

  /**
   * Get statistics
   */
  getStats(): {
    total: number;
    byZone: Record<TargetZone, number>;
    byType: Record<TargetType, number>;
    byStatus: Record<TargetStatus, number>;
    owned: number;
    vulnerable: number;
    totalVulnerabilities: number;
  } {
    const targets = this.getAllTargets();

    const byZone: Record<TargetZone, number> = {
      external: 0,
      dmz: 0,
      internal: 0,
      restricted: 0,
      airgapped: 0,
    };

    const byType: Record<TargetType, number> = {
      web_application: 0,
      api: 0,
      network: 0,
      host: 0,
      database: 0,
      cloud: 0,
      mobile: 0,
      iot: 0,
      container: 0,
    };

    const byStatus: Record<TargetStatus, number> = {
      discovered: 0,
      scanning: 0,
      vulnerable: 0,
      exploited: 0,
      owned: 0,
      exfiltrated: 0,
    };

    let totalVulnerabilities = 0;

    for (const target of targets) {
      byZone[target.zone]++;
      byType[target.type]++;
      byStatus[target.status]++;
      totalVulnerabilities += target.vulnerabilities?.length || 0;
    }

    return {
      total: targets.length,
      byZone,
      byType,
      byStatus,
      owned: byStatus.owned,
      vulnerable: byStatus.vulnerable,
      totalVulnerabilities,
    };
  }

  /**
   * Clear all targets
   */
  clear(): void {
    this.targets.clear();
  }
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

export function createTargetFromUrl(url: string, zone: TargetZone = 'external'): Target {
  const parsed = new URL(url);
  const normalizedUrl = parsed.toString();

  return {
    id: randomUUID(),
    name: parsed.hostname,
    type: 'web_application',
    zone,
    status: 'discovered',
    address: parsed.hostname,
    port: parsed.port ? parseInt(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80),
    protocol: parsed.protocol.replace(':', ''),
    services: [],
    vulnerabilities: [],
    credentials: [],
    metadata: {
      url: normalizedUrl,
      origin: parsed.origin,
      path: `${parsed.pathname}${parsed.search}${parsed.hash}`,
    },
    discoveredAt: Date.now(),
  };
}

export function createTargetFromIP(ip: string, zone: TargetZone = 'internal'): Target {
  return {
    id: randomUUID(),
    name: ip,
    type: 'host',
    zone,
    status: 'discovered',
    address: ip,
    services: [],
    vulnerabilities: [],
    credentials: [],
    discoveredAt: Date.now(),
  };
}

export function createDMZArchitecture(): Target[] {
  return [
    {
      id: randomUUID(),
      name: 'Web Server',
      type: 'web_application',
      zone: 'dmz',
      status: 'discovered',
      address: '10.0.1.10',
      port: 443,
      protocol: 'https',
      services: [],
      vulnerabilities: [],
      credentials: [],
      discoveredAt: Date.now(),
    },
    {
      id: randomUUID(),
      name: 'API Gateway',
      type: 'api',
      zone: 'dmz',
      status: 'discovered',
      address: '10.0.1.20',
      port: 8443,
      protocol: 'https',
      services: [],
      vulnerabilities: [],
      credentials: [],
      discoveredAt: Date.now(),
    },
    {
      id: randomUUID(),
      name: 'Database Server',
      type: 'database',
      zone: 'internal',
      status: 'discovered',
      address: '10.0.2.10',
      port: 5432,
      protocol: 'tcp',
      services: [],
      vulnerabilities: [],
      credentials: [],
      discoveredAt: Date.now(),
    },
  ];
}
