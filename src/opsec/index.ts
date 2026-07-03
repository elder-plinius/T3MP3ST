/**
 * T3MP3ST OPSEC Controller
 *
 * Manages operational security, detection monitoring, and evasion.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type {
  OpsecConfig,
  OpsecLevel,
  DetectionEvent,
  Severity,
} from '../types/index.js';

// =============================================================================
// EVENTS
// =============================================================================

export interface OpsecEvents {
  'detection:triggered': DetectionEvent;
  'opsec:level_changed': { oldLevel: OpsecLevel; newLevel: OpsecLevel };
  'opsec:abort_recommended': { reason: string };
  'cooldown:started': { durationMs: number };
  'cooldown:ended': void;
}

// =============================================================================
// IOC (Indicators of Compromise)
// =============================================================================

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'signature' | 'behavior';
  value: string;
  description: string;
  createdAt: number;
}

// =============================================================================
// DEFAULT CONFIGS
// =============================================================================

const DEFAULT_OPSEC_CONFIG: OpsecConfig = {
  level: 'covert',
  maxDetectionEvents: 3,
  cooldownAfterDetection: 60000,
  cleanupOnComplete: true,
  avoidDetection: true,
  jitterRange: [1000, 5000],
  trafficBlending: true,
  loggingSanitization: true,
};

export function createSilentOpsecConfig(): OpsecConfig {
  return {
    level: 'silent',
    maxDetectionEvents: 1,
    cooldownAfterDetection: 300000,
    cleanupOnComplete: true,
    avoidDetection: true,
    jitterRange: [5000, 15000],
    trafficBlending: true,
    loggingSanitization: true,
  };
}

export function createAggressiveOpsecConfig(): OpsecConfig {
  return {
    level: 'loud',
    maxDetectionEvents: 20,
    cooldownAfterDetection: 2000,
    cleanupOnComplete: false,
    avoidDetection: false,
    jitterRange: [100, 500],
    trafficBlending: false,
    loggingSanitization: false,
  };
}

export function createBalancedOpsecConfig(): OpsecConfig {
  return { ...DEFAULT_OPSEC_CONFIG };
}

// =============================================================================
// OPSEC CONTROLLER
// =============================================================================

export class OpsecController extends EventEmitter<OpsecEvents> {
  private config: OpsecConfig;
  private detectionEvents: DetectionEvent[] = [];
  private iocs: IOC[] = [];
  private inCooldown: boolean = false;
  private cooldownTimer: NodeJS.Timeout | null = null;

  constructor(config?: Partial<OpsecConfig>) {
    super();
    this.config = { ...DEFAULT_OPSEC_CONFIG, ...config };
  }

  /**
   * Get current OPSEC level
   */
  getLevel(): OpsecLevel {
    return this.config.level;
  }

  /**
   * Set OPSEC level
   */
  setLevel(level: OpsecLevel): void {
    const oldLevel = this.config.level;
    this.config.level = level;
    this.emit('opsec:level_changed', { oldLevel, newLevel: level });
  }

  /**
   * Record a detection event
   */
  recordDetection(params: {
    type: DetectionEvent['type'];
    severity: Severity;
    source: string;
    description: string;
    operatorId?: string;
    targetId?: string;
  }): DetectionEvent {
    const event: DetectionEvent = {
      id: randomUUID(),
      type: params.type,
      severity: params.severity,
      source: params.source,
      description: params.description,
      operatorId: params.operatorId,
      targetId: params.targetId,
      timestamp: Date.now(),
      mitigated: false,
    };

    this.detectionEvents.push(event);
    this.emit('detection:triggered', event);

    // Check if we should recommend abort
    if (this.detectionEvents.length >= this.config.maxDetectionEvents) {
      this.emit('opsec:abort_recommended', {
        reason: `Maximum detection events (${this.config.maxDetectionEvents}) reached`,
      });
    }

    // Start cooldown if configured
    if (this.config.avoidDetection && !this.inCooldown) {
      this.startCooldown();
    }

    return event;
  }

  /**
   * Mark a detection as mitigated
   */
  mitigateDetection(eventId: string): DetectionEvent | undefined {
    const event = this.detectionEvents.find(e => e.id === eventId);
    if (event) {
      event.mitigated = true;
    }
    return event;
  }

  /**
   * Get all detection events
   */
  getDetectionEvents(): DetectionEvent[] {
    return [...this.detectionEvents];
  }

  /**
   * Get unmitigated detection events
   */
  getActiveDetections(): DetectionEvent[] {
    return this.detectionEvents.filter(e => !e.mitigated);
  }

  /**
   * Check if abort is recommended
   */
  isAbortRecommended(): boolean {
    const activeDetections = this.getActiveDetections();
    return activeDetections.length >= this.config.maxDetectionEvents;
  }

  /**
   * Add an IOC
   */
  addIOC(ioc: Omit<IOC, 'id' | 'createdAt'>): IOC {
    const newIOC: IOC = {
      id: randomUUID(),
      ...ioc,
      createdAt: Date.now(),
    };
    this.iocs.push(newIOC);
    return newIOC;
  }

  /**
   * Get all IOCs
   */
  getIOCs(): IOC[] {
    return [...this.iocs];
  }

  /**
   * Start cooldown period
   */
  private startCooldown(): void {
    if (this.inCooldown) return;

    this.inCooldown = true;
    this.emit('cooldown:started', { durationMs: this.config.cooldownAfterDetection });

    this.cooldownTimer = setTimeout(() => {
      this.inCooldown = false;
      this.cooldownTimer = null;
      this.emit('cooldown:ended');
    }, this.config.cooldownAfterDetection);
  }

  /**
   * Check if in cooldown
   */
  isInCooldown(): boolean {
    return this.inCooldown;
  }

  /**
   * Get jittered delay
   */
  getJitteredDelay(): number {
    const [min, max] = this.config.jitterRange;
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  /**
   * Get statistics
   */
  getStats(): {
    level: OpsecLevel;
    totalDetections: number;
    activeDetections: number;
    mitigatedDetections: number;
    iocCount: number;
    inCooldown: boolean;
    abortRecommended: boolean;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  } {
    const totalDetections = this.detectionEvents.length;
    const activeDetections = this.getActiveDetections().length;
    const mitigatedDetections = totalDetections - activeDetections;

    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    const riskRatio = activeDetections / this.config.maxDetectionEvents;

    if (riskRatio >= 1) riskLevel = 'critical';
    else if (riskRatio >= 0.7) riskLevel = 'high';
    else if (riskRatio >= 0.3) riskLevel = 'medium';

    return {
      level: this.config.level,
      totalDetections,
      activeDetections,
      mitigatedDetections,
      iocCount: this.iocs.length,
      inCooldown: this.inCooldown,
      abortRecommended: this.isAbortRecommended(),
      riskLevel,
    };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<OpsecConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration
   */
  getConfig(): OpsecConfig {
    return { ...this.config };
  }

  /**
   * Clear all detection events (for cleanup)
   */
  clearDetections(): void {
    this.detectionEvents = [];
  }

  /**
   * Cleanup resources
   */
  cleanup(): void {
    if (this.cooldownTimer) {
      clearTimeout(this.cooldownTimer);
      this.cooldownTimer = null;
    }
    this.inCooldown = false;
  }
}
