/**
 * T3MP3ST BLU3H4T — Detection Engine
 *
 * Factory and exports for the detection subsystem. Composes all
 * components (bus, registry, signature matcher, ATT&CK rules,
 * anomaly engine, AI detector, correlator, SIEM connectors)
 * into a single DetectionEngine instance.
 */

import type { DetectionConfig, ConnectorConfig, CredentialProvider } from './types.js';
import { DetectionBus, createDetectionBus } from './bus.js';
import { DetectionRegistry, createDetectionRegistry } from './registry.js';
import { SignatureMatcher, createSignatureMatcher } from './signatures.js';
import { ATTACKRuleEngine, createATTACKRuleEngine } from './attack-rules.js';
import { AnomalyEngine, createAnomalyEngine } from './anomaly.js';
import { AIAgentDetector, createAIAgentDetector } from './ai-detector.js';
import { AlertCorrelator, createAlertCorrelator } from './correlator.js';
import { SIEMConnector } from './connectors/types.js';
import { createWazuhConnector } from './connectors/wazuh.js';
import { createELKConnector } from './connectors/elk.js';
import { EnvCredentialProvider } from './connectors/types.js';

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export * from './types.js';

// =============================================================================
// MODULE EXPORTS
// =============================================================================

export { DetectionBus, createDetectionBus } from './bus.js';
export { DetectionRegistry, createDetectionRegistry } from './registry.js';
export { SignatureMatcher, createSignatureMatcher } from './signatures.js';
export { ATTACKRuleEngine, createATTACKRuleEngine } from './attack-rules.js';
export { AnomalyEngine, createAnomalyEngine } from './anomaly.js';
export { AIAgentDetector, createAIAgentDetector } from './ai-detector.js';
export { isKnownScannerIdentifier } from './scanner-guard.js';
export { isKnownHuntSkillSlug } from './hunt-skill-guard.js';
export { AlertCorrelator, createAlertCorrelator } from './correlator.js';
export { SIEMConnector, EnvCredentialProvider } from './connectors/types.js';
export { WazuhConnector, createWazuhConnector } from './connectors/wazuh.js';
export { ELKConnector, createELKConnector } from './connectors/elk.js';

// =============================================================================
// DETECTION ENGINE (composed)
// =============================================================================

export interface DetectionEngine {
  bus: DetectionBus;
  registry: DetectionRegistry;
  signatures: SignatureMatcher;
  attackRules: ATTACKRuleEngine;
  anomaly: AnomalyEngine;
  aiDetector: AIAgentDetector;
  correlator: AlertCorrelator;
  connectors: SIEMConnector[];

  start(): void;
  stop(): void;
  getStats(): DetectionEngineStats;
}

export interface DetectionEngineStats {
  running: boolean;
  totalRules: number;
  enabledRules: number;
  eventsIngested: number;
  confirmedAIAgents: number;
  matureBaselines: number;
  connectorCount: number;
  connectedConnectors: number;
  correlatorPending: number;
}

// =============================================================================
// FACTORY
// =============================================================================

export function createDetectionEngine(
  config: DetectionConfig,
  credentialProvider?: CredentialProvider,
): DetectionEngine {
  const bus = createDetectionBus({
    maxEventsPerSecond: config.maxEventsPerSecond ?? 0,
    enableWAL: config.enableWAL ?? false,
    walPath: config.walPath ?? './detection-wal.jsonl',
  });

  const registry = createDetectionRegistry();

  const signatures = createSignatureMatcher();
  signatures.attach(bus, registry);

  const attackRules = createATTACKRuleEngine();
  attackRules.attach(bus, registry);

  const anomaly = createAnomalyEngine(config.anomaly);
  anomaly.attach(bus);

  const aiDetector = createAIAgentDetector(config.aiDetection);
  aiDetector.attach(bus);

  const correlator = createAlertCorrelator({
    windowMs: config.correlationWindowMs ?? 30_000,
  });
  correlator.attach(bus);

  const provider = credentialProvider ?? new EnvCredentialProvider();
  const connectors: SIEMConnector[] = [];

  for (const connConfig of config.connectors ?? []) {
    if (!connConfig.enabled) continue;

    const connector = createConnector(connConfig, provider);
    if (connector) {
      connectors.push(connector);
    }
  }

  return {
    bus,
    registry,
    signatures,
    attackRules,
    anomaly,
    aiDetector,
    correlator,
    connectors,

    start(): void {
      bus.start();

      for (const connector of connectors) {
        connector.startPolling((event) => bus.ingest(event)).catch((err) => {
          bus.emit('bus:error', {
            operation: 'connector_start',
            error: err instanceof Error ? err.message : String(err),
          });
        });
      }
    },

    stop(): void {
      for (const connector of connectors) {
        connector.stopPolling();
        connector.disconnect().catch(() => {});
      }
      correlator.stop();
      anomaly.stop();
      aiDetector.stop();
      bus.stop();
    },

    getStats(): DetectionEngineStats {
      const busStats = bus.getStats();
      const aiStats = aiDetector.getStats();
      const corrStats = correlator.getStats();

      return {
        running: busStats.running,
        totalRules: registry.getRuleCount(),
        enabledRules: registry.getEnabledCount(),
        eventsIngested: busStats.eventsIngested,
        confirmedAIAgents: aiStats.confirmedAgents,
        matureBaselines: anomaly.getMatureBaselineCount(),
        connectorCount: connectors.length,
        connectedConnectors: connectors.filter((c) => c.isConnected()).length,
        correlatorPending: corrStats.totalPendingAlerts,
      };
    },
  };
}

function createConnector(
  config: ConnectorConfig,
  credentialProvider: CredentialProvider,
): SIEMConnector | null {
  switch (config.type) {
    case 'wazuh':
      return createWazuhConnector(config, credentialProvider);
    case 'elk':
      return createELKConnector(config, credentialProvider);
    default:
      return null;
  }
}
