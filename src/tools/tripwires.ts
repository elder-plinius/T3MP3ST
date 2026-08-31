/**
 * Tripwires & Cyber Deception Engine (Honeytokens & Canary Traps)
 * Inspired by Horizon3.ai NodeZero Tripwires
 * Automatically provisions canary tokens, decoy credentials, and beacon traps to detect active attacker intrusion.
 */

import crypto from 'crypto';

export type TripwireType = 'aws_key' | 'webhook_beacon' | 'db_credential' | 'bearer_token' | 'ad_service_account';

export interface TripwireTriggerEvent {
  id: string;
  tripwireId: string;
  tripwireName: string;
  tripwireType: TripwireType;
  attackerIp: string;
  userAgent?: string;
  method?: string;
  path?: string;
  query?: Record<string, any>;
  headers?: Record<string, string>;
  bodySnippet?: string;
  timestamp: string;
}

export interface Tripwire {
  id: string;
  name: string;
  type: TripwireType;
  description: string;
  token: string;
  canaryPayload: Record<string, any>;
  targetEnvironment?: string;
  createdAt: string;
  triggeredCount: number;
  lastTriggeredAt?: string;
  triggers: TripwireTriggerEvent[];
}

export class TripwireManager {
  private static tripwires: Map<string, Tripwire> = new Map();
  private static triggerListeners: Array<(event: TripwireTriggerEvent) => void> = [];

  /**
   * Generates a new honeytoken / canary tripwire
   */
  public static generateTripwire(options: {
    name: string;
    type: TripwireType;
    description?: string;
    targetEnvironment?: string;
    baseUrl?: string;
  }): Tripwire {
    const id = `tw_${crypto.randomBytes(6).toString('hex')}`;
    const token = crypto.randomBytes(16).toString('hex');
    const baseUrl = (options.baseUrl || 'http://localhost:3333').replace(/\/+$/, '');
    const createdAt = new Date().toISOString();

    let canaryPayload: Record<string, any> = {};

    switch (options.type) {
      case 'aws_key': {
        const keyId = `AKIA${token.substring(0, 16).toUpperCase()}`;
        const secret = crypto.randomBytes(20).toString('base64');
        canaryPayload = {
          AWS_ACCESS_KEY_ID: keyId,
          AWS_SECRET_ACCESS_KEY: secret,
          AWS_DEFAULT_REGION: 'us-east-1',
          beaconUrl: `${baseUrl}/api/tripwires/beacon/${token}`
        };
        break;
      }
      case 'webhook_beacon': {
        canaryPayload = {
          beaconUrl: `${baseUrl}/api/tripwires/beacon/${token}`,
          curlCommand: `curl -s -X GET "${baseUrl}/api/tripwires/beacon/${token}"`,
          imageTag: `<img src="${baseUrl}/api/tripwires/beacon/${token}" width="1" height="1" style="display:none;" />`
        };
        break;
      }
      case 'db_credential': {
        canaryPayload = {
          databaseUrl: `postgresql://db_master_backup:${token}@internal-vault.corp.local:5432/finance_db`,
          username: 'db_master_backup',
          password: `P@ss_${token.substring(0, 8)}!`,
          beaconUrl: `${baseUrl}/api/tripwires/beacon/${token}`
        };
        break;
      }
      case 'bearer_token': {
        const apiKey = `t3mp_live_${token}`;
        canaryPayload = {
          authorization: `Bearer ${apiKey}`,
          apiKey,
          beaconUrl: `${baseUrl}/api/tripwires/beacon/${token}`
        };
        break;
      }
      case 'ad_service_account': {
        canaryPayload = {
          sAMAccountName: `svc_backup_${token.substring(0, 6)}`,
          userPrincipalName: `svc_backup_${token.substring(0, 6)}@corp.local`,
          servicePrincipalName: `MSSQLSvc/db-cluster.corp.local:1433`,
          spnPassword: `Winter2026_${token.substring(0, 6)}!`,
          beaconUrl: `${baseUrl}/api/tripwires/beacon/${token}`
        };
        break;
      }
    }

    const tripwire: Tripwire = {
      id,
      name: options.name,
      type: options.type,
      description: options.description || `Autonomous Canary Trap (${options.type})`,
      token,
      canaryPayload,
      targetEnvironment: options.targetEnvironment || 'default',
      createdAt,
      triggeredCount: 0,
      triggers: []
    };

    TripwireManager.tripwires.set(token, tripwire);
    return tripwire;
  }

  /**
   * Process a beacon callback trigger
   */
  public static trigger(token: string, metadata: {
    ip: string;
    userAgent?: string;
    method?: string;
    path?: string;
    query?: Record<string, any>;
    headers?: Record<string, string>;
    body?: any;
  }): TripwireTriggerEvent | null {
    const tripwire = TripwireManager.tripwires.get(token);
    if (!tripwire) {
      return null;
    }

    const triggerEvent: TripwireTriggerEvent = {
      id: `trig_${crypto.randomBytes(6).toString('hex')}`,
      tripwireId: tripwire.id,
      tripwireName: tripwire.name,
      tripwireType: tripwire.type,
      attackerIp: metadata.ip || 'unknown',
      userAgent: metadata.userAgent,
      method: metadata.method || 'GET',
      path: metadata.path || `/api/tripwires/beacon/${token}`,
      query: metadata.query,
      headers: metadata.headers,
      bodySnippet: metadata.body ? (typeof metadata.body === 'string' ? metadata.body.slice(0, 300) : JSON.stringify(metadata.body).slice(0, 300)) : undefined,
      timestamp: new Date().toISOString()
    };

    tripwire.triggeredCount++;
    tripwire.lastTriggeredAt = triggerEvent.timestamp;
    tripwire.triggers.unshift(triggerEvent);

    // Notify listeners
    for (const listener of TripwireManager.triggerListeners) {
      try {
        listener(triggerEvent);
      } catch (err) {
        console.error('[Tripwires] Error notifying listener:', err);
      }
    }

    return triggerEvent;
  }

  /**
   * Subscribe to live trigger alerts
   */
  public static onTrigger(listener: (event: TripwireTriggerEvent) => void) {
    TripwireManager.triggerListeners.push(listener);
  }

  /**
   * Get all active tripwires
   */
  public static listTripwires(): Tripwire[] {
    return Array.from(TripwireManager.tripwires.values());
  }

  /**
   * Get tripwire by ID or token
   */
  public static getTripwire(idOrToken: string): Tripwire | undefined {
    if (TripwireManager.tripwires.has(idOrToken)) {
      return TripwireManager.tripwires.get(idOrToken);
    }
    for (const tw of TripwireManager.tripwires.values()) {
      if (tw.id === idOrToken) return tw;
    }
    return undefined;
  }

  /**
   * Delete a tripwire
   */
  public static deleteTripwire(id: string): boolean {
    for (const [token, tw] of TripwireManager.tripwires.entries()) {
      if (tw.id === id) {
        TripwireManager.tripwires.delete(token);
        return true;
      }
    }
    return false;
  }
}
