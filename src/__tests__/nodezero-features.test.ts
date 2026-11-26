import { describe, it, expect } from 'vitest';
import { RapidResponseEngine } from '../tools/rapid-response.js';
import { TripwireManager } from '../tools/tripwires.js';
import { WebhookDispatcher } from '../config/webhooks.js';

describe('Horizon3.ai NodeZero Ported Features', () => {

  describe('Rapid Response Targeted CVE Engine', () => {
    it('provides a catalog of high-impact N-day and 0-day checks', () => {
      const catalog = RapidResponseEngine.getCatalog();
      expect(catalog.length).toBeGreaterThanOrEqual(6);

      const checkIds = catalog.map(c => c.id);
      expect(checkIds).toContain('git-exposed');
      expect(checkIds).toContain('env-exposed');
      expect(checkIds).toContain('spring-actuator');
      expect(checkIds).toContain('php-cgi-arg-injection');
      expect(checkIds).toContain('citrix-bleed');
      expect(checkIds).toContain('openssh-regresshion');
    });

    it('executes checks safely against non-vulnerable targets without crashing', async () => {
      // Probing localhost non-listening port returns safe not-vulnerable result
      const result = await RapidResponseEngine.runCheck('git-exposed', 'http://127.0.0.1:59999', 500);
      expect(result.checkId).toBe('git-exposed');
      expect(result.vulnerable).toBe(false);
      expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it('performs concurrent multi-target sweeps', async () => {
      const sweep = await RapidResponseEngine.sweep({
        targets: ['http://127.0.0.1:59998', 'http://127.0.0.1:59999'],
        checkIds: ['git-exposed'],
        timeoutMs: 500
      });

      expect(sweep.totalChecks).toBe(2);
      expect(sweep.vulnerableCount).toBe(0);
      expect(sweep.results.length).toBe(2);
    });
  });

  describe('Tripwires & Cyber Deception Engine', () => {
    it('generates deceptive honeytokens with embedded beacon tracking', () => {
      const tripwire = TripwireManager.generateTripwire({
        name: 'Finance Root AWS Key',
        type: 'aws_key',
        baseUrl: 'http://localhost:3333'
      });

      expect(tripwire.id).toMatch(/^tw_/);
      expect(tripwire.name).toBe('Finance Root AWS Key');
      expect(tripwire.type).toBe('aws_key');
      expect(tripwire.canaryPayload.AWS_ACCESS_KEY_ID).toMatch(/^AKIA/);
      expect(tripwire.canaryPayload.beaconUrl).toContain(`/api/tripwires/beacon/${tripwire.token}`);
      expect(tripwire.triggeredCount).toBe(0);
    });

    it('tracks beacon callback trigger events and alerts', () => {
      const tripwire = TripwireManager.generateTripwire({
        name: 'Test Webhook Beacon',
        type: 'webhook_beacon',
        baseUrl: 'http://localhost:3333'
      });

      let alertFired = false;
      TripwireManager.onTrigger((event) => {
        if (event.tripwireId === tripwire.id) {
          alertFired = true;
        }
      });

      const event = TripwireManager.trigger(tripwire.token, {
        ip: '198.51.100.42',
        userAgent: 'curl/8.1.2',
        method: 'GET'
      });

      expect(event).not.toBeNull();
      expect(event?.attackerIp).toBe('198.51.100.42');
      expect(event?.tripwireName).toBe('Test Webhook Beacon');
      expect(tripwire.triggeredCount).toBe(1);
      expect(tripwire.lastTriggeredAt).toBeDefined();
      expect(alertFired).toBe(true);
    });

    it('lists and deletes deployed tripwires', () => {
      const tripwire = TripwireManager.generateTripwire({
        name: 'Temporary Canary',
        type: 'bearer_token'
      });

      const listBefore = TripwireManager.listTripwires();
      expect(listBefore.some(t => t.id === tripwire.id)).toBe(true);

      const deleted = TripwireManager.deleteTripwire(tripwire.id);
      expect(deleted).toBe(true);

      const listAfter = TripwireManager.listTripwires();
      expect(listAfter.some(t => t.id === tripwire.id)).toBe(false);
    });
  });

  describe('Webhook & SIEM Alert Dispatcher', () => {
    it('handles empty webhooks gracefully without errors', async () => {
      const result = await WebhookDispatcher.broadcast({
        event: 'mission_milestone',
        title: 'Mission Test Run',
        details: 'Automated test execution',
        timestamp: new Date().toISOString()
      });

      expect(result).toBeDefined();
      expect(result.errors.length).toBe(0);
    });
  });

});
