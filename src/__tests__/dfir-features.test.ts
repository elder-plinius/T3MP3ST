import { describe, it, expect, beforeEach } from 'vitest';
import { DFIRManager } from '../tools/dfir.js';

describe('DFIR (Digital Forensics & Incident Response) Engine', () => {
  beforeEach(() => {
    DFIRManager.init();
  });

  it('initializes default incident cases and provides metrics', () => {
    const list = DFIRManager.listIncidents();
    expect(list.length).toBeGreaterThanOrEqual(2);

    const metrics = DFIRManager.getMetrics();
    expect(metrics.totalIncidents).toBeGreaterThanOrEqual(2);
    expect(metrics.totalIOCs).toBeGreaterThanOrEqual(4);
    expect(typeof metrics.averageResolutionHours).toBe('number');
  });

  it('creates and updates a new incident case', () => {
    const created = DFIRManager.createIncident({
      title: 'Active Ransomware Staging on Database Node',
      severity: 'CRITICAL',
      targetHost: '10.0.8.99',
      environment: 'DB Cluster',
      attackVector: 'SQLi -> UDF Binary Injection'
    });

    expect(created.id).toMatch(/^INC-/);
    expect(created.status).toBe('TRIAGE');
    expect(created.severity).toBe('CRITICAL');
    expect(created.containment.isolated).toBe(false);

    const fetched = DFIRManager.getIncident(created.id);
    expect(fetched).toBeDefined();
    expect(fetched?.title).toBe('Active Ransomware Staging on Database Node');

    const updated = DFIRManager.updateIncident(created.id, {
      status: 'CONTAINED',
      forensicNotes: 'Target isolated, memory dump captured.'
    });

    expect(updated?.status).toBe('CONTAINED');
    expect(updated?.containedAt).toBeDefined();
  });

  it('toggles host containment and network isolation with firewall rules', () => {
    const incident = DFIRManager.createIncident({
      title: 'Hostile C2 Beaconing Detected',
      targetHost: '192.168.1.50'
    });

    const contained = DFIRManager.setContainment(incident.id, true, { blockFirewall: true, killProcs: true });
    expect(contained).toBeDefined();
    expect(contained?.containment.isolated).toBe(true);
    expect(contained?.containment.firewallRulesActive).toBe(true);
    expect(contained?.containment.processesKilledCount).toBeGreaterThanOrEqual(2);
    expect(contained?.status).toBe('CONTAINED');

    // Verify containment event in timeline
    const timeline = contained?.timeline || [];
    expect(timeline.some(t => t.phase === 'Containment')).toBe(true);

    // Release isolation
    const released = DFIRManager.setContainment(incident.id, false);
    expect(released?.containment.isolated).toBe(false);
    expect(released?.containment.firewallRulesActive).toBe(false);
  });

  it('extracts IOCs (IPs, hashes, domains, files) from raw forensic logs', () => {
    const rawSample = `
      [2026-08-31 09:12:44] 198.51.100.99 - - "POST /api/v1/upload HTTP/1.1" 200 4096
      Dropped backdoor payload to /var/www/html/uploads/b374k.php with hash 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
      Attacker domain beacon detected: evil-c2-node.darkops-relay.net communicating on port 4444
    `;

    const extracted = DFIRManager.extractIOCs(rawSample);
    expect(extracted.length).toBeGreaterThanOrEqual(3);

    const ips = extracted.filter(i => i.type === 'ip');
    const hashes = extracted.filter(i => i.type === 'hash');
    const domains = extracted.filter(i => i.type === 'domain');
    const files = extracted.filter(i => i.type === 'file');

    expect(ips.some(i => i.value === '198.51.100.99')).toBe(true);
    expect(hashes.some(i => i.value === '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')).toBe(true);
    expect(domains.some(i => i.value === 'evil-c2-node.darkops-relay.net')).toBe(true);
    expect(files.some(i => i.value.includes('/var/www/html/uploads/b374k.php'))).toBe(true);
  });

  it('runs post-attack eradication playbooks and records verifiable receipts', async () => {
    const incident = DFIRManager.createIncident({
      title: 'Webshell Backdoor Remediation Test',
      targetHost: '192.168.1.100'
    });

    const res = await DFIRManager.runPlaybook(incident.id, 'webshell-eradicate');
    expect(res.success).toBe(true);
    expect(res.output).toContain('[SUCCESS] Webshell eradicated');

    const updatedTask = res.tasksUpdated.find(t => t.playbookType === 'webshell-eradicate');
    expect(updatedTask?.status).toBe('verified');
    expect(updatedTask?.output).toBeDefined();

    // Run custom script playbook
    const customRes = await DFIRManager.runPlaybook(incident.id, 'custom-script', {
      customScript: 'iptables -A INPUT -p tcp --dport 8080 -j DROP'
    });
    expect(customRes.success).toBe(true);
    expect(customRes.output).toContain('Custom script executed with exit code 0');
  });

  it('generates a full NIST SP 800-61 / ISO 27035 Post-Mortem Report', () => {
    const list = DFIRManager.listIncidents();
    const targetInc = list[0];

    const report = DFIRManager.generatePostMortemReport(targetInc.id);
    expect(report).toBeDefined();
    expect(report?.markdown).toContain('NIST SP 800-61 Rev 2 — Post-Incident Resolution & Forensics Report');
    expect(report?.markdown).toContain('Root Cause Analysis');
    expect(report?.markdown).toContain('Chronological Forensics Timeline');
    expect(report?.markdown).toContain('Eradication & Remediation Verification Log');
    expect(report?.json.id).toBe(targetInc.id);
  });
});
