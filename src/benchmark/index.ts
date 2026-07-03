/**
 * T3MP3ST Benchmark Framework
 *
 * Measures T3MP3ST's effectiveness against known-vulnerable targets.
 * Compares discovered findings to a ground truth to compute precision,
 * recall, and time-to-finding metrics.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type {
  Task,
  ToolFinding,
  Target,
  Severity,
  KillChainPhase,
} from '../types/index.js';

// =============================================================================
// TYPES
// =============================================================================

/** A known vulnerability in a benchmark target (ground truth) */
export interface GroundTruthVuln {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  /** Keywords that a finding should match to be considered a detection */
  matchKeywords: string[];
  /** Points awarded for finding this */
  points: number;
}

/** A benchmark challenge definition */
export interface BenchmarkChallenge {
  id: string;
  name: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard' | 'expert';
  /** Target definition to scan */
  target: {
    address: string;
    type: Target['type'];
    zone: Target['zone'];
  };
  /** Tasks to execute against the target */
  tasks: Array<{
    name: string;
    description: string;
    phase: KillChainPhase;
    operatorType: string;
    priority: number;
  }>;
  /** Ground truth - known vulnerabilities */
  groundTruth: GroundTruthVuln[];
  /** Time limit in seconds */
  timeLimitSec: number;
}

/** Metrics from a benchmark run */
export interface BenchmarkMetrics {
  /** Fraction of discovered findings that are real (found / (found + false positives)) */
  precision: number;
  /** Fraction of ground truth vulns that were found (found / total ground truth) */
  recall: number;
  /** Harmonic mean of precision and recall */
  f1Score: number;
  /** Total points scored */
  pointsScored: number;
  /** Maximum possible points */
  maxPoints: number;
  /** Percentage score */
  scorePercent: number;
  /** Number of true positives */
  truePositives: number;
  /** Number of false positives */
  falsePositives: number;
  /** Number of missed vulns (false negatives) */
  missedVulns: number;
  /** Seconds until first finding */
  timeToFirstFinding: number | null;
  /** Total duration in seconds */
  totalDurationSec: number;
  /** Findings per minute */
  findingsPerMinute: number;
  /** Severity breakdown */
  severityBreakdown: Record<Severity, { found: number; total: number }>;
}

/** Full result of a benchmark run */
export interface BenchmarkRunResult {
  id: string;
  challengeId: string;
  challengeName: string;
  startedAt: number;
  completedAt: number;
  metrics: BenchmarkMetrics;
  /** Which ground truth vulns were found */
  foundVulns: GroundTruthVuln[];
  /** Which ground truth vulns were missed */
  missedVulns: GroundTruthVuln[];
  /** Findings that didn't match any ground truth */
  falsePositives: ToolFinding[];
  /** All findings from the agent */
  allFindings: ToolFinding[];
  /** Whether the time limit was exceeded */
  timedOut: boolean;
}

export interface BenchmarkSuiteResult {
  id: string;
  name: string;
  startedAt: number;
  completedAt: number;
  runs: BenchmarkRunResult[];
  aggregate: BenchmarkMetrics;
}

export interface BenchmarkEvents {
  'benchmark:started': { challengeId: string };
  'benchmark:finding': { finding: ToolFinding; isMatch: boolean };
  'benchmark:completed': BenchmarkRunResult;
  'suite:started': { name: string; challengeCount: number };
  'suite:completed': BenchmarkSuiteResult;
}

// =============================================================================
// BENCHMARK SCORING
// =============================================================================

/**
 * Match a finding against ground truth vulnerabilities
 */
export function matchFinding(finding: ToolFinding, groundTruth: GroundTruthVuln[]): GroundTruthVuln | null {
  const findingText = `${finding.title} ${finding.details}`.toLowerCase();

  for (const vuln of groundTruth) {
    const matched = vuln.matchKeywords.some(keyword =>
      findingText.includes(keyword.toLowerCase())
    );
    if (matched) return vuln;
  }
  return null;
}

/**
 * Score a set of findings against ground truth
 */
export function scoreBenchmark(
  findings: ToolFinding[],
  groundTruth: GroundTruthVuln[],
  durationSec: number,
  timeToFirstFindingSec: number | null
): BenchmarkMetrics {
  const matchedVulnIds = new Set<string>();
  const falsePositives: ToolFinding[] = [];

  for (const finding of findings) {
    const match = matchFinding(finding, groundTruth);
    if (match) {
      matchedVulnIds.add(match.id);
    } else {
      falsePositives.push(finding);
    }
  }

  const truePositives = matchedVulnIds.size;
  const totalGroundTruth = groundTruth.length;
  const missedVulns = totalGroundTruth - truePositives;

  const precision = findings.length > 0 ? truePositives / findings.length : 0;
  const recall = totalGroundTruth > 0 ? truePositives / totalGroundTruth : 0;
  const f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

  const pointsScored = groundTruth
    .filter(v => matchedVulnIds.has(v.id))
    .reduce((sum, v) => sum + v.points, 0);
  const maxPoints = groundTruth.reduce((sum, v) => sum + v.points, 0);

  // Severity breakdown
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const severityBreakdown = {} as Record<Severity, { found: number; total: number }>;
  for (const sev of severities) {
    const total = groundTruth.filter(v => v.severity === sev).length;
    const found = groundTruth.filter(v => v.severity === sev && matchedVulnIds.has(v.id)).length;
    severityBreakdown[sev] = { found, total };
  }

  return {
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1Score: Math.round(f1Score * 1000) / 1000,
    pointsScored,
    maxPoints,
    scorePercent: maxPoints > 0 ? Math.round((pointsScored / maxPoints) * 1000) / 10 : 0,
    truePositives,
    falsePositives: falsePositives.length,
    missedVulns,
    timeToFirstFinding: timeToFirstFindingSec,
    totalDurationSec: Math.round(durationSec * 10) / 10,
    findingsPerMinute: durationSec > 0 ? Math.round((findings.length / (durationSec / 60)) * 10) / 10 : 0,
    severityBreakdown,
  };
}

/**
 * Aggregate metrics across multiple benchmark runs
 */
export function aggregateMetrics(runs: BenchmarkRunResult[]): BenchmarkMetrics {
  if (runs.length === 0) {
    return scoreBenchmark([], [], 0, null);
  }

  const allFindings = runs.flatMap(r => r.allFindings);
  const allGroundTruth = runs.flatMap(r => [...r.foundVulns, ...r.missedVulns]);
  const totalDuration = runs.reduce((sum, r) => sum + r.metrics.totalDurationSec, 0);
  const firstFindingTimes = runs
    .map(r => r.metrics.timeToFirstFinding)
    .filter((t): t is number => t !== null);
  const avgFirstFinding = firstFindingTimes.length > 0
    ? firstFindingTimes.reduce((a, b) => a + b, 0) / firstFindingTimes.length
    : null;

  return scoreBenchmark(allFindings, allGroundTruth, totalDuration, avgFirstFinding);
}

// =============================================================================
// BUILT-IN BENCHMARK CHALLENGES
// =============================================================================

export const BENCHMARK_CHALLENGES: BenchmarkChallenge[] = [
  {
    id: 'web-basic-recon',
    name: 'Basic Web Reconnaissance',
    description: 'Enumerate subdomains, detect technologies, and analyze security headers on a target web application.',
    difficulty: 'easy',
    target: {
      address: 'http://localhost:8080',
      type: 'web_application',
      zone: 'external',
    },
    tasks: [
      { name: 'Technology Detection', description: 'Detect web technologies and frameworks', phase: 'reconnaissance' as KillChainPhase, operatorType: 'recon', priority: 10 },
      { name: 'Security Header Analysis', description: 'Analyze HTTP security headers', phase: 'reconnaissance' as KillChainPhase, operatorType: 'recon', priority: 9 },
      { name: 'Directory Enumeration', description: 'Discover hidden directories and files', phase: 'reconnaissance' as KillChainPhase, operatorType: 'recon', priority: 8 },
    ],
    groundTruth: [
      { id: 'missing-hsts', title: 'Missing HSTS Header', severity: 'medium', category: 'headers', matchKeywords: ['strict-transport', 'hsts', 'missing'], points: 10 },
      { id: 'missing-csp', title: 'Missing CSP Header', severity: 'medium', category: 'headers', matchKeywords: ['content-security-policy', 'csp', 'missing'], points: 10 },
      { id: 'server-info', title: 'Server Version Disclosure', severity: 'low', category: 'info', matchKeywords: ['server', 'version', 'disclosure', 'detected'], points: 5 },
      { id: 'dirs-found', title: 'Sensitive Directories Found', severity: 'info', category: 'recon', matchKeywords: ['directories', 'paths', 'discovered'], points: 5 },
    ],
    timeLimitSec: 120,
  },
  {
    id: 'web-sqli',
    name: 'SQL Injection Detection',
    description: 'Identify SQL injection vulnerabilities in a web application with various injection points.',
    difficulty: 'medium',
    target: {
      address: 'http://localhost:8081',
      type: 'web_application',
      zone: 'external',
    },
    tasks: [
      { name: 'SQLi Parameter Scan', description: 'Test URL parameters for SQL injection', phase: 'exploitation' as KillChainPhase, operatorType: 'scanner', priority: 10 },
      { name: 'Error-based SQLi', description: 'Test for error-based SQL injection', phase: 'exploitation' as KillChainPhase, operatorType: 'exploiter', priority: 9 },
    ],
    groundTruth: [
      { id: 'sqli-id-param', title: 'SQL Injection in ID parameter', severity: 'critical', category: 'sqli', matchKeywords: ['sql injection', 'sqli', 'sql error'], points: 25 },
      { id: 'sqli-search', title: 'SQL Injection in search', severity: 'high', category: 'sqli', matchKeywords: ['sql injection', 'search', 'query'], points: 20 },
    ],
    timeLimitSec: 180,
  },
  {
    id: 'web-xss',
    name: 'Cross-Site Scripting Detection',
    description: 'Identify reflected and stored XSS vulnerabilities.',
    difficulty: 'medium',
    target: {
      address: 'http://localhost:8082',
      type: 'web_application',
      zone: 'external',
    },
    tasks: [
      { name: 'Reflected XSS Scan', description: 'Test input fields for reflected XSS', phase: 'exploitation' as KillChainPhase, operatorType: 'scanner', priority: 10 },
    ],
    groundTruth: [
      { id: 'rxss-name', title: 'Reflected XSS in name parameter', severity: 'high', category: 'xss', matchKeywords: ['xss', 'reflected', 'cross-site scripting'], points: 20 },
      { id: 'rxss-search', title: 'Reflected XSS in search', severity: 'high', category: 'xss', matchKeywords: ['xss', 'reflected', 'payload'], points: 20 },
    ],
    timeLimitSec: 120,
  },
  {
    id: 'network-recon',
    name: 'Network Service Discovery',
    description: 'Discover and fingerprint network services on a target host.',
    difficulty: 'easy',
    target: {
      address: '127.0.0.1',
      type: 'host',
      zone: 'external',
    },
    tasks: [
      { name: 'Port Scan', description: 'Scan for open ports and services', phase: 'reconnaissance' as KillChainPhase, operatorType: 'recon', priority: 10 },
      { name: 'SSL/TLS Analysis', description: 'Analyze SSL/TLS configuration', phase: 'reconnaissance' as KillChainPhase, operatorType: 'scanner', priority: 8 },
    ],
    groundTruth: [
      { id: 'open-ports', title: 'Open Ports Identified', severity: 'info', category: 'recon', matchKeywords: ['open port', 'open ports', 'port'], points: 10 },
      { id: 'ssl-issues', title: 'SSL/TLS Configuration Issues', severity: 'medium', category: 'ssl', matchKeywords: ['ssl', 'tls', 'certificate', 'cipher'], points: 15 },
    ],
    timeLimitSec: 90,
  },
  {
    id: 'full-pentest',
    name: 'Full Web Application Assessment',
    description: 'Complete assessment: recon, scanning, and exploitation of a vulnerable web application.',
    difficulty: 'hard',
    target: {
      address: 'http://localhost:8080',
      type: 'web_application',
      zone: 'external',
    },
    tasks: [
      { name: 'Reconnaissance', description: 'Full target reconnaissance', phase: 'reconnaissance' as KillChainPhase, operatorType: 'recon', priority: 10 },
      { name: 'Vulnerability Scanning', description: 'Comprehensive vulnerability scan', phase: 'reconnaissance' as KillChainPhase, operatorType: 'scanner', priority: 9 },
      { name: 'Exploitation', description: 'Exploit discovered vulnerabilities', phase: 'exploitation' as KillChainPhase, operatorType: 'exploiter', priority: 8 },
      { name: 'Credential Testing', description: 'Test for weak credentials', phase: 'exploitation' as KillChainPhase, operatorType: 'exploiter', priority: 7 },
    ],
    groundTruth: [
      { id: 'tech-detect', title: 'Technology Stack Identified', severity: 'info', category: 'recon', matchKeywords: ['technolog', 'detected', 'framework'], points: 5 },
      { id: 'missing-headers', title: 'Missing Security Headers', severity: 'medium', category: 'headers', matchKeywords: ['header', 'missing', 'security'], points: 10 },
      { id: 'sensitive-dirs', title: 'Sensitive Directories Exposed', severity: 'high', category: 'recon', matchKeywords: ['.git', '.env', 'backup', 'sensitive'], points: 20 },
      { id: 'sqli-vuln', title: 'SQL Injection', severity: 'critical', category: 'sqli', matchKeywords: ['sql injection', 'sqli'], points: 25 },
      { id: 'xss-vuln', title: 'Cross-Site Scripting', severity: 'high', category: 'xss', matchKeywords: ['xss', 'cross-site'], points: 20 },
      { id: 'weak-creds', title: 'Weak Credentials', severity: 'critical', category: 'auth', matchKeywords: ['weak password', 'credential', 'default password'], points: 25 },
      { id: 'ssl-misconfig', title: 'SSL Misconfiguration', severity: 'medium', category: 'ssl', matchKeywords: ['ssl', 'tls', 'certificate'], points: 10 },
    ],
    timeLimitSec: 600,
  },
];

// =============================================================================
// BENCHMARK RUNNER
// =============================================================================

export class Benchmark extends EventEmitter<BenchmarkEvents> {
  private challenges: Map<string, BenchmarkChallenge> = new Map();

  constructor() {
    super();
    // Load built-in challenges
    for (const challenge of BENCHMARK_CHALLENGES) {
      this.challenges.set(challenge.id, challenge);
    }
  }

  /**
   * Register a custom challenge
   */
  addChallenge(challenge: BenchmarkChallenge): void {
    this.challenges.set(challenge.id, challenge);
  }

  /**
   * Get a challenge by ID
   */
  getChallenge(id: string): BenchmarkChallenge | undefined {
    return this.challenges.get(id);
  }

  /**
   * List all available challenges
   */
  listChallenges(): BenchmarkChallenge[] {
    return Array.from(this.challenges.values());
  }

  /**
   * Score findings from an external agent run against a challenge's ground truth
   */
  scoreRun(
    challengeId: string,
    findings: ToolFinding[],
    durationSec: number,
    timeToFirstFindingSec: number | null = null
  ): BenchmarkRunResult {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new Error(`Challenge "${challengeId}" not found`);

    const startedAt = Date.now() - (durationSec * 1000);
    const foundVulns: GroundTruthVuln[] = [];
    const matchedIds = new Set<string>();
    const falsePositives: ToolFinding[] = [];

    for (const finding of findings) {
      const match = matchFinding(finding, challenge.groundTruth);
      if (match && !matchedIds.has(match.id)) {
        matchedIds.add(match.id);
        foundVulns.push(match);
        this.emit('benchmark:finding', { finding, isMatch: true });
      } else if (!match) {
        falsePositives.push(finding);
        this.emit('benchmark:finding', { finding, isMatch: false });
      }
    }

    const missedVulnsList = challenge.groundTruth.filter(v => !matchedIds.has(v.id));
    const metrics = scoreBenchmark(findings, challenge.groundTruth, durationSec, timeToFirstFindingSec);

    const result: BenchmarkRunResult = {
      id: randomUUID(),
      challengeId,
      challengeName: challenge.name,
      startedAt,
      completedAt: Date.now(),
      metrics,
      foundVulns,
      missedVulns: missedVulnsList,
      falsePositives,
      allFindings: findings,
      timedOut: durationSec >= challenge.timeLimitSec,
    };

    this.emit('benchmark:completed', result);
    return result;
  }

  /**
   * Generate a human-readable report from benchmark results
   */
  formatReport(result: BenchmarkRunResult): string {
    const m = result.metrics;
    const lines: string[] = [];

    lines.push(`${'='.repeat(60)}`);
    lines.push(`BENCHMARK REPORT: ${result.challengeName}`);
    lines.push(`${'='.repeat(60)}`);
    lines.push('');
    lines.push(`Score: ${m.pointsScored}/${m.maxPoints} (${m.scorePercent}%)`);
    lines.push(`F1 Score: ${m.f1Score} (precision: ${m.precision}, recall: ${m.recall})`);
    lines.push('');
    lines.push(`Duration: ${m.totalDurationSec}s ${result.timedOut ? '(TIMED OUT)' : ''}`);
    lines.push(`Time to first finding: ${m.timeToFirstFinding !== null ? `${m.timeToFirstFinding}s` : 'N/A'}`);
    lines.push(`Findings per minute: ${m.findingsPerMinute}`);
    lines.push('');
    lines.push(`True positives: ${m.truePositives}`);
    lines.push(`False positives: ${m.falsePositives}`);
    lines.push(`Missed vulnerabilities: ${m.missedVulns}`);
    lines.push('');
    lines.push('Severity Breakdown:');
    for (const [sev, stats] of Object.entries(m.severityBreakdown)) {
      if (stats.total > 0) {
        lines.push(`  ${sev.toUpperCase().padEnd(10)} ${stats.found}/${stats.total}`);
      }
    }

    if (result.foundVulns.length > 0) {
      lines.push('');
      lines.push('Found Vulnerabilities:');
      for (const v of result.foundVulns) {
        lines.push(`  [${v.severity.toUpperCase()}] ${v.title} (+${v.points} pts)`);
      }
    }

    if (result.missedVulns.length > 0) {
      lines.push('');
      lines.push('Missed Vulnerabilities:');
      for (const v of result.missedVulns) {
        lines.push(`  [${v.severity.toUpperCase()}] ${v.title} (${v.points} pts)`);
      }
    }

    lines.push('');
    lines.push(`${'='.repeat(60)}`);

    return lines.join('\n');
  }

  /**
   * Format a suite report
   */
  formatSuiteReport(suiteResult: BenchmarkSuiteResult): string {
    const lines: string[] = [];
    lines.push(`${'='.repeat(60)}`);
    lines.push(`BENCHMARK SUITE: ${suiteResult.name}`);
    lines.push(`${'='.repeat(60)}`);
    lines.push('');

    for (const run of suiteResult.runs) {
      const m = run.metrics;
      lines.push(`${run.challengeName.padEnd(40)} ${m.scorePercent}% (${m.pointsScored}/${m.maxPoints}) F1=${m.f1Score}`);
    }

    lines.push('');
    const a = suiteResult.aggregate;
    lines.push(`AGGREGATE: ${a.scorePercent}% score, F1=${a.f1Score}, precision=${a.precision}, recall=${a.recall}`);
    lines.push(`Total: ${a.truePositives} found, ${a.falsePositives} false+, ${a.missedVulns} missed`);
    lines.push(`${'='.repeat(60)}`);

    return lines.join('\n');
  }

  /**
   * Convert a challenge to Task objects for the mission system
   */
  challengeToTasks(challenge: BenchmarkChallenge, missionId: string): Task[] {
    return challenge.tasks.map((t, i) => ({
      id: `bench-${challenge.id}-${i}`,
      missionId,
      name: t.name,
      description: t.description,
      phase: t.phase,
      operatorType: t.operatorType as Task['operatorType'],
      status: 'pending' as const,
      priority: t.priority,
      dependencies: [],
      createdAt: Date.now(),
    }));
  }
}

/**
 * Create a benchmark instance with all built-in challenges loaded
 */
export function createBenchmark(): Benchmark {
  return new Benchmark();
}
