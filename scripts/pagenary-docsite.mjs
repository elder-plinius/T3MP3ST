#!/usr/bin/env node
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const ROOT = process.cwd();
const TENANT_ID = 't3mp3st-docs';
const TENANT_DIR = join(ROOT, 'docsite', TENANT_ID);
const CONTENT_DIR = join(TENANT_DIR, 'content');
const DEFAULT_SITE_URL = 'https://elder-plinius.github.io/T3MP3ST/t3mp3st-docs';

const pages = [
  {
    source: 'docs/README.md',
    output: 'README.md',
    id: 'welcome',
    title: 'T3MP3ST Documentation',
    summary: 'Documentation map for operators, developers, benchmarks, and release work.',
    category: 'overview',
    audience: ['operator', 'developer'],
  },
  {
    source: 'docs/GETTING_STARTED.md',
    output: 'GETTING_STARTED.md',
    id: 'getting-started',
    title: 'Getting Started',
    summary: 'Install, configure, launch, and run the first safe T3MP3ST workflow.',
    category: 'operator',
    audience: ['operator'],
  },
  {
    source: 'docs/SCOPE_AND_AUTHORIZATION.md',
    output: 'SCOPE_AND_AUTHORIZATION.md',
    id: 'scope-and-authorization',
    title: 'Scope and Authorization',
    summary: 'Rules of engagement, authorization receipts, evidence, and retest boundaries.',
    category: 'operator',
    audience: ['operator', 'security-reviewer'],
  },
  {
    source: 'docs/TARGET_HEADERS.md',
    output: 'TARGET_HEADERS.md',
    id: 'target-headers',
    title: 'Target Headers',
    summary: 'How to inject target-scoped authentication headers safely.',
    category: 'operator',
    audience: ['operator', 'developer'],
  },
  {
    source: 'docs/AUTHENTICATED_WORKFLOWS.md',
    output: 'AUTHENTICATED_WORKFLOWS.md',
    id: 'authenticated-workflows',
    title: 'Authenticated Workflow Boundaries',
    summary: 'Current authenticated-request support and the design boundary for future interactive workflows.',
    category: 'operator',
    audience: ['operator', 'developer', 'security-reviewer'],
  },
  {
    source: 'docs/ARSENAL_ACTIVATION_PLAN.md',
    output: 'ARSENAL_ACTIVATION_PLAN.md',
    id: 'arsenal-activation-plan',
    title: 'Arsenal Activation Plan',
    summary: 'Install optional external tools and understand adapter readiness.',
    category: 'operator',
    audience: ['operator'],
  },
  {
    source: 'docs/TEAM_PREVIEW.md',
    output: 'TEAM_PREVIEW.md',
    id: 'team-preview',
    title: 'Team Preview',
    summary: 'Ten-minute preview path for evaluating the War Room and local-safe flows.',
    category: 'operator',
    audience: ['operator', 'maintainer'],
  },
  {
    source: 'docs/DEVELOPER_GUIDE.md',
    output: 'DEVELOPER_GUIDE.md',
    id: 'developer-guide',
    title: 'Developer Guide',
    summary: 'Architecture, local development, scripts, extension points, and release checks.',
    category: 'developer',
    audience: ['developer', 'maintainer'],
  },
  {
    source: 'docs/API_REFERENCE.md',
    output: 'API_REFERENCE.md',
    id: 'api-reference',
    title: 'API Reference',
    summary: 'Local HTTP API endpoints grouped by workflow.',
    category: 'developer',
    audience: ['developer', 'integrator'],
  },
  {
    source: 'docs/MCP_GUIDE.md',
    output: 'MCP_GUIDE.md',
    id: 'mcp-guide',
    title: 'MCP Guide',
    summary: 'Model Context Protocol setup and security_recon usage.',
    category: 'developer',
    audience: ['developer', 'integrator'],
  },
  {
    source: 'docs/CONTRIBUTION_RECEIPTS.md',
    output: 'CONTRIBUTION_RECEIPTS.md',
    id: 'contribution-receipts',
    title: 'Contribution Receipts',
    summary: 'Evidence template for scoped pull requests and claim changes.',
    category: 'developer',
    audience: ['contributor', 'maintainer'],
  },
  {
    source: 'docs/PULL_REQUEST_DELIVERY.md',
    output: 'PULL_REQUEST_DELIVERY.md',
    id: 'pull-request-delivery',
    title: 'Pull Request Delivery',
    summary: 'Contributor and maintainer checklist for reviewable pull requests.',
    category: 'developer',
    audience: ['contributor', 'maintainer'],
  },
  {
    source: 'docs/VERIFIED_PROVENANCE.md',
    output: 'VERIFIED_PROVENANCE.md',
    id: 'verified-provenance',
    title: 'Verified Provenance',
    summary: 'How findings become tool-proven instead of model-asserted.',
    category: 'benchmarks',
    audience: ['developer', 'researcher'],
  },
  {
    source: 'docs/XBOW_BASELINE.md',
    output: 'XBOW_BASELINE.md',
    id: 'xbow-baseline',
    title: 'XBOW Baseline',
    summary: 'XBEN benchmark baseline and validation notes.',
    category: 'benchmarks',
    audience: ['researcher', 'maintainer'],
  },
  {
    source: 'docs/CYBENCH.md',
    output: 'CYBENCH.md',
    id: 'cybench',
    title: 'Cybench',
    summary: 'Cybench benchmark methodology and results notes.',
    category: 'benchmarks',
    audience: ['researcher', 'maintainer'],
  },
  {
    source: 'docs/WALL_FORENSICS.md',
    output: 'WALL_FORENSICS.md',
    id: 'wall-forensics',
    title: 'Wall Forensics',
    summary: 'Per-challenge misses and benchmark analysis.',
    category: 'benchmarks',
    audience: ['researcher', 'maintainer'],
  },
  {
    source: 'docs/INTEGRITY_LEDGER.md',
    output: 'INTEGRITY_LEDGER.md',
    id: 'integrity-ledger',
    title: 'Integrity Ledger',
    summary: 'Contamination audit and retractions.',
    category: 'benchmarks',
    audience: ['researcher', 'maintainer'],
  },
  {
    source: 'docs/OBSIDIVM.md',
    output: 'OBSIDIVM.md',
    id: 'obsidivm',
    title: 'Obsidivm',
    summary: 'Local web range and evaluation notes.',
    category: 'benchmarks',
    audience: ['researcher', 'operator'],
  },
  {
    source: 'docs/COGNITIVE_ARCHITECTURE.md',
    output: 'COGNITIVE_ARCHITECTURE.md',
    id: 'cognitive-architecture',
    title: 'Cognitive Architecture',
    summary: 'Prompt and reasoning architecture boundaries.',
    category: 'benchmarks',
    audience: ['researcher', 'developer'],
  },
  {
    source: 'docs/AI_REDTEAM_TECHNIQUES.md',
    output: 'AI_REDTEAM_TECHNIQUES.md',
    id: 'ai-redteam-techniques',
    title: 'AI Red-Team Techniques',
    summary: 'Defensive taxonomy and technique map.',
    category: 'benchmarks',
    audience: ['researcher', 'operator'],
  },
  {
    source: 'docs/INSTALL_MATRIX.md',
    output: 'INSTALL_MATRIX.md',
    id: 'install-matrix',
    title: 'Install Matrix',
    summary: 'Operating-system readiness notes.',
    category: 'release',
    audience: ['operator', 'maintainer'],
  },
  {
    source: 'docs/RELEASE_CHECKLIST.md',
    output: 'RELEASE_CHECKLIST.md',
    id: 'release-checklist',
    title: 'Release Checklist',
    summary: 'Release gates and verification steps.',
    category: 'release',
    audience: ['maintainer'],
  },
  {
    source: 'docs/CHANGELOG.md',
    output: 'CHANGELOG.md',
    id: 'changelog',
    title: 'Changelog',
    summary: 'Project change history.',
    category: 'release',
    audience: ['operator', 'developer', 'maintainer'],
  },
];

const groups = [
  {
    id: 'operators',
    title: 'Operators',
    summary: 'Install, configure, scope, and review T3MP3ST safely.',
    ids: ['getting-started', 'scope-and-authorization', 'target-headers', 'arsenal-activation-plan', 'team-preview'],
  },
  {
    id: 'developers',
    title: 'Developers',
    summary: 'Integrate, extend, and contribute to T3MP3ST.',
    ids: ['developer-guide', 'api-reference', 'mcp-guide', 'contribution-receipts', 'pull-request-delivery'],
  },
  {
    id: 'benchmarks',
    title: 'Benchmarks And Provenance',
    summary: 'Benchmark methodology, provenance, and research architecture.',
    ids: [
      'verified-provenance',
      'xbow-baseline',
      'cybench',
      'wall-forensics',
      'integrity-ledger',
      'obsidivm',
      'cognitive-architecture',
      'ai-redteam-techniques',
    ],
  },
  {
    id: 'release',
    title: 'Release And Maintenance',
    summary: 'Install readiness, release gates, and project history.',
    ids: ['install-matrix', 'release-checklist', 'changelog'],
  },
];

const pageById = new Map(pages.map((page) => [page.id, page]));
const idByBasename = new Map(pages.map((page) => [page.output.toLowerCase(), page.id]));

function yamlScalar(value) {
  return JSON.stringify(String(value));
}

function yamlList(values) {
  return `[${values.map((value) => yamlScalar(value)).join(', ')}]`;
}

function stripExistingFrontmatter(markdown) {
  return markdown.replace(/^\uFEFF?---\r?\n[\s\S]*?\r?\n---\r?\n?/, '');
}

function normalizeMarkdown(markdown) {
  return stripExistingFrontmatter(markdown).replace(/\r\n/g, '\n').replace(/\s+$/g, '') + '\n';
}

function rewriteInternalLinks(markdown) {
  return markdown.replace(/\]\(([^)]+\.md)(#[^)]+)?\)/gi, (match, rawTarget, rawAnchor = '') => {
    const normalizedTarget = String(rawTarget).replace(/\\/g, '/');
    const basename = normalizedTarget.split('/').pop().toLowerCase();
    const id = idByBasename.get(basename);
    if (!id) return match;
    const anchor = rawAnchor ? rawAnchor.replace(/^#/, '-') : '';
    return `](#${id}${anchor})`;
  });
}

function frontmatterFor(page) {
  return [
    '---',
    `title: ${yamlScalar(page.title)}`,
    `summary: ${yamlScalar(page.summary)}`,
    `description: ${yamlScalar(page.summary)}`,
    `audience: ${yamlList(page.audience)}`,
    `category: ${yamlScalar(page.category)}`,
    'status: "current"',
    'source: "T3MP3ST repository"',
    `sourcePath: ${yamlScalar(page.source)}`,
    'updated: "2026-07-20"',
    '---',
    '',
  ].join('\n');
}

function sectionFor(page) {
  return {
    id: page.id,
    title: page.title,
    summary: page.summary,
    file: page.output,
  };
}

function groupContent(group) {
  const lines = [
    `# ${group.title}`,
    '',
    group.summary,
    '',
    '## Pages',
    '',
  ];

  for (const id of group.ids) {
    const page = pageById.get(id);
    lines.push(`- [${page.title}](#${page.id}) - ${page.summary}`);
  }

  return `${lines.join('\n')}\n`;
}

async function writeJson(filePath, value) {
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function main() {
  await rm(TENANT_DIR, { recursive: true, force: true });
  await mkdir(CONTENT_DIR, { recursive: true });

  for (const page of pages) {
    const sourcePath = join(ROOT, page.source);
    const outputPath = join(CONTENT_DIR, page.output);
    const markdown = rewriteInternalLinks(normalizeMarkdown(await readFile(sourcePath, 'utf8')));
    await writeFile(outputPath, `${frontmatterFor(page)}${markdown}`, 'utf8');
  }

  for (const group of groups) {
    const outputPath = join(CONTENT_DIR, `${group.id}.md`);
    const page = {
      source: `generated:${group.id}`,
      title: group.title,
      summary: group.summary,
      audience: ['operator', 'developer', 'maintainer'],
      category: 'navigation',
    };
    await writeFile(outputPath, `${frontmatterFor(page)}${groupContent(group)}`, 'utf8');
  }

  const config = {
    title: 'T3MP3ST Documentation',
    description: 'Operator and developer documentation for T3MP3ST, the local offensive-security command center for authorized testing.',
    brandMark: 'T3MP3ST',
    brandSub: 'Docs',
    tagline: 'Authorized testing, evidence-first workflows, and developer integration.',
    copyright: 'T3MP3ST contributors',
    language: 'en-US',
    layout: 'docs',
    navPosition: 'left',
    navCollapse: 'overlay',
    pageToc: { placement: 'rail', minHeadings: 2 },
    codeCopy: true,
    readingProgress: true,
    accentColor: '#00d4ff',
    surfaceColor: '#f7fafc',
    seo: {
      siteUrl: process.env.PAGENARY_SITE_URL || DEFAULT_SITE_URL,
      discoverabilityProfile: 'open',
      generateStaticPages: true,
      generateSitemap: true,
      generateRobotsTxt: true,
      generateLlmsTxt: true,
      generateCorpusArtifacts: true,
      defaultChangeFreq: 'weekly',
    },
    share: {
      enabled: true,
      services: ['copy', 'email', 'x', 'linkedin', 'reddit'],
    },
  };

  const manifest = {
    default: 'welcome',
    sections: [
      sectionFor(pageById.get('welcome')),
      ...groups.map((group) => ({
        id: group.id,
        title: group.title,
        summary: group.summary,
        file: `${group.id}.md`,
        sections: group.ids.map((id) => sectionFor(pageById.get(id))),
      })),
    ],
  };

  const tenants = {
    tenants: [
      {
        id: TENANT_ID,
        source: { type: 'local', path: `./docsite/${TENANT_ID}` },
        strictLinks: true,
        language: 'en-US',
        accessibility: {
          strict: false,
          report: { enabled: true },
        },
      },
    ],
  };

  await writeJson(join(TENANT_DIR, 'config.json'), config);
  await writeJson(join(TENANT_DIR, 'manifest.json'), manifest);
  await writeJson(join(ROOT, 'tenants.json'), tenants);

  console.log(`Pagenary tenant synced: ${TENANT_ID}`);
  console.log(`Content: ${pages.length} source Markdown pages plus ${groups.length} generated group pages`);
  console.log('Build: npm run docs:build');
  console.log('Preview: npm run docs:serve');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
