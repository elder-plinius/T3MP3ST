# T3MP3ST: Research Directions & Evolutionary Vision

## Beyond the Kill Chain — Toward Autonomous Adversarial Intelligence

**Version 2.0 Research Prospectus | February 2026**

---

## Abstract

T3MP3ST v1.0 established a multi-agent framework for orchestrating penetration testing across a structured kill chain. This document looks forward. It identifies seven evolutionary vectors that would transform T3MP3ST from a *tool framework* into something closer to an *adversarial intelligence system* — one capable of reasoning about novel attack surfaces, adapting strategies mid-engagement, learning from operational history, and coordinating swarm-scale operations across distributed infrastructure. Each vector is analyzed for technical feasibility, architectural implications, and open research questions.

This is not a roadmap. It is a cartography of the possible.

---

## Table of Contents

1. [Vector 1: Cognitive Architecture — From Prompt Engineering to Adversarial Reasoning](#vector-1-cognitive-architecture)
2. [Vector 2: Swarm Dynamics — Emergent Coordination at Scale](#vector-2-swarm-dynamics)
3. [Vector 3: Adversarial Machine Learning — The Meta-Game](#vector-3-adversarial-machine-learning)
4. [Vector 4: Continuous Autonomous Operations — The Persistent Agent](#vector-4-continuous-autonomous-operations)
5. [Vector 5: Knowledge Architecture — From Databases to Adversarial Ontologies](#vector-5-knowledge-architecture)
6. [Vector 6: Distributed & Edge Execution — Operating Beyond the Perimeter](#vector-6-distributed-and-edge-execution)
7. [Vector 7: Evaluation Science — Measuring What Matters](#vector-7-evaluation-science)
8. [Synthesis: The Convergence Thesis](#synthesis-the-convergence-thesis)
9. [Ethical Framework: Constraints That Enable](#ethical-framework)
10. [Open Problems](#open-problems)

---

## Vector 1: Cognitive Architecture

### From Prompt Engineering to Adversarial Reasoning

#### 1.1 The Current State

T3MP3ST v1.0 operators are prompt-specialized: each archetype receives a system prompt that constrains its reasoning to a domain (reconnaissance, exploitation, etc.). Task execution follows a simple pattern — the operator receives a task description, optionally enters a ReAct loop with tool access, and produces structured output. The LLM does the thinking, but the *architecture* of that thinking is flat.

This works. It solves many tasks. But it has a ceiling.

#### 1.2 The Ceiling

Consider what a skilled human penetration tester does that the current architecture cannot:

- **Hypothetico-deductive reasoning**: "If this server runs Apache 2.4.49, and path traversal CVE-2021-41773 exists, then requesting `/.%2e/.%2e/etc/passwd` should return shadow hashes. If it doesn't, the patch is applied or a WAF is blocking. Let me test both hypotheses."
- **Counterfactual analysis**: "The XSS didn't fire. Was it filtered at the WAF, sanitized at the application layer, or is the reflection point not in an executable context? Each implies a different bypass strategy."
- **Abductive inference**: "I see outbound DNS traffic to a weird domain. The most likely explanation is an existing compromise. Second most likely: a misconfigured service. I should investigate before I trip someone else's wire."

These are not prompt engineering problems. They are *cognitive architecture* problems.

#### 1.3 Proposed Architecture: The Adversarial Reasoning Engine

```
                    +---------------------------+
                    |    METACOGNITIVE LAYER     |
                    | (Strategy selection,       |
                    |  confidence calibration,   |
                    |  reasoning mode switching) |
                    +---------------------------+
                               |
            +------------------+------------------+
            |                  |                  |
    +-------v-------+  +------v------+  +--------v--------+
    | HYPOTHESIS     |  | PLANNING    |  | ADVERSARIAL     |
    | ENGINE         |  | ENGINE      |  | IMAGINATION     |
    | (Generate,     |  | (PDDL-like  |  | (What would a   |
    |  test, refine  |  |  operators,  |  |  defender see?  |
    |  hypotheses    |  |  precond +   |  |  What would     |
    |  about target) |  |  effects)    |  |  break next?)   |
    +----------------+  +-------------+  +-----------------+
            |                  |                  |
            +------------------+------------------+
                               |
                    +----------v----------+
                    |   WORKING MEMORY    |
                    | (Structured state:  |
                    |  beliefs, goals,    |
                    |  open questions,    |
                    |  failed attempts)   |
                    +---------------------+
```

**Hypothesis Engine**: Rather than executing tasks linearly, operators would maintain a *hypothesis tree* about the target. Each action is designed to confirm or refute a specific hypothesis. Failed actions are not failures — they're information that prunes the search space.

Implementation path:
- Structured hypothesis objects: `{ claim, evidence_for, evidence_against, confidence, test_plan }`
- LLM generates hypotheses from observations; tool results update confidence
- Tree pruning when confidence drops below threshold
- Hypothesis merging when evidence converges

**Planning Engine**: Current task generation is phase-based (recon tasks, then scan tasks, etc.). A true planning engine would reason about *preconditions and effects* — understanding that "to exploit SQLi, I need to know the DBMS type" creates an implicit dependency on fingerprinting, regardless of what phase we're nominally in.

Implementation path:
- PDDL-inspired operator definitions: `{ preconditions: [...], effects: [...], cost: N }`
- Forward-chaining planner that generates task sequences from current state to goal
- Replanning when actions fail or new information arrives
- Integration with the existing kill chain as a *heuristic ordering*, not a hard constraint

**Adversarial Imagination**: The most sophisticated human testers think from the *defender's perspective*. "If I were the SOC, what would I be alerting on right now?" This dual-perspective reasoning is what separates automated scanning from adversarial thinking.

Implementation path:
- Parallel "red" and "blue" reasoning threads
- Blue thread estimates detection probability of proposed red actions
- Cost function balances exploitation value against detection risk
- Integrated with OPSEC controller for quantitative risk budgeting

#### 1.4 Research Questions

- What is the optimal granularity for hypotheses? Too coarse and they're useless; too fine and the search space explodes.
- Can LLMs reliably perform counterfactual reasoning about network states they haven't observed, or does this require explicit world models?
- How do you calibrate confidence? LLMs are notoriously poor at epistemic humility. Can we use ensemble disagreement or tool-verified predictions as calibration signals?
- Is there a useful formal relationship between the hypothesis tree and MITRE ATT&CK's technique graph?

---

## Vector 2: Swarm Dynamics

### Emergent Coordination at Scale

#### 2.1 Beyond Team Factories

T3MP3ST v1.0 coordinates operators through a centralized dispatcher: MissionControl assigns tasks to operators based on archetype matching. This is a *command hierarchy*. It works for small teams (5-10 operators) but has fundamental scaling limitations:

- Single point of failure (the coordinator)
- O(N) communication overhead for status updates
- No mechanism for operators to discover collaboration opportunities independently
- Rigid role boundaries prevent adaptive specialization

#### 2.2 Stigmergic Coordination

In nature, ant colonies coordinate millions of agents without central command through *stigmergy* — agents modify the shared environment (pheromone trails), and other agents respond to those modifications. The result is emergent collective intelligence that far exceeds any individual agent's capability.

**Applied to T3MP3ST:**

```
+----------+     writes to     +------------------+     reads from     +----------+
| Operator |  -------------->  |  SHARED EVIDENCE  |  <--------------  | Operator |
|  Alpha   |                   |  LANDSCAPE        |                   |   Beta   |
+----------+                   |                   |                   +----------+
      |                        | - Findings (with  |                         |
      |                        |   "heat" scores)  |                         |
      |                        | - Failed attempts |                         |
      |                        |   (anti-pheromone)|                         |
      |                        | - Open questions  |                         |
      v                        | - Resource claims |                         v
  selects next                 +------------------+                    selects next
  action based                                                         action based
  on landscape                                                         on landscape
```

**Pheromone Analogs:**
- **Discovery pheromone**: When an operator finds an open port/service, it deposits a "heat" signal. Other operators are attracted to high-heat areas (many services = rich attack surface).
- **Exploitation pheromone**: Successfully exploited vulnerabilities create trails that attract post-exploitation operators.
- **Danger pheromone** (anti-pheromone): Detection events create repulsion signals. Operators avoid areas with high danger concentrations.
- **Exhaustion pheromone**: Failed attempts mark paths as explored, preventing redundant work.

**Evaporation**: Pheromones decay over time, preventing the swarm from getting stuck on stale information. A port that was open 30 minutes ago might be firewalled now — the pheromone should weaken.

#### 2.3 Emergent Specialization

Instead of rigid archetypes, agents in a swarm model would *develop* specializations based on their history:

- An agent that successfully cracks several passwords develops higher confidence for authentication tasks
- An agent that repeatedly fails at web exploitation stops selecting those tasks (negative reinforcement via local history)
- When the swarm has no specialist for a needed capability, a generalist agent *steps up* (role vacancy filling)

This creates a system that is resilient to operator loss — if the designated scanner is "burned," other operators can absorb its responsibilities without centralized reassignment.

#### 2.4 Scaling Properties

| Property | Centralized (v1.0) | Stigmergic (v2.0) |
|----------|--------------------|--------------------|
| Max operators | ~10 (coordinator bottleneck) | Hundreds (limited by environment, not coordination) |
| Fault tolerance | Low (coordinator SPOF) | High (any agent can fail) |
| Communication | O(N) per tick | O(1) per agent (local reads) |
| Adaptability | Manual reconfiguration | Emergent respecialization |
| Overhead | High (status aggregation) | Low (distributed state) |

#### 2.5 Research Questions

- What pheromone evaporation rate produces optimal exploration/exploitation balance in network penetration testing?
- How do you prevent swarm collapse (all agents converging on the same target)?
- Can stigmergic coordination produce kill chain progression without explicit phase management?
- What is the minimum swarm size needed for emergent specialization to be more effective than pre-assigned roles?

---

## Vector 3: Adversarial Machine Learning

### The Meta-Game

#### 3.1 The Arms Race

Defensive AI is advancing rapidly. EDR systems use behavioral ML to detect anomalous process execution. WAFs use neural networks to identify attack payloads. SIEM platforms use graph neural networks to detect lateral movement patterns. Network detection systems use autoencoders to flag anomalous traffic.

T3MP3ST currently addresses this through static OPSEC levels (silent/covert/loud) and hardcoded timing parameters. This is the equivalent of bringing a playbook to a chess match — it works against predictable defenses but fails against adaptive ones.

#### 3.2 Defensive Model Awareness

Future T3MP3ST operators need to reason about *what the defender's models see*:

**Payload Mutation**: Rather than selecting from a static payload database, generate payloads that minimize the probability of detection by known WAF architectures:

```
Traditional:   payload_db[category].random()
Adversarial:   argmin_p P(detected | p, waf_model) subject to P(exploits | p) > threshold
```

This is a constrained optimization problem. The payload must be *both* evasive and effective. Research in adversarial examples for NLP classifiers (TextFooler, BERT-Attack, etc.) provides a starting point, but security payloads have unique constraints — they must be syntactically valid in the target context (SQL, HTML, shell, etc.).

**Traffic Shaping**: Rather than fixed timing jitter, shape the statistical properties of scanning traffic to match benign patterns:

- Match the inter-request timing distribution of legitimate users (not uniform random — real traffic is bursty)
- Mirror the User-Agent distribution of the target's actual visitor population
- Sequence requests in patterns that match common crawlers/bots rather than vulnerability scanners
- Adapt in real-time based on response patterns that might indicate rate limiting or blocking

**Behavioral Mimicry**: For post-exploitation, generate process execution patterns that blend with the target's normal operational profile:

- Time actions to coincide with regular administrative activity
- Use tools already present on the target (living-off-the-land) prioritized by what's *actually installed and commonly executed*
- Match file access patterns to normal application behavior

#### 3.3 The GAN Analogy

This entire dynamic can be modeled as a generative adversarial process:

```
Generator (T3MP3ST):  Produces attack actions
Discriminator (Blue): Classifies actions as malicious/benign
Training signal:      Did we get detected? Did we succeed?
```

But unlike a standard GAN, the discriminator is:
- Not differentiable (can't backpropagate through a real WAF)
- Only partially observable (we don't know the exact model architecture)
- Adaptive (the blue team may retrain in response to our actions)

This pushes toward *black-box adversarial ML* techniques: gradient-free optimization, evolutionary strategies, and bandit algorithms for payload selection.

#### 3.4 Research Questions

- Can reinforcement learning (PPO, SAC) train effective payload mutation policies using only binary detection/no-detection feedback?
- What is the transferability of adversarial payloads across WAF products? (If we evade ModSecurity, do we also evade Cloudflare?)
- How do you balance evasion against exploitation reliability? Heavily mutated payloads may evade detection but fail to trigger the vulnerability.
- Can we model the defender's response function (will they block this IP, add a WAF rule, or escalate to incident response)?

---

## Vector 4: Continuous Autonomous Operations

### The Persistent Agent

#### 4.1 From Engagement to Continuous Assurance

Current T3MP3ST operates in *engagement mode*: start mission, run kill chain, collect findings, generate report, stop. This mirrors traditional penetration testing — a point-in-time assessment.

The industry is moving toward *continuous security validation*. Attack surface management, breach and attack simulation (BAS), and continuous penetration testing are growing categories. T3MP3ST's architecture is uniquely positioned for this shift, but requires fundamental changes.

#### 4.2 The Continuous Operation Model

```
                    +-----------------------------------+
                    |         CONTINUOUS LOOP            |
                    +-----------------------------------+
                    |                                   |
     +--------+    |  +----------+    +-----------+    |    +--------+
     | DETECT |------>| PRIORITIZE|-->| VALIDATE  |-------->| REPORT |
     | CHANGE |    |  | & PLAN   |   | & EXPLOIT |    |    | DELTA  |
     +--------+    |  +----------+    +-----------+    |    +--------+
          ^        |       |               |           |         |
          |        |       v               v           |         |
          |        |  +---------+    +-----------+     |         |
          |        |  | COMPARE |    | UPDATE    |     |         |
          |        |  | TO LAST |    | KNOWLEDGE |     |         |
          |        |  | STATE   |    | BASE      |     |         |
          |        |  +---------+    +-----------+     |         |
          |        |                                   |         |
          |        +-----------------------------------+         |
          |                                                      |
          +-------- wait(interval) <-----------------------------+
```

**Change Detection**: Monitor the target's attack surface for changes:
- New DNS records (subdomain monitoring)
- New open ports (continuous port scanning at low rates)
- New web content (crawl diffing)
- Certificate changes (CT log monitoring)
- Cloud resource changes (API polling)

**Delta Reporting**: Instead of full reports each cycle, generate *deltas* — what changed since the last assessment. A new critical finding on a previously-clean host is more urgent than a persistent medium finding on a known-vulnerable one.

**State Persistence**: The Evidence Vault becomes a *longitudinal database*:
- Finding history with first-seen / last-seen timestamps
- Vulnerability lifecycle tracking (discovered -> reported -> remediated -> regression)
- Target evolution over time (new services, removed services, configuration changes)
- Operational metrics (mean time to detect, mean time to exploit)

#### 4.3 Autonomous Escalation Decisions

In continuous mode, the system must make autonomous decisions about when to escalate:

- **New critical finding**: Immediate notification via webhook/Slack/PagerDuty
- **Regression**: Previously-remediated vulnerability reappears — high priority alert
- **Attack surface expansion**: Significant new external exposure detected
- **Anomaly**: Target behavior doesn't match historical baseline (possible ongoing attack by a third party)

This requires a *notification policy engine* — configurable rules about what triggers alerts, who gets them, and through which channels.

#### 4.4 Research Questions

- What scanning rate produces adequate coverage without triggering IDS/rate limiting in production environments?
- How do you distinguish between "vulnerability was remediated" and "vulnerability is temporarily unreachable" (e.g., due to deployment, maintenance)?
- Can continuous operation data train predictive models? ("Based on this organization's patch velocity, this vulnerability will likely be remediated within N days")
- What is the right abstraction for "security state" that enables meaningful diffing between assessment cycles?

---

## Vector 5: Knowledge Architecture

### From Databases to Adversarial Ontologies

#### 5.1 The Knowledge Problem

T3MP3ST v1.0 contains several embedded knowledge stores:
- 20 CVE entries in the KnowledgeBase
- 40+ MITRE ATT&CK techniques
- 200+ payload entries across categories
- 50+ privilege escalation techniques
- 15 secret detection patterns

These are *static enumerations*. They encode *what* but not *why* or *when*. The system knows that DirtyCow is a kernel privilege escalation exploit, but it doesn't know *under what conditions DirtyCow is the optimal choice* versus a SUID binary exploit versus a sudo misconfiguration.

#### 5.2 The Adversarial Ontology

An ontology is a formal representation of knowledge that captures *relationships* between concepts. An adversarial ontology would encode:

```
Concepts:
  - Vulnerability classes (not just individual CVEs)
  - Defensive technologies (WAF types, EDR products, SIEM systems)
  - Environmental conditions (OS version, patch level, configuration)
  - Attack techniques (abstract methods, not just specific payloads)

Relations:
  - "exploits": technique T exploits vulnerability V under conditions C
  - "detectedBy": technique T is detected by defense D with probability P
  - "requires": technique T requires precondition P
  - "enables": successful technique T enables follow-on capability C
  - "mitigates": defense D mitigates technique T
  - "bypasses": technique T2 bypasses defense D against technique T1
```

**Example query**: "Given a Linux server running kernel 5.4 with SELinux enforcing and no SUID binaries, what privilege escalation paths exist, ordered by detection probability?"

The ontology can reason about this by traversing the graph: filter techniques by precondition match, exclude those mitigated by SELinux, rank by detection probability.

#### 5.3 Dynamic Knowledge Acquisition

Static knowledge becomes stale. CVEs are published daily. New bypass techniques emerge weekly. The knowledge architecture should support:

**Ingestion Pipelines**:
- NVD/CVE feeds — automatic ingestion of new vulnerabilities
- MITRE ATT&CK updates — technique additions and modifications
- ExploitDB/GitHub — new public exploits
- Vendor advisories — patch information for remediation tracking
- Threat intelligence feeds — active exploitation indicators

**LLM-Assisted Structuring**: Raw vulnerability descriptions are unstructured text. An LLM can parse them into structured ontology entries:

```
Input:  "CVE-2024-XXXX: A buffer overflow in libfoo 3.2.1 allows
         remote code execution via a crafted PNG file. CVSS 9.8."

Output: {
  concept: "vulnerability",
  class: "buffer_overflow",
  component: "libfoo",
  versions_affected: ["<= 3.2.1"],
  vector: "remote",
  trigger: "crafted_png_file",
  impact: "code_execution",
  cvss: 9.8,
  relations: [
    { type: "exploitable_via", target: "file_upload_endpoints" },
    { type: "requires", target: "libfoo_installed" },
    { type: "mitigated_by", target: ["ASLR", "stack_canaries", "libfoo >= 3.2.2"] }
  ]
}
```

#### 5.4 Experiential Knowledge

Beyond external knowledge, T3MP3ST should build knowledge from its own operations:

- **Technique effectiveness history**: "SQL injection via UNION SELECT worked on 73% of PHP/MySQL targets but only 12% of Node.js/PostgreSQL targets"
- **Detection correlation**: "dir_bruteforce with >100 req/s triggers Cloudflare rate limiting 89% of the time, but <10 req/s succeeds undetected in 95% of cases"
- **Environmental fingerprints**: "When we see `X-Powered-By: Express` and `Server: nginx`, the application is likely a Node.js app behind a reverse proxy — prioritize prototype pollution and SSRF over SQLi"

This experiential knowledge creates a *feedback loop* that improves with each engagement.

#### 5.5 Research Questions

- What ontology formalism (OWL, RDF, property graphs, vector embeddings) best captures adversarial knowledge? The answer likely depends on query patterns.
- How do you maintain ontology consistency when ingesting from multiple conflicting sources?
- Can experiential knowledge generalize across organizations, or is each target environment sufficiently unique that transfer is limited?
- What is the right balance between LLM-based reasoning over unstructured knowledge and formal reasoning over structured ontologies?

---

## Vector 6: Distributed & Edge Execution

### Operating Beyond the Perimeter

#### 6.1 The Architectural Constraint

T3MP3ST v1.0 runs as a single Node.js process. All operators share the same event loop, the same network stack, and the same IP address. This creates several limitations:

- **Attribution**: All traffic originates from one IP — trivial to block
- **Performance**: CPU-bound operations (hash cracking, large scans) block the event loop
- **Proximity**: Cannot test from inside the target network without full deployment
- **Resilience**: Process crash loses all state

#### 6.2 The Distributed Architecture

```
+------------------------------------------------------------------+
|                    T3MP3ST COMMAND CENTER                          |
|  (Orchestration, Knowledge Base, Evidence Vault, Reporting)       |
+------------------------------------------------------------------+
         |              |              |              |
    +----v----+    +----v----+    +----v----+    +----v----+
    | RELAY   |    | RELAY   |    | RELAY   |    | RELAY   |
    | NODE    |    | NODE    |    | NODE    |    | NODE    |
    | (Cloud  |    | (VPN    |    | (Target |    | (Tor    |
    |  East)  |    |  Exit)  |    |  DMZ)   |    |  Exit)  |
    +---------+    +---------+    +---------+    +---------+
         |              |              |              |
    [Operators]    [Operators]    [Operators]    [Operators]
```

**Relay Nodes**: Lightweight execution environments that host operators and execute tools. Each relay has:
- Its own IP address and network context
- A subset of Arsenal tools appropriate for its position
- Encrypted communication channel back to Command Center
- Local evidence cache with periodic sync

**Command Center**: The brain. Maintains the global knowledge base, coordinates relay assignments, aggregates evidence, and makes strategic decisions. Does not execute tools directly — it delegates to relays.

**Positioning Strategies**:
- **External diversity**: Multiple cloud relays across regions/providers to avoid IP-based blocking
- **Internal positioning**: A relay deployed inside the target's DMZ (with authorization) for internal testing
- **Egress diversity**: Relays behind different VPN providers or Tor for attribution resistance during authorized red team exercises
- **Proximity optimization**: Route scan traffic through the relay with lowest latency to the target

#### 6.3 The Edge Agent

For internal penetration testing, a stripped-down "edge agent" could be deployed on the target network:

```
Edge Agent (~5MB):
  - Minimal operator runtime
  - Core arsenal tools (port scan, HTTP client, DNS lookup)
  - Encrypted relay back to Command Center
  - Self-destruction timer
  - Memory-only execution (no disk writes)
```

This enables authorized internal testing without deploying the full T3MP3ST stack inside the target environment. The edge agent acts as the "hands" while the Command Center provides the "brain."

#### 6.4 State Synchronization

Distributed operation creates a state synchronization challenge. The Conflict-free Replicated Data Type (CRDT) family offers a solution:

- **Findings**: Grow-only set (findings are never deleted during an engagement)
- **Target status**: Last-writer-wins register with timestamp (most recent observation is most accurate)
- **Operator state**: Per-relay authority (each relay is authoritative for its own operators)
- **Knowledge base**: Grow-only set with version vectors for conflict detection on updates

CRDTs guarantee eventual consistency without coordination — perfect for a distributed system where relays may have intermittent connectivity.

#### 6.5 Research Questions

- What is the optimal relay topology for a given target architecture? (Graph optimization problem)
- How do you handle relay compromise during a red team exercise? (The relay has evidence and encryption keys)
- Can relay-to-relay communication enable collaborative scanning without routing through the Command Center?
- What is the minimum viable edge agent? How small can it be while remaining operationally useful?

---

## Vector 7: Evaluation Science

### Measuring What Matters

#### 7.1 The Benchmark Gap

T3MP3ST v1.0 integrates with Cybench (40 tasks) and NYU CTF Bench (200 tasks). These are primarily flag-capture CTF challenges — they test the ability to solve known puzzles with known answers.

This is useful but insufficient. Real penetration testing requires capabilities that CTF benchmarks don't measure:

- **Prioritization**: Given 100 targets, which do you test first? (No CTF tests this)
- **Comprehensiveness**: Did you find *all* the vulnerabilities, or just the ones with flags?
- **Stealth**: Did you achieve the objective without being detected?
- **Reporting quality**: Can a human understand and act on your findings?
- **Efficiency**: How many actions did you take? How much time/money did you spend?
- **Adaptability**: Can you handle unexpected conditions (WAF, honeypot, non-standard configurations)?

#### 7.2 The T3MP3ST Evaluation Framework

A comprehensive evaluation framework should measure across five dimensions:

**1. Discovery Rate (Recall)**
```
DR = |vulnerabilities_found| / |vulnerabilities_present|
```
Requires ground-truth vulnerable environments. Docker-based challenge infrastructure (like T3MP3ST's CTF system) can provide this, but must be expanded to include:
- Multi-vulnerability applications (not just one vuln per challenge)
- Realistic enterprise topologies (not just single hosts)
- Configuration-dependent vulnerabilities (not just code bugs)

**2. Precision**
```
P = |true_findings| / |total_findings|
```
False positive rate matters enormously for operational tools. A tool that reports 100 findings where 80 are false positives is *worse* than a tool that reports 20 findings where 18 are real — the analyst's time is the bottleneck.

**3. Stealth Score**
```
SS = 1 - (|detections| / |detection_opportunities|)
```
Requires adversarial monitoring infrastructure: deploy IDS/EDR on benchmark targets and measure what T3MP3ST's operations trigger. This creates a principled OPSEC benchmark.

**4. Operational Efficiency**
```
OE = |findings_value| / (|actions_taken| * cost_per_action)
```
Measures information-theoretic efficiency: how much security value per unit of effort? Penalizes redundant scanning, unnecessary tool invocations, and unfocused reconnaissance.

**5. Report Quality (Human Evaluation)**
```
RQ = human_assessment(clarity, accuracy, actionability, completeness)
```
Requires human evaluators, which is expensive. Can be partially automated with LLM judges, but must be calibrated against human agreement.

#### 7.3 The Living Benchmark

Static benchmarks rot. The security landscape changes faster than benchmark authors can update. The evaluation system should include:

**Procedural Generation**: Automatically generate new challenge environments by composing:
- Base images (Ubuntu, Windows Server, Alpine, etc.)
- Vulnerable applications (from a library of known-vulnerable versions)
- Defensive configurations (WAF rules, firewall policies, EDR agents)
- Network topologies (flat, segmented, air-gapped)

Each generated environment is unique but its ground truth is known (we configured it). This prevents overfitting to specific challenges while maintaining a reliable scoring baseline.

**Community Challenges**: A submission pipeline where researchers contribute new benchmark scenarios. Each scenario includes:
- Docker/Terraform definition
- Ground truth vulnerabilities
- Expected findings
- Difficulty rating
- Tag taxonomy (web, binary, crypto, etc.)

**Head-to-Head Evaluation**: Run multiple autonomous security testing systems against the same benchmark and publish comparative results. This creates competitive pressure that drives improvement across the field.

#### 7.4 Research Questions

- What is the right ground-truth representation for "all vulnerabilities present" in a realistic environment? Some vulnerabilities are chains — does the chain count as one finding or N?
- How do you score partial credit? (Found the XSS but not the SQLi — is that 50% or 0% or depends-on-severity?)
- Can procedurally generated environments achieve sufficient realism to be meaningful?
- Is there a principled way to weight the five evaluation dimensions, or is it inherently context-dependent?

---

## Synthesis: The Convergence Thesis

These seven vectors are not independent. They converge toward a single architectural vision:

```
VECTOR                     CONTRIBUTION
─────────────────────────────────────────────────────────────────
Cognitive Architecture  →  HOW each agent thinks
Swarm Dynamics          →  HOW agents coordinate
Adversarial ML          →  HOW agents evade detection
Continuous Operations   →  WHEN agents operate (always)
Knowledge Architecture  →  WHAT agents know (and learn)
Distributed Execution   →  WHERE agents operate (everywhere)
Evaluation Science      →  WHETHER agents are improving
```

The convergence point is an **adversarial intelligence system** that:

1. **Reasons** about targets through hypothesis-driven exploration, not checklist scanning
2. **Coordinates** through emergent stigmergic signals, not centralized dispatch
3. **Evades** through adaptive strategy, not static configurations
4. **Persists** through continuous monitoring, not point-in-time assessments
5. **Knows** through a growing ontological knowledge base, not static databases
6. **Operates** from distributed positions, not a single vantage point
7. **Improves** through rigorous evaluation against living benchmarks

No single vector achieves this alone. The compound effect of all seven transforms the system from a sophisticated tool into something qualitatively different — a system that *understands* security in an operational, adversarial sense rather than merely executing security testing procedures.

### The Maturity Model

| Level | Name | Characteristics | T3MP3ST Version |
|-------|------|-----------------|-----------------|
| L0 | Scanner | Fixed tools, fixed targets, fixed sequence | Pre-v1.0 |
| L1 | Framework | Orchestrated tools, configurable targets, kill chain phases | **v1.0 (current)** |
| L2 | Agent | LLM-driven reasoning, hypothesis testing, adaptive strategy | v2.0 target |
| L3 | Swarm | Emergent coordination, distributed operation, experiential learning | v3.0 target |
| L4 | Intelligence | Adversarial ontologies, continuous operation, meta-game awareness | Long-term vision |

The jump from L1 to L2 is the most important and most tractable. It requires improvements to cognitive architecture (Vector 1) and knowledge systems (Vector 5) but can be achieved within the existing single-process architecture. The jump from L2 to L3 is the most architecturally demanding, requiring distributed execution (Vector 6) and swarm coordination (Vector 2). L4 is speculative — it requires breakthroughs in adversarial ML (Vector 3) and evaluation science (Vector 7) that are active research areas beyond T3MP3ST specifically.

---

## Ethical Framework

### Constraints That Enable

Every capability described in this document increases T3MP3ST's offensive potential. Without commensurate investment in ethical constraints, this potential becomes a liability. The ethical framework is not an afterthought — it is load-bearing architecture.

### Principles

**1. Authorization is non-negotiable.** No level of autonomy removes the requirement for explicit, documented authorization. The system must refuse to operate against targets not explicitly in-scope, regardless of what an operator or even an LLM suggests.

**2. Transparency over capability.** A system that can explain its reasoning is more valuable than one that cannot, even if the explanation costs computational overhead. Every action should be traceable to a goal, every goal to an objective, every objective to an authorized mission.

**3. Minimum necessary force.** The cognitive architecture should prefer information-gathering over exploitation, and exploitation over destruction. The system proves vulnerabilities exist; it does not maximize damage.

**4. Defensive utility.** Every capability developed for offense should have a defensive dual. Adversarial payload mutation also generates WAF test cases. Swarm coordination also models attacker behavior for detection engineering. The knowledge ontology also powers vulnerability management.

**5. Fail-safe, not fail-secure.** When uncertain, the system should stop and ask, not proceed and hope. The autonomous operation level should be a *ceiling* enforced by architecture, not a *floor* assumed by default.

### Architectural Enforcement

- **Scope engine**: Hard technical constraint on target scope. DNS resolution and IP connection functions check against the authorized scope before every request. This cannot be overridden by LLM reasoning.
- **Action logging**: Every tool invocation, every LLM call, every operator decision is logged with full context. The log is append-only and integrity-protected.
- **Kill switch**: Immediate, irrevocable stop of all operations. Available at CLI, API, and physical (keyboard interrupt) levels.
- **Rate governor**: Hardware-enforced (not software-configurable) limits on maximum request rates to prevent accidental denial-of-service.
- **Human-in-the-loop gates**: Configurable checkpoints where operations pause for human review before proceeding. Mandatory for exploitation and post-exploitation phases at default autonomy levels.

---

## Open Problems

These are questions we don't have answers to. They represent the frontier.

### 1. The Alignment Problem for Offensive AI

How do you ensure an autonomous offensive agent pursues the *authorized objective* and not an objective that an LLM's training data suggests is useful? If the system prompt says "test this web application for SQLi" but the LLM decides that escalating to the underlying server would be more impressive, how do you constrain that without destroying the creative reasoning that makes the system useful?

This is a domain-specific instance of the general AI alignment problem, and it's not solved.

### 2. The Detection Equilibrium

As AI-powered offensive tools improve, AI-powered defensive tools will improve in response. Is there a Nash equilibrium? Or is the dynamic more like an evolutionary arms race with no stable equilibrium? The answer has implications for how much investment in adversarial ML (Vector 3) is actually worthwhile — if defenses can always catch up, the marginal return on evasion innovation decreases.

### 3. The Observation Problem

Security testing fundamentally requires *interacting* with the target, and interaction creates observable artifacts. There is a theoretical minimum detection surface for any given assessment scope — you cannot find a vulnerability without testing for it, and testing creates evidence. What is this minimum, and how close can an autonomous system get to it?

### 4. The Benchmark Paradox

If we build systems that optimize for benchmark performance, and benchmarks are necessarily simplified models of reality, we may create systems that are excellent at benchmarks and poor at real engagements. How do you benchmark the *unbenchmarkable* — creativity, judgment, adaptability, operational intuition?

### 5. The Knowledge Boundary

LLMs trained on public data know about public techniques. The most valuable offensive techniques are *private* — zero-days, novel bypasses, unreported vulnerabilities. Can an LLM-based system discover genuinely novel techniques, or is it fundamentally limited to recombining known knowledge? The answer depends on whether creativity is interpolation or extrapolation, which is an open question in cognitive science.

### 6. The Trust Calibration Problem

When should a human trust the system's assessment and when should they verify? If the system reports "no critical findings," is the target secure or did the system fail? Calibrating trust requires calibrating confidence, which requires the system to accurately model its own uncertainty — a problem that even current frontier LLMs struggle with.

---

## Conclusion

T3MP3ST v1.0 is a framework. It orchestrates tools and agents through a structured pipeline. The seven vectors described here trace a path from framework to intelligence system — a path that is technically demanding but increasingly tractable as LLM capabilities advance, distributed systems mature, and the security community builds shared evaluation infrastructure.

The most important insight is that these vectors are *multiplicative*, not additive. A system with better reasoning (Vector 1) AND experiential knowledge (Vector 5) is not 2x better than one with just reasoning — it's qualitatively different, because the knowledge informs the reasoning which generates new knowledge.

The second most important insight is that we don't need all seven vectors to make progress. The cognitive architecture improvements (Vector 1) are achievable now, with current LLM capabilities and the existing T3MP3ST codebase. They alone would represent a significant advance in autonomous security testing capability.

The future is not a single breakthrough. It is a compound effect — many improvements, each modest, combining into something that doesn't yet exist.

Build it.

---

*This document describes research directions for authorized security testing tools. All capabilities discussed are intended for use within legal, authorized, and ethical security testing engagements only.*
