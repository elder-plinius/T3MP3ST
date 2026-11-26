/**
 * Cognitive Reflector & Autonomous Decision Critic
 * Ported & adapted from PentAGI (pkg/templates/prompts/reflector.tmpl & adviser.tmpl)
 * 
 * Analyzes command and tool outputs after execution to determine:
 * 1. Progress toward mission objectives.
 * 2. Dead-end identification (blocked ports, rate-limits, unexploitable responses).
 * 3. Strategy pivot recommendations.
 */

export interface ReflectionVerdict {
  assessment: 'progress' | 'dead_end' | 'pivot_required' | 'goal_achieved';
  confidence: number;
  reasoning: string;
  suggestedAction?: string;
  identifiedArtifacts?: string[];
}

export class AgentReflector {
  /**
   * Evaluates the latest action and output against target goals.
   */
  public static reflect(params: {
    target: string;
    goal: string;
    lastCommand: string;
    output: string;
    priorAttempts?: number;
  }): ReflectionVerdict {
    const { target, goal, lastCommand, output, priorAttempts = 1 } = params;
    const lowerOutput = (output || '').toLowerCase();
    const artifacts: string[] = [];

    // 1. Goal Achieved Signals (Flags, successful shell, authenticated token)
    if (lowerOutput.includes('t3mp3st{') || lowerOutput.includes('flag{') || lowerOutput.includes('root@') || lowerOutput.includes('uid=0(')) {
      const flagMatch = output.match(/(?:T3MP3ST|flag)\{[a-zA-Z0-9_]+\}/i);
      if (flagMatch) artifacts.push(flagMatch[0]);

      return {
        assessment: 'goal_achieved',
        confidence: 0.98,
        reasoning: `Objective achieved for goal "${goal}": valid execution signature or flag string detected in tool output.`,
        identifiedArtifacts: artifacts
      };
    }

    // 2. Dead-End Signals (Connection refused, host down, 404, firewall drop)
    const isConnectionRefused = lowerOutput.includes('connection refused') || lowerOutput.includes('no route to host') || lowerOutput.includes('host is down');
    const isWafBlock = lowerOutput.includes('403 forbidden') || lowerOutput.includes('cloudflare') || lowerOutput.includes('access denied');

    if (isConnectionRefused) {
      return {
        assessment: 'dead_end',
        confidence: 0.90,
        reasoning: `Target ${target} dropped or refused connection on ${lastCommand} while pursuing "${goal}". Vector is not network reachable.`,
        suggestedAction: 'Pivot to alternate port or discover subdomains/virtual hosts.'
      };
    }

    if (isWafBlock && priorAttempts >= 2) {
      return {
        assessment: 'pivot_required',
        confidence: 0.85,
        reasoning: `Repeated WAF/Perimeter block (403/Forbidden) on current vector for "${goal}". Direct payload probing is filtered.`,
        suggestedAction: 'Pivot to parameter-level fuzzing or out-of-band/blind verification techniques.'
      };
    }

    // 3. Informational & Recon Discoveries (New endpoints, banners, technologies)
    const cveMatches = output.match(/CVE-\d{4}-\d{4,7}/gi) || [];
    if (cveMatches.length > 0) {
      artifacts.push(...cveMatches);
      return {
        assessment: 'progress',
        confidence: 0.88,
        reasoning: `Identified ${cveMatches.length} specific CVE vulnerability candidates toward "${goal}".`,
        suggestedAction: 'Query exploit intelligence (Sploitus) for discovered CVE references.',
        identifiedArtifacts: artifacts
      };
    }

    // 4. Default incremental progress
    return {
      assessment: 'progress',
      confidence: 0.70,
      reasoning: `Command produced valid telemetry for goal "${goal}". Continue methodical testing against ${target}.`,
      suggestedAction: 'Analyze response body and formulate next logical probe.'
    };
  }
}
