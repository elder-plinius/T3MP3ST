/**
 * Security Event Webhook & SIEM Dispatcher
 * Inspired by Horizon3.ai NodeZero Integrations (Splunk, Sentinel, Jira, Slack, Discord)
 * Delivers real-time notifications for critical findings, tripwire triggers, and scan milestones.
 */

export type WebhookEventType = 'finding_discovered' | 'tripwire_triggered' | 'rapid_response_alert' | 'mission_milestone';

export interface WebhookPayload {
  event: WebhookEventType;
  title: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target?: string;
  details: string;
  proof?: string;
  metadata?: Record<string, any>;
  timestamp: string;
}

export class WebhookDispatcher {
  /**
   * Broadcast an event to all configured webhooks
   */
  public static async broadcast(payload: WebhookPayload): Promise<{ dispatched: number; errors: string[] }> {
    const discordUrl = process.env.DISCORD_WEBHOOK_URL;
    const slackUrl = process.env.SLACK_WEBHOOK_URL;
    const siemUrl = process.env.SIEM_WEBHOOK_URL;

    const dispatchPromises: Promise<any>[] = [];
    const errors: string[] = [];
    let dispatched = 0;

    if (discordUrl) {
      dispatchPromises.push(
        WebhookDispatcher.sendDiscord(discordUrl, payload)
          .then(() => dispatched++)
          .catch(err => errors.push(`Discord: ${err.message || err}`))
      );
    }

    if (slackUrl) {
      dispatchPromises.push(
        WebhookDispatcher.sendSlack(slackUrl, payload)
          .then(() => dispatched++)
          .catch(err => errors.push(`Slack: ${err.message || err}`))
      );
    }

    if (siemUrl) {
      dispatchPromises.push(
        WebhookDispatcher.sendSiem(siemUrl, payload)
          .then(() => dispatched++)
          .catch(err => errors.push(`SIEM: ${err.message || err}`))
      );
    }

    await Promise.allSettled(dispatchPromises);
    return { dispatched, errors };
  }

  private static async sendDiscord(url: string, payload: WebhookPayload): Promise<void> {
    const colorMap: Record<string, number> = {
      critical: 0xff0055, // red/magenta
      high: 0xff6600,     // orange
      medium: 0xffcc00,   // amber
      low: 0x00ccff,      // blue
      info: 0x00ff88      // green
    };

    const color = colorMap[payload.severity || 'info'] || 0x00ff88;

    const body = {
      username: 'T3MP3ST Security Swarm',
      avatar_url: 'https://raw.githubusercontent.com/elder-plinius/T3MP3ST/main/docs/favicon.svg',
      embeds: [
        {
          title: `[T3MP3ST] ${payload.title}`,
          description: payload.details,
          color,
          fields: [
            ...(payload.target ? [{ name: 'Target', value: `\`${payload.target}\``, inline: true }] : []),
            ...(payload.severity ? [{ name: 'Severity', value: payload.severity.toUpperCase(), inline: true }] : []),
            ...(payload.proof ? [{ name: 'Proof of Exploit', value: `\`\`\`\n${payload.proof.slice(0, 500)}\n\`\`\`` }] : [])
          ],
          footer: { text: `T3MP3ST Active Intelligence • ${payload.timestamp}` }
        }
      ]
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      throw new Error(`Discord returned status ${res.status}`);
    }
  }

  private static async sendSlack(url: string, payload: WebhookPayload): Promise<void> {
    const body = {
      text: `*🚨 [T3MP3ST Alert] ${payload.title}*\n*Severity:* ${payload.severity?.toUpperCase() || 'INFO'} | *Target:* ${payload.target || 'N/A'}\n>${payload.details}`
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      throw new Error(`Slack returned status ${res.status}`);
    }
  }

  private static async sendSiem(url: string, payload: WebhookPayload): Promise<void> {
    const body = {
      source: 'T3MP3ST_AUTONOMOUS_SECURITY_SWARM',
      event_type: payload.event,
      timestamp: payload.timestamp,
      severity: payload.severity || 'info',
      target: payload.target,
      title: payload.title,
      description: payload.details,
      proof: payload.proof,
      metadata: payload.metadata
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      throw new Error(`SIEM Webhook returned status ${res.status}`);
    }
  }
}
