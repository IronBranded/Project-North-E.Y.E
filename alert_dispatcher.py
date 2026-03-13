"""
North E.Y.E. — Alert Dispatcher
Fires real-time notifications for HIGH severity events via:
  - Slack webhook
  - Email (via SendGrid or SMTP)
  - Discord webhook (optional)
  - Microsoft Teams webhook (optional)

Runs as the final post-commit step in the GitHub Actions pipeline.
Only fires for newly added HIGH severity threats (not re-alerts on existing ones).

USAGE:
    python alert_dispatcher.py \
        --threats threats.json \
        --previous previous_threat_ids.txt \
        --channels slack,email
"""

import argparse
import json
import os
import smtplib
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

# ── SEVERITY FILTER ──────────────────────────────────────────────────
ALERT_SEVERITIES = {"high"}  # Only alert on HIGH by default

# ── CATEGORY ICONS ───────────────────────────────────────────────────
CATEGORY_EMOJI = {
    "cyber":    "🔴",
    "fincrime": "🟡",
}

SUBCATEGORY_EMOJI = {
    "ransomware":               "🔒",
    "data-breach":              "💾",
    "ddos":                     "⚡",
    "business-email-compromise":"📧",
    "phishing-campaign":        "🎣",
    "ai-attack":                "🤖",
    "large-data-leak":          "🗄️",
    "money-laundering":         "💸",
    "crypto-crime":             "🪙",
    "banking-malware":          "📱",
    "elder-abuse":              "👴",
    "cyber-fraud":              "🎭",
    "scams":                    "📞",
}


def load_previous_ids(path: str) -> set:
    """Load set of previously alerted threat IDs."""
    try:
        with open(path) as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()


def save_alerted_ids(path: str, ids: set):
    """Save the full set of alerted IDs for future dedup."""
    with open(path, "w") as f:
        for tid in sorted(ids):
            f.write(tid + "\n")


def build_slack_block(threat: dict, dashboard_url: str) -> dict:
    """Build a rich Slack Block Kit message for a threat."""
    cat_emoji = CATEGORY_EMOJI.get(threat.get("category", ""), "🔴")
    sub_emoji = SUBCATEGORY_EMOJI.get(threat.get("subcategory", "").lower().replace(" ", "-"), "⚠️")
    severity  = threat.get("severity", "").upper()
    province  = threat.get("province", "Unknown")
    score     = threat.get("threat_score", 0)
    iocs      = threat.get("iocs", [])[:3]
    sig_srcs  = threat.get("signal_sources", [])

    ioc_text = "\n".join(
        f"`{i['type']}` {i['val']}" for i in iocs
    ) if iocs else "_No IOCs extracted_"

    sig_text = ", ".join(
        f"@{s['handle']} ({s['type'].upper()})" for s in sig_srcs
    ) if sig_srcs else "_Internal validation_"

    council = threat.get("council_votes", {})
    council_text = " · ".join(
        f"{'✅' if v else '❌'} {k.upper()}"
        for k, v in council.items()
    )

    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{cat_emoji} {sub_emoji} NORTH E.Y.E. ALERT — {severity} SEVERITY",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{threat.get('title', 'Unknown Threat')}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Province*\n{province}"},
                    {"type": "mrkdwn", "text": f"*Category*\n{threat.get('category', '').upper()} / {threat.get('subcategory', '')}"},
                    {"type": "mrkdwn", "text": f"*Threat Score*\n{score}/100"},
                    {"type": "mrkdwn", "text": f"*Status*\n{threat.get('status', 'active').upper()}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Summary*\n{threat.get('summary', '_No summary available_')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IOCs*\n{ioc_text}"},
                    {"type": "mrkdwn", "text": f"*Signal Sources*\n{sig_text}"},
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"🤖 AI Council: {council_text}"},
                    {"type": "mrkdwn", "text": f"⏰ {threat.get('timestamp', '')[:19].replace('T', ' ')} UTC"},
                    {"type": "mrkdwn", "text": f"🆔 {threat.get('id', '')}"},
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🗺️ View on Map", "emoji": True},
                        "url": f"{dashboard_url}#{threat.get('id', '')}",
                        "style": "primary"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📋 Full Report", "emoji": True},
                        "url": f"{dashboard_url}",
                    }
                ]
            },
            {"type": "divider"}
        ]
    }


def build_teams_card(threat: dict, dashboard_url: str) -> dict:
    """Build a Microsoft Teams Adaptive Card message."""
    cat_emoji = CATEGORY_EMOJI.get(threat.get("category", ""), "🔴")
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"{cat_emoji} NORTH E.Y.E. — {threat.get('severity', '').upper()} SEVERITY",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention"
                        },
                        {
                            "type": "TextBlock",
                            "text": threat.get("title", ""),
                            "weight": "Bolder",
                            "wrap": True
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Province",   "value": threat.get("province", "")},
                                {"title": "Category",   "value": f"{threat.get('category', '').upper()} / {threat.get('subcategory', '')}"},
                                {"title": "Score",      "value": f"{threat.get('threat_score', 0)}/100"},
                                {"title": "Status",     "value": threat.get("status", "active").upper()},
                                {"title": "Event ID",   "value": threat.get("id", "")},
                            ]
                        },
                        {
                            "type": "TextBlock",
                            "text": threat.get("summary", ""),
                            "wrap": True,
                            "spacing": "Medium"
                        }
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "View on North E.Y.E. Map",
                            "url": dashboard_url
                        }
                    ]
                }
            }
        ]
    }


def build_email_html(threats: list, dashboard_url: str) -> str:
    """Build an HTML email digest for multiple HIGH severity threats."""
    rows = ""
    for t in threats:
        cat_emoji = CATEGORY_EMOJI.get(t.get("category", ""), "🔴")
        sub_emoji = SUBCATEGORY_EMOJI.get(t.get("subcategory", "").lower().replace(" ", "-"), "⚠️")
        iocs_html = "".join(
            f'<code style="background:#1a2840;color:#00c8ff;padding:2px 6px;border-radius:3px;font-size:11px;margin:2px 2px 0 0;display:inline-block;">{i["type"]}: {i["val"]}</code>'
            for i in t.get("iocs", [])[:4]
        )
        sigs_html = ", ".join(f'@{s["handle"]}' for s in t.get("signal_sources", []))

        rows += f"""
        <div style="background:#0c1628;border:1px solid rgba(255,32,64,0.3);border-left:3px solid #ff2040;border-radius:6px;padding:16px;margin-bottom:16px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <span style="background:rgba(255,32,64,0.15);color:#ff2040;border:1px solid rgba(255,32,64,0.3);padding:2px 8px;border-radius:3px;font-size:10px;font-family:monospace;letter-spacing:1px;font-weight:700;">{t.get('category','').upper()}</span>
            <span style="background:rgba(255,32,64,0.1);color:#ff2040;padding:2px 8px;border-radius:3px;font-size:10px;font-family:monospace;">{t.get('severity','').upper()}</span>
            <span style="color:#5a7a9a;font-family:monospace;font-size:10px;margin-left:auto;">{t.get('id','')}</span>
          </div>
          <h3 style="color:#c8d8f0;margin:0 0 8px;font-size:14px;">{cat_emoji} {sub_emoji} {t.get('title','')}</h3>
          <p style="color:#5a7a9a;font-size:12px;margin:0 0 10px;"><strong style="color:#00c8ff;">◈</strong> {t.get('province','Canada')} · Threat Score: <strong style="color:#ffb800;">{t.get('threat_score',0)}/100</strong></p>
          <p style="color:#8aa0c0;font-size:12px;line-height:1.6;margin:0 0 10px;">{t.get('summary','')}</p>
          {f'<div style="margin-bottom:8px;">{iocs_html}</div>' if iocs_html else ''}
          {f'<p style="color:#2a4060;font-size:10px;font-family:monospace;margin:0;">Signals: {sigs_html}</p>' if sigs_html else ''}
        </div>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>North E.Y.E. — High Severity Alert</title></head>
<body style="background:#020912;font-family:'Segoe UI',Arial,sans-serif;color:#c8d8f0;padding:24px;max-width:680px;margin:0 auto;">
  <div style="border-bottom:1px solid rgba(0,200,255,0.2);padding-bottom:16px;margin-bottom:24px;">
    <h1 style="color:#00c8ff;font-family:monospace;letter-spacing:4px;font-size:18px;margin:0;">🍁 NORTH E.Y.E.</h1>
    <p style="color:#5a7a9a;font-family:monospace;font-size:10px;letter-spacing:2px;margin:4px 0 0;">ELECTRONIC YIELD EXCHANGE · HIGH SEVERITY ALERT DIGEST</p>
    <p style="color:#2a4060;font-family:monospace;font-size:9px;margin:4px 0 0;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · {len(threats)} new event{'s' if len(threats) != 1 else ''}</p>
  </div>

  {rows}

  <div style="text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid rgba(0,200,255,0.1);">
    <a href="{dashboard_url}" style="background:rgba(0,200,255,0.1);color:#00c8ff;border:1px solid rgba(0,200,255,0.3);padding:10px 24px;border-radius:4px;text-decoration:none;font-family:monospace;font-size:11px;letter-spacing:2px;">
      🗺️ VIEW LIVE MAP
    </a>
    <p style="color:#2a4060;font-size:10px;font-family:monospace;margin-top:16px;">
      North E.Y.E. is an open-source Canadian CTI project.<br>
      Unsubscribe: set ALERT_EMAIL_ENABLED=false in your GitHub secrets.
    </p>
  </div>
</body>
</html>"""


def dispatch_slack(webhook_url: str, threat: dict, dashboard_url: str) -> bool:
    """Send a single threat alert to Slack."""
    payload = build_slack_block(threat, dashboard_url)
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        print(f"    Slack error: {e}")
        return False


def dispatch_teams(webhook_url: str, threat: dict, dashboard_url: str) -> bool:
    """Send a single threat alert to Microsoft Teams."""
    payload = build_teams_card(threat, dashboard_url)
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code in (200, 202)
    except Exception as e:
        print(f"    Teams error: {e}")
        return False


def dispatch_discord(webhook_url: str, threat: dict, dashboard_url: str) -> bool:
    """Send a threat alert to Discord."""
    cat_emoji = CATEGORY_EMOJI.get(threat.get("category", ""), "🔴")
    payload = {
        "embeds": [{
            "title": f"{cat_emoji} {threat.get('title', 'Threat Alert')[:256]}",
            "description": threat.get("summary", "")[:4096],
            "color": 0xFF2040 if threat.get("category") == "cyber" else 0xFFB800,
            "fields": [
                {"name": "Province",     "value": threat.get("province", "?"),        "inline": True},
                {"name": "Category",     "value": threat.get("subcategory", "?"),     "inline": True},
                {"name": "Score",        "value": f"{threat.get('threat_score',0)}/100", "inline": True},
                {"name": "Event ID",     "value": f"`{threat.get('id', '?')}`",       "inline": False},
            ],
            "footer": {"text": "North E.Y.E. — Canadian CTI Dashboard"},
            "timestamp": threat.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "url": dashboard_url
        }]
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"    Discord error: {e}")
        return False


def dispatch_email(smtp_config: dict, to_addresses: list, threats: list, dashboard_url: str) -> bool:
    """Send an email digest for multiple HIGH severity threats."""
    if not threats:
        return True

    html_body = build_email_html(threats, dashboard_url)
    subject = f"🍁 North E.Y.E. Alert — {len(threats)} HIGH Severity Threat{'s' if len(threats) != 1 else ''} Detected"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_config.get("from_address", "northeye@example.com")
    msg["To"]      = ", ".join(to_addresses)

    # Plain text fallback
    plain_lines = [f"NORTH E.Y.E. — HIGH SEVERITY ALERT\n{'─'*40}"]
    for t in threats:
        plain_lines.append(f"\n[{t.get('id')}] {t.get('title', '')}")
        plain_lines.append(f"Province: {t.get('province')} | Score: {t.get('threat_score',0)}/100")
        plain_lines.append(t.get("summary", ""))

    plain_lines.append(f"\nView map: {dashboard_url}")
    msg.attach(MIMEText("\n".join(plain_lines), "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        host = smtp_config.get("host", "smtp.sendgrid.net")
        port = int(smtp_config.get("port", 587))
        user = smtp_config.get("username", "apikey")
        pwd  = smtp_config.get("password", "")

        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(user, pwd)
            server.sendmail(msg["From"], to_addresses, msg.as_string())

        print(f"    ✅ Email sent to {len(to_addresses)} recipients")
        return True

    except Exception as e:
        print(f"    ❌ Email error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="North E.Y.E. Alert Dispatcher")
    parser.add_argument("--threats",   required=True, help="threats.json")
    parser.add_argument("--previous",  default="alerted_ids.txt", help="Previously alerted IDs file")
    parser.add_argument("--channels",  default="slack", help="Comma-separated: slack,email,discord,teams")
    parser.add_argument("--min-score", type=int, default=50, help="Minimum threat score to alert (0–100)")
    args = parser.parse_args()

    channels = [c.strip().lower() for c in args.channels.split(",")]

    # Config from environment
    slack_webhook   = os.environ.get("SLACK_WEBHOOK_URL", "")
    teams_webhook   = os.environ.get("TEAMS_WEBHOOK_URL", "")
    discord_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "")
    dashboard_url   = os.environ.get("DASHBOARD_URL", "https://your-org.github.io/north-eye/")
    alert_emails    = [e.strip() for e in os.environ.get("ALERT_EMAILS", "").split(",") if e.strip()]

    smtp_config = {
        "host":         os.environ.get("SMTP_HOST",     "smtp.sendgrid.net"),
        "port":         os.environ.get("SMTP_PORT",     "587"),
        "username":     os.environ.get("SMTP_USERNAME", "apikey"),
        "password":     os.environ.get("SMTP_PASSWORD", ""),
        "from_address": os.environ.get("SMTP_FROM",     "northeye-alerts@yourdomain.com"),
    }

    # Load threats
    with open(args.threats) as f:
        data = json.load(f)
    all_threats = data.get("threats", [])

    # Load previously alerted IDs
    previous_ids = load_previous_ids(args.previous)

    # Find new HIGH severity threats not yet alerted
    new_threats = [
        t for t in all_threats
        if t.get("id") not in previous_ids
        and t.get("severity") in ALERT_SEVERITIES
        and t.get("threat_score", 0) >= args.min_score
    ]

    if not new_threats:
        print("✅ Alert Dispatcher: No new HIGH severity events to dispatch")
        return

    print(f"Alert Dispatcher: {len(new_threats)} new HIGH severity events")
    print(f"Channels: {channels}")
    print("─" * 60)

    dispatched_ids = set(previous_ids)
    email_batch = []

    for threat in new_threats:
        tid = threat.get("id", "")
        print(f"  → {tid}: {threat.get('title', '')[:60]}...")

        success = False

        if "slack" in channels and slack_webhook:
            ok = dispatch_slack(slack_webhook, threat, dashboard_url)
            print(f"    Slack: {'✅' if ok else '❌'}")
            success = success or ok

        if "teams" in channels and teams_webhook:
            ok = dispatch_teams(teams_webhook, threat, dashboard_url)
            print(f"    Teams: {'✅' if ok else '❌'}")
            success = success or ok

        if "discord" in channels and discord_webhook:
            ok = dispatch_discord(discord_webhook, threat, dashboard_url)
            print(f"    Discord: {'✅' if ok else '❌'}")
            success = success or ok

        if "email" in channels:
            email_batch.append(threat)
            success = True

        if success:
            dispatched_ids.add(tid)

        import time
        time.sleep(0.5)

    # Send email digest (batched, not per-threat)
    if "email" in channels and email_batch and alert_emails:
        ok = dispatch_email(smtp_config, alert_emails, email_batch, dashboard_url)
        if not ok:
            print("    ❌ Email digest failed")

    # Persist alerted IDs
    save_alerted_ids(args.previous, dispatched_ids)

    print(f"\n✅ Dispatched: {len(new_threats)} alerts across {channels}")


if __name__ == "__main__":
    main()
