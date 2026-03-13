# 🍁 Project North E.Y.E.
### Electronic Yield Exchange — Canadian Cyber Threat Intelligence Dashboard

> A fully serverless, open-source Canadian CTI platform. Transforms raw OSINT into a live visual threat map of Canada. Zero infrastructure — runs entirely on GitHub Actions + GitHub Pages.

---

## Live Architecture

```
X/Twitter Watchlist (22 accounts) ─┐
CCCS RSS Alerts                    │
CAFC Fraud Bulletins               ├─► Aggregator ─► AI Council (Gemini/GPT-4o/Claude)
FINTRAC Advisories                 │       │               │ 2/3 consensus vote
AlienVault OTX (CA-filtered)       │       │               ▼
CISA KEV Catalog                   │   raw_threats.json   validated_threats.json
ThreatFox / abuse.ch               │                       │
Chainabuse API (CA)                │                       ▼
HaveIBeenPwned (.ca breaches) ─────┘              synthesizer.py (Claude)
                                                           │
                                                           ▼
                                              TTL Manager (30d purge + merge)
                                                           │
                                             ┌─────────────┼─────────────┐
                                             ▼             ▼             ▼
                                       threats.json   stats.json   alerted_ids.txt
                                             │
                                     GitHub Pages ──► index.html (live map)
                                                           │
                                                    Alert Dispatcher
                                               (Slack / Teams / Discord / Email)
```

**Cost: ~$10–15 CAD/month** (API calls only — compute and hosting are free on GitHub)

---

## Features

### Dashboard (`index.html`)
- **SVG Canada Map** with 13 provinces/territories and real-time threat dots
- **Province Heatmap** — provinces glow red/amber based on active threat intensity
- **3-tab right panel:**
  - `⬡ EVENT INTEL` — IOCs, IOAs, AI Council votes, Signal Sources (actual X posts), AI summary
  - `◈ PROVINCE STATS` — national stats, 30-day sparkline, province ranking by threat count
  - `𝕏 SOURCES` — all 9 data source cards + full 22-account X watchlist
- **4-mode filter:** ALL / CYBER / FINCRIME / 𝕏 SIGNAL
- **Signal source badges** on every feed item: `GOV` `POLICE` `𝕏` `OSINT` `CHAIN`
- **Live search** across IOCs, provinces, tags, handles, post text
- **Keyboard shortcuts:** `1/2/3` switch tabs, `↑/↓` cycle threats, `Esc` clears search
- **Scrolling news ticker** with signal source attribution
- **X Watchlist mini panel** in map legend (top 5 by signal count)

---

## Pipeline Scripts

| Script | Stage | Description |
|--------|-------|-------------|
| `twitter_monitor.py` | 1 — Social Intel | Monitors 22 curated X accounts across 4 tiers |
| `aggregator.py` | 2 — OSINT Aggregation | Pulls 9 sources, merges X signals, CA filter |
| `council_node.py` | 3 — AI Council | Per-AI classification (Gemini / GPT-4o / Claude) |
| `consensus.py` | 4 — Consensus | 2-of-3 voting engine with severity tolerance |
| `synthesizer.py` | 5 — AI Synthesis | Claude writes tactical summaries + threat scores |
| `ttl_manager.py` | 6 — TTL Enforcement | Merges new threats, purges >30 days |
| `province_stats.py` | 7 — Statistics | Province heatmap intensity + 30d sparklines |
| `alert_dispatcher.py` | 8 — Alerts | Slack / Teams / Discord / Email for HIGH severity |

---

## X Watchlist (22 Accounts, 4 Tiers)

| Tier | Accounts | Auto-Confidence | Notes |
|------|----------|-----------------|-------|
| **GOV** | `@CybercentreCA` `@CAFC_ACFC` `@FINTRAC_Canada` `@PublicSafetyCA` `@cirnac_cirnac` | 88–95% | Auto-validated, no CA filter needed |
| **POLICE** | `@rcmpgrc` `@OPP_News` `@SureteDuQuebec` `@VancouverPD` `@TorontoPolice` `@calgarypolice` `@edmontonpolice` | 78–90% | Federal + provincial + municipal |
| **𝕏 EXPERTS** | `@zachxbt` `@GossiTheDog` `@MalwareMustDie` | 65–72% | Must pass Canadian relevance filter |
| **OSINT** | `@BleepinComputer` `@vxunderground` `@chainalysis` `@elliptic` `@trmlabs` `@threatpost` `@sansforensics` | 60–70% | CA keyword filter required |

---

## OSINT Feed Sources (9 Total)

| Source | Type | What It Provides |
|--------|------|-----------------|
| CCCS RSS | `GOV` | Official Canadian cyber alerts & advisories |
| CAFC Bulletins | `GOV` | Active fraud campaigns targeting Canadians |
| FINTRAC Advisories | `GOV` | AML typologies, virtual currency misuse |
| AlienVault OTX | `OSINT` | Global threat pulses filtered for Canadian context |
| CISA KEV | `GOV` | Known exploited vulnerabilities (CA-relevant vendors) |
| ThreatFox / abuse.ch | `OSINT` | Real-time malware IOCs (C2s, hashes, domains) |
| Chainabuse API | `BLOCKCHAIN` | Crypto scam reports filtered for Canadian activity |
| HaveIBeenPwned | `OSINT` | Breach detection for .ca domain organizations |
| X / Twitter Watchlist | `SOCIAL` | 22 curated accounts monitored hourly |

---

## Required GitHub Secrets

```
# AI Council
ANTHROPIC_API_KEY       # Claude (Sonnet for council + synthesis)
OPENAI_API_KEY          # GPT-4o council node
GEMINI_API_KEY          # Gemini 1.5 Pro council node

# Social Intel
TWITTER_BEARER_TOKEN    # X API v2 Bearer Token (free tier works)

# OSINT Feeds
ALIENVAULT_API_KEY      # AlienVault OTX (free registration)
CHAINABUSE_API_KEY      # Chainabuse API
HIBP_API_KEY            # HaveIBeenPwned API
CCCS_FEED_URL           # CCCS RSS feed URL (default: public)
CAFC_FEED_URL           # CAFC news URL (default: public)

# Alert Dispatch (optional — any combination)
SLACK_WEBHOOK_URL       # Slack incoming webhook
TEAMS_WEBHOOK_URL       # Microsoft Teams webhook
DISCORD_WEBHOOK_URL     # Discord webhook
ALERT_EMAILS            # Comma-separated email addresses
SMTP_HOST               # e.g. smtp.sendgrid.net
SMTP_PORT               # e.g. 587
SMTP_USERNAME           # e.g. apikey (SendGrid)
SMTP_PASSWORD           # SMTP/SendGrid API key
SMTP_FROM               # From address
DASHBOARD_URL           # https://your-org.github.io/north-eye/
```

---

## Quick Start

```bash
# 1. Fork / clone this repo
git clone https://github.com/your-org/north-eye.git
cd north-eye

# 2. Install Python dependencies
pip install -r scripts/requirements.txt

# 3. Set environment variables (copy .env.example)
cp .env.example .env
# Fill in your API keys

# 4. Run the pipeline manually
python scripts/twitter_monitor.py --output raw_x_threats.json --lookback-hours 24
python scripts/aggregator.py --output raw_threats.json --x-signals raw_x_threats.json
# ... (see workflow for full pipeline)

# 5. Push to GitHub — Actions handles the rest hourly
# 6. Enable GitHub Pages (Settings → Pages → Deploy from main branch)
# 7. Open https://your-org.github.io/north-eye/
```

---

## Threat Categories

| Category | Tags |
|----------|------|
| **CYBER** | `ransomware` `data-breach` `ddos` `business-email-compromise` `phishing-campaign` `ai-attack` `large-data-leak` `ics-scada` `supply-chain` |
| **FINCRIME** | `money-laundering` `crypto-crime` `banking-malware` `elder-abuse` `cyber-fraud` `scams` `pig-butchering` `rug-pull` `investment-fraud` |

---

## Roadmap

- **v1.1** — Province drill-down: click ON/QC/BC to see only that province's threats
- **v1.2** — STIX/TAXII export endpoint for security tooling integration
- **v1.3** — Canadian ISAC feed integration (FS-ISAC, H-ISAC, E-ISAC)
- **v1.4** — Threat actor profile pages (APT29, NoName057, BlackSuit, etc.)
- **v2.0** — Cross-border Canada/US/UK correlation (Five Eyes alignment)
- **v2.1** — Mobile PWA with push notifications for HIGH severity events

---

## License

MIT — Open source, no warranty. Not affiliated with any government entity.

Built with 🍁 for Canadian security professionals, researchers, and the public.
