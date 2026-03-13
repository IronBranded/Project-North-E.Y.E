"""
North E.Y.E. — X (Twitter) Monitor
Scrapes curated Canadian CTI accounts for threat signals using X API v2.
Produces a normalized list of candidate threat events for the AI Council.

WATCHLIST TIERS:
  Tier 1 — GOV:     Official Canadian government accounts (auto-high confidence)
  Tier 2 — POLICE:  Canadian federal + provincial + municipal police
  Tier 3 — X:       Domain experts (ZachXBT, etc.) — AI council validates
  Tier 4 — OSINT:   Cyber news + threat research accounts

USAGE:
  python twitter_monitor.py --output raw_x_threats.json --lookback-hours 2
"""

import argparse
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests

# ══════════════════════════════════════════════════════════════════════
# WATCHLIST — Curated Canadian CTI accounts
# Updated: 2025-07. Add/remove as relevance shifts.
# ══════════════════════════════════════════════════════════════════════
WATCHLIST = [

    # ── TIER 1: CANADIAN GOVERNMENT ──────────────────────────────────
    {
        "handle":   "CybercentreCA",
        "name":     "Canadian Centre for Cyber Security",
        "tier":     "gov",
        "auto_confidence": 0.95,
        "keywords": ["alert", "advisory", "ransomware", "threat", "breach", "malware",
                     "ddos", "phishing", "vulnerability", "incident", "IOC", "AV25"],
        "notes":    "Primary CCCS comms account. Treat alerts as auto-validated."
    },
    {
        "handle":   "CAFC_ACFC",
        "name":     "Canadian Anti-Fraud Centre",
        "tier":     "gov",
        "auto_confidence": 0.95,
        "keywords": ["fraud", "scam", "phishing", "elder", "grandparent", "investment",
                     "romance", "alert", "warning", "BEC", "gift card"],
        "notes":    "Key source for FinCrime / social engineering campaigns."
    },
    {
        "handle":   "FINTRAC_Canada",
        "name":     "FINTRAC",
        "tier":     "gov",
        "auto_confidence": 0.9,
        "keywords": ["money laundering", "PCMLTF", "typology", "virtual currency",
                     "suspicious", "sanctions", "advisory", "assessment"],
        "notes":    "Primary FinCrime financial intelligence authority."
    },
    {
        "handle":   "PublicSafetyCA",
        "name":     "Public Safety Canada",
        "tier":     "gov",
        "auto_confidence": 0.88,
        "keywords": ["cyber", "critical infrastructure", "national security", "RCMP",
                     "CSE", "incident", "threat"],
        "notes":    "Policy-level comms. Confirms major federal incidents."
    },
    {
        "handle":   "cirnac_cirnac",
        "name":     "CSE Canada (Signals Intelligence)",
        "tier":     "gov",
        "auto_confidence": 0.92,
        "keywords": ["cyber", "threat", "APT", "foreign", "espionage", "advisory"],
        "notes":    "CSE public alerts. Rare but extremely high signal."
    },

    # ── TIER 2: CANADIAN POLICE ───────────────────────────────────────
    {
        "handle":   "rcmpgrc",
        "name":     "RCMP (National)",
        "tier":     "police",
        "auto_confidence": 0.90,
        "keywords": ["cyber", "fraud", "arrest", "charges", "investigation", "warning",
                     "money laundering", "crypto", "scam"],
        "notes":    "National RCMP. Watch for press releases on cyber/financial busts."
    },
    {
        "handle":   "OPP_News",
        "name":     "Ontario Provincial Police",
        "tier":     "police",
        "auto_confidence": 0.85,
        "keywords": ["cyber", "fraud", "scam", "elder", "phishing", "ransomware",
                     "arrest", "investigation", "warning"],
        "notes":    "High volume. Filter aggressively for cyber/fincrime only."
    },
    {
        "handle":   "SureteDuQuebec",
        "name":     "Sûreté du Québec",
        "tier":     "police",
        "auto_confidence": 0.85,
        "keywords": ["fraude", "cyber", "arnaque", "aîné", "enquête", "alerte",
                     "fraud", "scam", "arrest"],
        "notes":    "French-language. AI Council must handle bilingual content."
    },
    {
        "handle":   "VancouverPD",
        "name":     "Vancouver Police Department",
        "tier":     "police",
        "auto_confidence": 0.82,
        "keywords": ["fraud", "scam", "cyber", "money laundering", "arrest",
                     "warning", "cryptocurrency"],
        "notes":    "BC financial crime and fraud alerts."
    },
    {
        "handle":   "TorontoPolice",
        "name":     "Toronto Police Service",
        "tier":     "police",
        "auto_confidence": 0.82,
        "keywords": ["fraud", "cyber", "scam", "elder", "phishing", "ransomware",
                     "BEC", "arrest", "warning"],
        "notes":    "High volume. TPS financial crimes unit posts frequently."
    },
    {
        "handle":   "calgarypolice",
        "name":     "Calgary Police Service",
        "tier":     "police",
        "auto_confidence": 0.78,
        "keywords": ["fraud", "scam", "cyber", "cryptocurrency", "warning"],
        "notes":    "Alberta-specific fraud and financial crime."
    },
    {
        "handle":   "edmontonpolice",
        "name":     "Edmonton Police Service",
        "tier":     "police",
        "auto_confidence": 0.78,
        "keywords": ["fraud", "scam", "cyber", "cryptocurrency", "warning"],
        "notes":    "Alberta-specific fraud and financial crime."
    },

    # ── TIER 3: X DOMAIN EXPERTS (highest-signal individual researchers) ──
    {
        "handle":   "zachxbt",
        "name":     "ZachXBT",
        "tier":     "x",
        "auto_confidence": 0.72,
        "keywords": ["canada", "canadian", ".ca", "CAD", "scam", "rug pull",
                     "fraud", "laundering", "stolen", "victim", "traced", "blockchain"],
        "notes":    "Premier on-chain investigator. Must filter for Canadian relevance. "
                    "Threads often contain wallet IOCs — extract automatically."
    },
    {
        "handle":   "GossiTheDog",
        "name":     "Kevin Beaumont",
        "tier":     "x",
        "auto_confidence": 0.70,
        "keywords": ["canada", "canadian", "ransomware", "breach", "APT", "CVE",
                     "RDP", "Fortinet", "critical infrastructure"],
        "notes":    "Senior threat researcher with strong Canada coverage. "
                    "Often breaks incidents before official advisories."
    },
    {
        "handle":   "MalwareMustDie",
        "name":     "MalwareMustDie!",
        "tier":     "x",
        "auto_confidence": 0.65,
        "keywords": ["canada", "canadian", "malware", "trojan", "RAT", "botnet",
                     "C2", "IOC", "banking", "infostealer"],
        "notes":    "Technical malware analysis. Often first to name new Canadian-targeted trojans."
    },

    # ── TIER 4: OSINT / CYBER NEWS ────────────────────────────────────
    {
        "handle":   "BleepinComputer",
        "name":     "BleepingComputer",
        "tier":     "osint",
        "auto_confidence": 0.68,
        "keywords": ["canada", "canadian", ".ca", "CAD", "ransomware", "breach",
                     "data leak", "malware", "phishing"],
        "notes":    "High-quality reporting. Filter strictly for Canadian mentions."
    },
    {
        "handle":   "vxunderground",
        "name":     "vx-underground",
        "tier":     "osint",
        "auto_confidence": 0.60,
        "keywords": ["canada", "canadian", "ransomware", "breach", "darkweb",
                     "BreachForums", "leak", "stolen", "database"],
        "notes":    "Dark web intelligence. Monitor for Canadian victim listings."
    },
    {
        "handle":   "threatpost",
        "name":     "Threatpost",
        "tier":     "osint",
        "auto_confidence": 0.62,
        "keywords": ["canada", "canadian", "ransomware", "APT", "breach", "phishing",
                     "vulnerability", "exploit"],
        "notes":    "General cyber news — filter for Canada."
    },
    {
        "handle":   "chainalysis",
        "name":     "Chainalysis",
        "tier":     "osint",
        "auto_confidence": 0.70,
        "keywords": ["canada", "canadian", "ransomware", "crypto crime", "FINTRAC",
                     "laundering", "sanctions", "rug pull", "scam"],
        "notes":    "Blockchain analytics firm. Often corroborates ZachXBT findings."
    },
    {
        "handle":   "elliptic",
        "name":     "Elliptic",
        "tier":     "osint",
        "auto_confidence": 0.68,
        "keywords": ["canada", "canadian", "crypto", "sanctions", "laundering",
                     "darknet", "ransomware"],
        "notes":    "Crypto intelligence. Good for FinCrime cross-reference."
    },
    {
        "handle":   "trmlabs",
        "name":     "TRM Labs",
        "tier":     "osint",
        "auto_confidence": 0.65,
        "keywords": ["canada", "FINTRAC", "crypto", "sanctions", "AML", "fraud"],
        "notes":    "Crypto compliance intelligence."
    },
    {
        "handle":   "ransomwarelive",
        "name":     "Ransomware.live",
        "tier":     "osint",
        "auto_confidence": 0.70,
        "keywords": [
            "canada", "canadian", ".ca", 
            "alberta", "british columbia", "manitoba", "new brunswick", 
            "newfoundland", "nova scotia", "ontario", "prince edward island", 
            "quebec", "saskatchewan", "northwest territories", "nunavut", "yukon",
            "AB", "BC", "MB", "NB", "NL", "NS", "ON", "PE", "QC", "SK", "NT", "NU", "YT"
        ],
        "notes":    "Real-time ransomware victim tracking. Comprehensive provincial keyword filter applied."
    },
    {
        "handle":   "sansforensics",
        "name":     "SANS Institute",
        "tier":     "osint",
        "auto_confidence": 0.60,
        "keywords": ["canada", "canadian", "IOC", "ransomware", "APT", "incident",
                     "advisory"],
        "notes":    "Educational but posts IOCs and analysis. Filter for Canada."
    },
]

# ── IOC EXTRACTION PATTERNS ────────────────────────────────────────────
IOC_PATTERNS = {
    "IP":     r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "DOMAIN": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:ca|com|net|org|onion|io|xyz)\b',
    "HASH":   r'\b[a-fA-F0-9]{32,64}\b',
    "WALLET": r'\b0x[a-fA-F0-9]{40}\b',
    "CVE":    r'CVE-\d{4}-\d{4,7}',
    "EMAIL":  r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
}

# ── CANADIAN RELEVANCE SIGNALS ──────────────────────────────────────────
CANADIAN_SIGNALS = [
    "canada", "canadian", ".ca", "CAD", "ontario", "quebec", "british columbia",
    "alberta", "saskatchewan", "manitoba", "nova scotia", "new brunswick",
    "newfoundland", "pei", "yukon", "northwest territories", "nunavut",
    "toronto", "vancouver", "montreal", "ottawa", "calgary", "edmonton",
    "winnipeg", "halifax", "RCMP", "OPP", "CCCS", "CAFC", "FINTRAC",
    "CRA", "TSX", "RBC", "TD Bank", "BMO", "Scotiabank", "CIBC", "National Bank",
    "Healthcare Canada", "GOC", "Government of Canada"
]


class XMonitor:
    def __init__(self, bearer_token: str):
        self.bearer_token = bearer_token
        self.base_url = "https://api.twitter.com/2"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": "NorthEYE-CTI-Monitor/1.0"
        })

    def get_user_id(self, handle: str) -> str | None:
        """Resolve @handle to numeric user ID."""
        resp = self.session.get(
            f"{self.base_url}/users/by/username/{handle}",
            params={"user.fields": "id,name,verified"}
        )
        if resp.status_code == 200:
            return resp.json()["data"]["id"]
        return None

    def get_recent_tweets(self, user_id: str, since_time: datetime, max_results: int = 20) -> list:
        """Fetch recent tweets from a user."""
        params = {
            "max_results": min(max_results, 100),
            "start_time": since_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tweet.fields": "created_at,text,entities,public_metrics",
            "exclude": "retweets,replies"
        }
        resp = self.session.get(
            f"{self.base_url}/users/{user_id}/tweets",
            params=params
        )
        if resp.status_code == 200:
            return resp.json().get("data", [])
        elif resp.status_code == 429:
            print(f"  Rate limited. Sleeping 15 minutes...")
            time.sleep(900)
            return self.get_recent_tweets(user_id, since_time, max_results)
        else:
            print(f"  Error {resp.status_code}: {resp.text[:200]}")
            return []

    def extract_iocs(self, text: str) -> list:
        """Extract IOCs from tweet text using regex patterns."""
        iocs = []
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Filter out common false positives
                if ioc_type == "IP" and match.startswith(("127.", "10.", "192.168.", "172.")):
                    continue
                if ioc_type == "DOMAIN" and len(match) < 6:
                    continue
                iocs.append({"type": ioc_type, "val": match})
        return iocs

    def is_canadian_relevant(self, text: str) -> bool:
        """Check if tweet contains Canadian relevance signals."""
        text_lower = text.lower()
        return any(sig.lower() in text_lower for sig in CANADIAN_SIGNALS)

    def keyword_match(self, text: str, keywords: list) -> bool:
        """Check if tweet matches account-specific keywords."""
        text_lower = text.lower()
        return any(kw.lower() in text_lower for kw in keywords)

    def process_account(self, account: dict, lookback_hours: int) -> list:
        """Process a single watchlist account and return candidate events."""
        handle = account["handle"]
        print(f"  Processing @{handle} ({account['tier'].upper()})...")

        # Resolve user ID
        user_id = self.get_user_id(handle)
        if not user_id:
            print(f"    ⚠️  Could not resolve @{handle}")
            return []

        since_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        tweets = self.get_recent_tweets(user_id, since_time, max_results=20)

        if not tweets:
            print(f"    → No new tweets")
            return []

        candidates = []
        for tweet in tweets:
            text = tweet.get("text", "")

            # Tier 1 & 2 (gov/police): always process if keyword match
            # Tier 3 & 4 (x/osint): must also have Canadian relevance
            keyword_hit = self.keyword_match(text, account["keywords"])
            if not keyword_hit:
                continue

            if account["tier"] in ("x", "osint"):
                if not self.is_canadian_relevant(text):
                    continue

            # Extract IOCs
            iocs = self.extract_iocs(text)

            candidate = {
                "id": f"X-{handle}-{tweet['id']}",
                "source_type": "social",
                "signal_source": {
                    "type": account["tier"],
                    "handle": handle,
                    "name": account["name"],
                    "verified": True,  # Will be enriched by user.fields
                    "time": tweet.get("created_at", ""),
                    "text": text,
                    "signal_url": f"https://twitter.com/{handle}/status/{tweet['id']}"
                },
                "raw_text": text,
                "iocs": iocs,
                "auto_confidence": account["auto_confidence"],
                "tier": account["tier"],
                "timestamp": tweet.get("created_at", ""),
                "metrics": tweet.get("public_metrics", {}),
                "requires_council": account["tier"] not in ("gov",)
            }
            candidates.append(candidate)

        print(f"    → {len(candidates)} candidates from @{handle}")

        # Respectful rate limiting between accounts
        time.sleep(1.5)
        return candidates


def main():
    parser = argparse.ArgumentParser(description="North E.Y.E. X Monitor")
    parser.add_argument("--output", required=True, help="Output raw_x_threats.json")
    parser.add_argument("--lookback-hours", type=int, default=2, help="Hours to look back")
    parser.add_argument("--tier-filter", choices=["gov", "police", "x", "osint", "all"],
                        default="all", help="Only process accounts of this tier")
    args = parser.parse_args()

    bearer_token = os.environ.get("TWITTER_BEARER_TOKEN") or os.environ.get("X_BEARER_TOKEN")
    if not bearer_token:
        raise EnvironmentError("TWITTER_BEARER_TOKEN or X_BEARER_TOKEN not set in environment")

    monitor = XMonitor(bearer_token)

    accounts_to_process = WATCHLIST if args.tier_filter == "all" else [
        a for a in WATCHLIST if a["tier"] == args.tier_filter
    ]

    print(f"North E.Y.E. X Monitor")
    print(f"Lookback: {args.lookback_hours}h | Accounts: {len(accounts_to_process)}")
    print("─" * 60)

    all_candidates = []
    total_gov    = 0
    total_police = 0
    total_x      = 0
    total_osint  = 0

    for account in accounts_to_process:
        candidates = monitor.process_account(account, args.lookback_hours)
        all_candidates.extend(candidates)
        tier = account["tier"]
        if tier == "gov":    total_gov    += len(candidates)
        if tier == "police": total_police += len(candidates)
        if tier == "x":      total_x      += len(candidates)
        if tier == "osint":  total_osint  += len(candidates)

    # Deduplicate by tweet text similarity (basic)
    seen_texts = set()
    unique_candidates = []
    for c in all_candidates:
        text_key = c["raw_text"][:100].lower().strip()
        if text_key not in seen_texts:
            seen_texts.add(text_key)
            unique_candidates.append(c)

    # Output
    output = {
        "meta": {
            "source": "X (Twitter) Watchlist Monitor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lookback_hours": args.lookback_hours,
            "accounts_monitored": len(accounts_to_process),
            "total_candidates": len(unique_candidates),
            "breakdown": {
                "gov": total_gov,
                "police": total_police,
                "x_experts": total_x,
                "osint": total_osint
            },
            "watchlist": [{"handle": a["handle"], "tier": a["tier"]} for a in WATCHLIST]
        },
        "candidates": unique_candidates
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'─' * 60}")
    print(f"✅ X Monitor Complete")
    print(f"   Gov signals    : {total_gov}")
    print(f"   Police signals : {total_police}")
    print(f"   X experts      : {total_x}")
    print(f"   OSINT          : {total_osint}")
    print(f"   Unique total   : {len(unique_candidates)}")
    print(f"   → {args.output}")


if __name__ == "__main__":
    main()
