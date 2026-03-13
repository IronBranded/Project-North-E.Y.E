"""
North E.Y.E. — Master OSINT Aggregator
Pulls from ALL configured sources and merges into a single raw_threats.json
for the AI Council to process.

SOURCES:
  1.  CCCS RSS          — Canadian Centre for Cyber Security alerts
  2.  CAFC Bulletins    — Canadian Anti-Fraud Centre news
  3.  FINTRAC           — Financial crime advisories
  4.  AlienVault OTX    — Global threat pulses (filtered: Canada)
  5.  CISA KEV          — Known Exploited Vulnerabilities (JSON feed)
  6.  URLhaus / ThreatFox — Real-time malware IOCs (abuse.ch)
  7.  Chainabuse API    — Crypto scam + fraud reports
  8.  OFAC SDN List     — Sanctions cross-reference
  9.  HaveIBeenPwned    — Canadian .ca breach detection
  10. X / Twitter       — Social signals (via twitter_monitor.py output)

All sources pass through a Canadian relevance filter before output.
"""

import argparse
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

# ── CANADIAN RELEVANCE FILTER ──────────────────────────────────────────
CANADIAN_KEYWORDS = [
    "canada", "canadian", ".ca", "cad$", "cad ", "ontario", "quebec", "québec",
    "british columbia", "alberta", "saskatchewan", "manitoba", "nova scotia",
    "new brunswick", "newfoundland", "yukon", "nunavut", "northwest territories",
    "toronto", "vancouver", "montreal", "montréal", "ottawa", "calgary", "edmonton",
    "winnipeg", "halifax", "rcmp", "opp", "cccs", "cafc", "fintrac", "cse canada",
    "cra", "government of canada", "tsx", "rbc", "td bank", "bmo", "scotiabank",
    "cibc", "national bank of canada", "bell canada", "rogers", "telus", "shopify",
    "canada post", "service canada", "healthcare canada",
]

def is_canadian(text: str) -> bool:
    text_l = (text or "").lower()
    return any(kw in text_l for kw in CANADIAN_KEYWORDS)

def safe_get(url: str, headers: dict = None, params: dict = None,
             timeout: int = 20, retries: int = 2) -> Optional[requests.Response]:
    """HTTP GET with retry logic."""
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                print(f"    ⚠️  Failed: {url} — {e}")
    return None


# ══════════════════════════════════════════════════════════════════════
# SOURCE 1: CCCS RSS ALERTS
# ══════════════════════════════════════════════════════════════════════
def pull_cccs_rss(cccs_feed_url: str = None) -> list:
    """Pull CCCS alerts and advisories RSS feed."""
    url = cccs_feed_url or "https://cyber.gc.ca/webservice/en/rss/alerts"
    print(f"  [CCCS] Pulling RSS feed...")

    resp = safe_get(url)
    if not resp:
        return []

    events = []
    try:
        root = ET.fromstring(resp.text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}

        # Try Atom format first, fall back to RSS
        items = root.findall(".//item")
        if not items:
            items = root.findall(".//atom:entry", ns)

        for item in items:
            title = item.findtext("title") or item.findtext("atom:title", namespaces=ns) or ""
            description = item.findtext("description") or item.findtext("atom:summary", namespaces=ns) or ""
            link = item.findtext("link") or item.findtext("atom:link", namespaces=ns) or ""
            pub_date = item.findtext("pubDate") or item.findtext("atom:published", namespaces=ns) or ""

            combined = f"{title} {description}"

            events.append({
                "id": f"CCCS-{hash(title) & 0xFFFFFF:06x}",
                "source": "CCCS",
                "source_type": "gov_rss",
                "title": title.strip(),
                "description": description.strip()[:2000],
                "url": link,
                "timestamp": pub_date,
                "is_canadian": True,  # CCCS is always Canadian
                "auto_confidence": 0.95,
                "raw_text": combined
            })
    except ET.ParseError as e:
        print(f"    ⚠️  CCCS XML parse error: {e}")

    print(f"    → {len(events)} CCCS events")
    return events


# ══════════════════════════════════════════════════════════════════════
# SOURCE 2: CAFC BULLETINS (web scrape)
# ══════════════════════════════════════════════════════════════════════
def pull_cafc_bulletins(cafc_url: str = None) -> list:
    """Pull CAFC news releases and fraud alerts."""
    url = cafc_url or "https://www.antifraudcentre-centreantifraude.ca/news-nouvelles/index-eng.htm"
    print(f"  [CAFC] Pulling bulletins...")

    resp = safe_get(url)
    if not resp:
        return []

    # Extract h2/h3 titles and adjacent text via simple parsing
    events = []
    text = resp.text

    # Find news items — basic pattern extraction
    titles = re.findall(r'<h[23][^>]*>(.*?)</h[23]>', text, re.DOTALL)
    for title in titles[:20]:  # Last 20 items
        clean_title = re.sub(r'<[^>]+>', '', title).strip()
        if len(clean_title) < 10:
            continue
        events.append({
            "id": f"CAFC-{hash(clean_title) & 0xFFFFFF:06x}",
            "source": "CAFC",
            "source_type": "gov_web",
            "title": clean_title,
            "description": f"Canadian Anti-Fraud Centre bulletin: {clean_title}",
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_canadian": True,
            "auto_confidence": 0.92,
            "raw_text": clean_title
        })

    print(f"    → {len(events)} CAFC events")
    return events


# ══════════════════════════════════════════════════════════════════════
# SOURCE 3: ALIENVAULT OTX
# ══════════════════════════════════════════════════════════════════════
def pull_alienvault_otx(api_key: str) -> list:
    """Pull AlienVault OTX pulses tagged with Canadian relevance."""
    if not api_key:
        print(f"  [OTX] No API key — skipping")
        return []

    print(f"  [OTX] Pulling Canadian-relevant pulses...")
    headers = {"X-OTX-API-KEY": api_key}
    events = []

    # Search for pulses with Canadian tags
    search_terms = ["Canada", "Ransomware Canada", "Canada phishing", "Canadian bank"]
    for term in search_terms:
        resp = safe_get(
            "https://otx.alienvault.com/api/v1/pulses/search",
            headers=headers,
            params={"q": term, "sort": "-modified", "limit": 10, "page": 1}
        )
        if not resp:
            continue

        data = resp.json()
        for pulse in data.get("results", []):
            title = pulse.get("name", "")
            description = pulse.get("description", "") or ""
            tags = pulse.get("tags", [])
            combined = f"{title} {description} {' '.join(tags)}"

            if not is_canadian(combined):
                continue

            # Extract IOCs from pulse indicators
            iocs = []
            for indicator in pulse.get("indicators", [])[:10]:
                ioc_type = indicator.get("type", "").upper()
                ioc_val = indicator.get("indicator", "")
                if ioc_type and ioc_val:
                    iocs.append({"type": ioc_type, "val": ioc_val})

            events.append({
                "id": f"OTX-{pulse.get('id', hash(title) & 0xFFFFFF)}",
                "source": "AlienVault OTX",
                "source_type": "osint_api",
                "title": title,
                "description": description[:2000],
                "tags": tags,
                "iocs": iocs,
                "url": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                "timestamp": pulse.get("modified", ""),
                "is_canadian": True,
                "auto_confidence": 0.72,
                "raw_text": combined
            })

        time.sleep(0.5)

    # Deduplicate
    seen = set()
    unique = []
    for e in events:
        if e["id"] not in seen:
            seen.add(e["id"])
            unique.append(e)

    print(f"    → {len(unique)} OTX events (Canada-filtered)")
    return unique


# ══════════════════════════════════════════════════════════════════════
# SOURCE 4: CISA KNOWN EXPLOITED VULNERABILITIES (KEV)
# ══════════════════════════════════════════════════════════════════════
def pull_cisa_kev() -> list:
    """Pull CISA KEV catalog — recent additions affecting Canadian-common software."""
    print(f"  [CISA] Pulling KEV catalog...")
    resp = safe_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if not resp:
        return []

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])

    # Canadian-relevant vendors (heavily used in Canadian gov/enterprise)
    ca_relevant_vendors = [
        "fortinet", "microsoft", "cisco", "ivanti", "vmware", "citrix",
        "palo alto", "juniper", "f5", "pulse", "solarwinds", "atlassian"
    ]

    # Get vulnerabilities added in last 7 days
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    events = []

    for vuln in vulnerabilities:
        try:
            added_date = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if added_date < cutoff:
                continue
        except (ValueError, KeyError):
            continue

        vendor = vuln.get("vendorProject", "").lower()
        if not any(cv in vendor for cv in ca_relevant_vendors):
            continue

        events.append({
            "id": f"KEV-{vuln.get('cveID', 'UNKNOWN')}",
            "source": "CISA KEV",
            "source_type": "gov_feed",
            "title": f"KEV: {vuln.get('cveID', '')} — {vuln.get('vulnerabilityName', '')}",
            "description": vuln.get("shortDescription", ""),
            "cve": vuln.get("cveID"),
            "vendor": vuln.get("vendorProject"),
            "product": vuln.get("product"),
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "timestamp": vuln.get("dateAdded", ""),
            "is_canadian": True,  # Canadian infrastructure uses these products
            "auto_confidence": 0.80,
            "raw_text": f"{vuln.get('cveID', '')} {vuln.get('vulnerabilityName', '')} {vuln.get('shortDescription', '')}"
        })

    print(f"    → {len(events)} KEV entries (CA-relevant vendors, last 7d)")
    return events


# ══════════════════════════════════════════════════════════════════════
# SOURCE 5: THREATFOX (abuse.ch) — Malware IOCs
# ══════════════════════════════════════════════════════════════════════
def pull_threatfox() -> list:
    """Pull recent malware IOCs from ThreatFox."""
    print(f"  [ThreatFox] Pulling recent IOCs...")
    resp = safe_get(
        "https://threatfox-api.abuse.ch/api/v1/",
        headers={"Content-Type": "application/json"},
    )

    # ThreatFox uses POST
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=20
        )
        data = resp.json()
    except Exception as e:
        print(f"    ⚠️  ThreatFox error: {e}")
        return []

    events = []
    for ioc_entry in data.get("data", [])[:50]:
        malware = ioc_entry.get("malware", "")
        tags = ioc_entry.get("tags") or []
        combined = f"{malware} {' '.join(tags)} {ioc_entry.get('ioc_value', '')}"

        events.append({
            "id": f"TFX-{ioc_entry.get('id', hash(combined) & 0xFFFFFF)}",
            "source": "ThreatFox (abuse.ch)",
            "source_type": "osint_api",
            "title": f"Malware IOC: {malware}",
            "description": f"ThreatFox IOC — {ioc_entry.get('ioc_type', '')} targeting {ioc_entry.get('malware_printable', '')}",
            "iocs": [{"type": ioc_entry.get("ioc_type", "IOC").upper(), "val": ioc_entry.get("ioc_value", "")}],
            "tags": tags,
            "url": f"https://threatfox.abuse.ch/ioc/{ioc_entry.get('id', '')}",
            "timestamp": ioc_entry.get("first_seen", ""),
            "is_canadian": False,  # AI council filters for Canadian relevance
            "auto_confidence": 0.60,
            "raw_text": combined
        })

    print(f"    → {len(events)} ThreatFox IOCs (pre-filter)")
    return events


# ══════════════════════════════════════════════════════════════════════
# SOURCE 6: CHAINABUSE — Crypto scam reports
# ══════════════════════════════════════════════════════════════════════
def pull_chainabuse(api_key: str = None) -> list:
    """Pull Chainabuse crypto scam reports."""
    if not api_key:
        print(f"  [Chainabuse] No API key — skipping")
        return []

    print(f"  [Chainabuse] Pulling Canadian crypto reports...")
    headers = {"Authorization": f"Bearer {api_key}"}

    resp = safe_get(
        "https://www.chainabuse.com/api/reports",
        headers=headers,
        params={"limit": 50, "country": "CA"}
    )
    if not resp:
        return []

    events = []
    for report in resp.json().get("reports", []):
        description = report.get("description", "")
        address = report.get("address", "")
        combined = f"{description} {address}"

        events.append({
            "id": f"CHAIN-{report.get('id', hash(address) & 0xFFFFFF)}",
            "source": "Chainabuse",
            "source_type": "blockchain",
            "title": f"Crypto Scam Report: {report.get('category', 'Unknown')}",
            "description": description[:2000],
            "iocs": [{"type": "WALLET", "val": address}] if address else [],
            "url": f"https://www.chainabuse.com/report/{report.get('id', '')}",
            "timestamp": report.get("createdAt", ""),
            "is_canadian": True,  # Filtered by country=CA
            "auto_confidence": 0.65,
            "raw_text": combined
        })

    print(f"    → {len(events)} Chainabuse reports")
    return events


# ══════════════════════════════════════════════════════════════════════
# SOURCE 7: HAVEIBEENPWNED — Canadian breach detection
# ══════════════════════════════════════════════════════════════════════
def pull_hibp_breaches() -> list:
    """Check HIBP breaches for Canadian .ca domain organizations."""
    print(f"  [HIBP] Checking recent breaches for .ca domains...")
    resp = safe_get(
        "https://haveibeenpwned.com/api/v3/breaches",
        headers={"hibp-api-key": os.environ.get("HIBP_API_KEY", ""), "user-agent": "NorthEYE-CTI/1.0"}
    )
    if not resp:
        return []

    events = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    for breach in resp.json():
        breach_date_str = breach.get("BreachDate", "")
        domain = breach.get("Domain", "")
        name = breach.get("Name", "")
        description = breach.get("Description", "")
        combined = f"{name} {domain} {description}"

        try:
            breach_date = datetime.strptime(breach_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if breach_date < cutoff:
                continue
        except ValueError:
            continue

        if not (domain.endswith(".ca") or is_canadian(combined)):
            continue

        events.append({
            "id": f"HIBP-{breach.get('Name', '').replace(' ', '_')}",
            "source": "HaveIBeenPwned",
            "source_type": "osint_api",
            "title": f"Data Breach: {name} ({breach.get('PwnCount', 0):,} records)",
            "description": re.sub(r'<[^>]+>', '', description)[:2000],
            "url": f"https://haveibeenpwned.com/PwnedWebsites#{name}",
            "timestamp": breach_date_str,
            "is_canadian": True,
            "auto_confidence": 0.78,
            "raw_text": combined,
            "metadata": {
                "pwn_count": breach.get("PwnCount"),
                "domain": domain,
                "data_classes": breach.get("DataClasses", [])
            }
        })

    print(f"    → {len(events)} HIBP .ca breaches (last 30d)")
    return events


# ══════════════════════════════════════════════════════════════════════
# SOURCE 8: X TWITTER MONITOR OUTPUT
# ══════════════════════════════════════════════════════════════════════
def load_x_signals(x_output_path: str) -> list:
    """Load pre-processed X/Twitter monitor output."""
    if not x_output_path or not os.path.exists(x_output_path):
        print(f"  [X] No X monitor output found — skipping social signals")
        return []

    with open(x_output_path) as f:
        data = json.load(f)

    candidates = data.get("candidates", [])
    print(f"  [X] Loaded {len(candidates)} social signals from watchlist")
    return candidates


# ══════════════════════════════════════════════════════════════════════
# MERGE & DEDUPLICATE
# ══════════════════════════════════════════════════════════════════════
def merge_and_dedup(all_events: list) -> list:
    """Merge events from all sources and deduplicate by ID."""
    seen_ids = set()
    unique = []
    for event in all_events:
        eid = event.get("id", "")
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            unique.append(event)
    return unique


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="North E.Y.E. Master OSINT Aggregator")
    parser.add_argument("--output", required=True, help="Output raw_threats.json")
    parser.add_argument("--x-signals", default="raw_x_threats.json", help="X monitor output file")
    parser.add_argument("--filter-canadian", action="store_true", default=True,
                        help="Apply Canadian relevance filter")
    parser.add_argument("--sources", default="all",
                        help="Comma-separated sources: cccs,cafc,otx,cisa,threatfox,chainabuse,hibp,x")
    args = parser.parse_args()

    sources = [s.strip().lower() for s in args.sources.split(",")]
    run_all = "all" in sources

    # API keys from environment
    otx_key       = os.environ.get("ALIENVAULT_API_KEY", "")
    chainabuse_key = os.environ.get("CHAINABUSE_API_KEY", "")
    cccs_url      = os.environ.get("CCCS_FEED_URL", "")
    cafc_url      = os.environ.get("CAFC_FEED_URL", "")

    print(f"North E.Y.E. — Master OSINT Aggregator")
    print(f"Sources: {args.sources} | CA filter: {args.filter_canadian}")
    print("═" * 60)

    all_events = []

    if run_all or "cccs"       in sources: all_events.extend(pull_cccs_rss(cccs_url))
    if run_all or "cafc"       in sources: all_events.extend(pull_cafc_bulletins(cafc_url))
    if run_all or "otx"        in sources: all_events.extend(pull_alienvault_otx(otx_key))
    if run_all or "cisa"       in sources: all_events.extend(pull_cisa_kev())
    if run_all or "threatfox"  in sources: all_events.extend(pull_threatfox())
    if run_all or "chainabuse" in sources: all_events.extend(pull_chainabuse(chainabuse_key))
    if run_all or "hibp"       in sources: all_events.extend(pull_hibp_breaches())
    if run_all or "x"          in sources: all_events.extend(load_x_signals(args.x_signals))

    print(f"\n{'─' * 60}")
    print(f"Total raw events: {len(all_events)}")

    # Apply Canadian relevance filter (except for already-marked sources)
    if args.filter_canadian:
        filtered = [
            e for e in all_events
            if e.get("is_canadian") or is_canadian(e.get("raw_text", ""))
        ]
        print(f"After CA filter:  {len(filtered)} events")
    else:
        filtered = all_events

    # Deduplicate
    unique = merge_and_dedup(filtered)
    print(f"After dedup:      {len(unique)} unique events")

    # Write output
    output = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_events": len(unique),
            "sources_used": [s for s in sources if s != "all"] if "all" not in sources else list({e.get("source") for e in unique}),
            "filter_canadian": args.filter_canadian
        },
        "events": unique
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Aggregation complete → {args.output}")


if __name__ == "__main__":
    main()
