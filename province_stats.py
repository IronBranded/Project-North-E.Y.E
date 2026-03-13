"""
North E.Y.E. — Province Statistics Generator
Reads threats.json and produces stats.json — a lightweight companion file
consumed by the frontend to power:

  - Province heatmap intensity on the SVG map
  - Trending threat categories per province
  - 30-day timeline sparklines (daily event counts)
  - National summary bar

Committed alongside threats.json on every sync cycle.

USAGE:
    python province_stats.py \
        --input threats.json \
        --output stats.json
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


# ── PROVINCE METADATA ────────────────────────────────────────────────
PROVINCES = {
    "Ontario":                       {"code": "ON", "capital": "Toronto",    "pop_m": 14.9},
    "Quebec":                        {"code": "QC", "capital": "Montréal",   "pop_m": 8.8},
    "British Columbia":              {"code": "BC", "capital": "Vancouver",  "pop_m": 5.5},
    "Alberta":                       {"code": "AB", "capital": "Calgary",    "pop_m": 4.6},
    "Saskatchewan":                  {"code": "SK", "capital": "Regina",     "pop_m": 1.2},
    "Manitoba":                      {"code": "MB", "capital": "Winnipeg",   "pop_m": 1.4},
    "Nova Scotia":                   {"code": "NS", "capital": "Halifax",    "pop_m": 1.0},
    "New Brunswick":                 {"code": "NB", "capital": "Fredericton","pop_m": 0.8},
    "Newfoundland and Labrador":     {"code": "NL", "capital": "St. John's", "pop_m": 0.5},
    "Prince Edward Island":          {"code": "PE", "capital": "Charlottetown","pop_m": 0.17},
    "Yukon":                         {"code": "YT", "capital": "Whitehorse", "pop_m": 0.04},
    "Northwest Territories":         {"code": "NT", "capital": "Yellowknife","pop_m": 0.04},
    "Nunavut":                       {"code": "NU", "capital": "Iqaluit",    "pop_m": 0.04},
    "National":                      {"code": "CA", "capital": "Ottawa",     "pop_m": 40.0},
}


def date_range_30d() -> list[str]:
    """Return list of YYYY-MM-DD strings for the last 30 days."""
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]


def compute_heatmap_intensity(threat_count: int, high_count: int, score_sum: int) -> float:
    """Compute a 0.0–1.0 heatmap intensity value for a province."""
    if threat_count == 0:
        return 0.0
    # Weighted: raw count + high severity bonus + avg score factor
    raw = min(threat_count / 5.0, 1.0)           # 5 threats = max raw
    sev = min(high_count / 3.0, 1.0) * 0.4       # 3 high = max sev bonus
    scr = min(score_sum / (threat_count * 80), 1.0) * 0.3  # avg score/80 factor
    return round(min(raw * 0.3 + sev + scr, 1.0), 3)


def main():
    parser = argparse.ArgumentParser(description="North E.Y.E. Province Stats Generator")
    parser.add_argument("--input",  required=True, help="threats.json")
    parser.add_argument("--output", required=True, help="stats.json")
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    threats = data.get("threats", [])
    now     = datetime.now(timezone.utc)
    days_30 = date_range_30d()

    # ── Per-Province Aggregation ──────────────────────────────────────
    province_threats:   dict[str, list] = defaultdict(list)
    province_scores:    dict[str, list] = defaultdict(list)
    province_timeline:  dict[str, dict] = defaultdict(lambda: {d: 0 for d in days_30})

    for t in threats:
        prov = t.get("province", "National")
        province_threats[prov].append(t)
        province_scores[prov].append(t.get("threat_score", 0))

        # Add to national totals as well
        if prov != "National":
            province_threats["National"].append(t)

        # Timeline bucketing
        ts_str = t.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            day_key = ts.date().isoformat()
            if day_key in province_timeline[prov]:
                province_timeline[prov][day_key] += 1
            if prov != "National" and day_key in province_timeline["National"]:
                province_timeline["National"][day_key] += 1
        except (ValueError, AttributeError):
            pass

    # ── Build Province Stats Objects ─────────────────────────────────
    province_stats = {}

    for prov_name, meta in PROVINCES.items():
        prov_threats = province_threats.get(prov_name, [])
        prov_scores  = province_scores.get(prov_name, [])

        if not prov_threats:
            province_stats[prov_name] = {
                "code":       meta["code"],
                "capital":    meta["capital"],
                "count":      0,
                "high":       0,
                "medium":     0,
                "low":        0,
                "cyber":      0,
                "fincrime":   0,
                "avg_score":  0,
                "intensity":  0.0,
                "top_tags":   [],
                "timeline":   {d: 0 for d in days_30},
                "latest_id":  None,
                "latest_ts":  None,
            }
            continue

        high   = sum(1 for t in prov_threats if t.get("severity") == "high")
        medium = sum(1 for t in prov_threats if t.get("severity") == "medium")
        low    = sum(1 for t in prov_threats if t.get("severity") == "low")
        cyber  = sum(1 for t in prov_threats if t.get("category") == "cyber")
        fincr  = sum(1 for t in prov_threats if t.get("category") == "fincrime")
        avg_sc = round(sum(prov_scores) / len(prov_scores), 1) if prov_scores else 0

        # Top tags across province
        all_tags = []
        for t in prov_threats:
            all_tags.extend(t.get("tags", []))
        top_tags = [tag for tag, _ in Counter(all_tags).most_common(5)]

        # Most recent threat
        sorted_ts = sorted(
            [t for t in prov_threats if t.get("timestamp")],
            key=lambda t: t.get("timestamp", ""),
            reverse=True
        )
        latest = sorted_ts[0] if sorted_ts else None

        province_stats[prov_name] = {
            "code":       meta["code"],
            "capital":    meta["capital"],
            "pop_m":      meta["pop_m"],
            "count":      len(prov_threats),
            "high":       high,
            "medium":     medium,
            "low":        low,
            "cyber":      cyber,
            "fincrime":   fincr,
            "avg_score":  avg_sc,
            "intensity":  compute_heatmap_intensity(len(prov_threats), high, sum(prov_scores)),
            "top_tags":   top_tags,
            "timeline":   province_timeline.get(prov_name, {d: 0 for d in days_30}),
            "latest_id":  latest.get("id") if latest else None,
            "latest_ts":  latest.get("timestamp") if latest else None,
            "latest_title": latest.get("title") if latest else None,
        }

    # ── National Summary ─────────────────────────────────────────────
    all_scores = [t.get("threat_score", 0) for t in threats]
    all_tags   = []
    for t in threats:
        all_tags.extend(t.get("tags", []))

    # Activity trend: compare last 7d vs prior 7d
    cutoff_7  = now - timedelta(days=7)
    cutoff_14 = now - timedelta(days=14)
    last_7d_count  = 0
    prior_7d_count = 0
    for t in threats:
        try:
            ts = datetime.fromisoformat(t.get("timestamp","").replace("Z","+00:00"))
            if ts >= cutoff_7:
                last_7d_count += 1
            elif ts >= cutoff_14:
                prior_7d_count += 1
        except (ValueError, AttributeError):
            pass

    trend_pct = 0
    if prior_7d_count > 0:
        trend_pct = round(((last_7d_count - prior_7d_count) / prior_7d_count) * 100, 1)

    # Source breakdown
    source_counts = Counter()
    for t in threats:
        for sig in t.get("signal_sources", []):
            source_counts[sig.get("type", "osint")] += 1

    national_summary = {
        "total_threats":     len(threats),
        "total_high":        sum(1 for t in threats if t.get("severity") == "high"),
        "total_medium":      sum(1 for t in threats if t.get("severity") == "medium"),
        "total_low":         sum(1 for t in threats if t.get("severity") == "low"),
        "total_cyber":       sum(1 for t in threats if t.get("category") == "cyber"),
        "total_fincrime":    sum(1 for t in threats if t.get("category") == "fincrime"),
        "avg_threat_score":  round(sum(all_scores) / len(all_scores), 1) if all_scores else 0,
        "max_threat_score":  max(all_scores) if all_scores else 0,
        "top_tags":          [tag for tag, _ in Counter(all_tags).most_common(10)],
        "trend_7d_pct":      trend_pct,
        "last_7d_count":     last_7d_count,
        "prior_7d_count":    prior_7d_count,
        "source_breakdown":  dict(source_counts),
        "provinces_affected": sum(1 for p, s in province_stats.items()
                                  if p != "National" and s.get("count", 0) > 0),
        "timeline_30d":      province_timeline.get("National", {d: 0 for d in days_30}),
    }

    # ── Write Output ─────────────────────────────────────────────────
    output = {
        "meta": {
            "generated_at":  now.isoformat(),
            "threats_count": len(threats),
            "days_covered":  30
        },
        "national":  national_summary,
        "provinces": province_stats,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"✅ Province stats generated")
    print(f"   Provinces with threats: {national_summary['provinces_affected']}/13")
    print(f"   7-day trend: {'+' if trend_pct >= 0 else ''}{trend_pct}%")
    print(f"   National avg score: {national_summary['avg_threat_score']}/100")
    print(f"   → {args.output}")


if __name__ == "__main__":
    main()
