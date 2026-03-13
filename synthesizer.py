"""
North E.Y.E. — AI Synthesizer
The final pipeline stage. Takes validated + council-voted threat events
and uses Claude to write a consistent, plain-language tactical summary
for each one. Also enriches each event with map coordinates, source
signal metadata, and a computed threat score.

This is the ONLY step that writes to the public-facing threats.json format.
All prior steps work on internal intermediate formats.

USAGE:
    python synthesizer.py \
        --input validated_threats.json \
        --output summarized_threats.json \
        --model claude-sonnet-4-6
"""

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone

import anthropic

# ── PROVINCE → MAP COORDINATES (900×560 SVG viewBox) ─────────────────
PROVINCE_COORDS = {
    "Ontario":                       {"province_code": "ON", "svg_x": 455, "svg_y": 330},
    "Quebec":                        {"province_code": "QC", "svg_x": 560, "svg_y": 265},
    "British Columbia":              {"province_code": "BC", "svg_x": 108, "svg_y": 315},
    "Alberta":                       {"province_code": "AB", "svg_x": 210, "svg_y": 300},
    "Saskatchewan":                  {"province_code": "SK", "svg_x": 284, "svg_y": 295},
    "Manitoba":                      {"province_code": "MB", "svg_x": 355, "svg_y": 300},
    "Nova Scotia":                   {"province_code": "NS", "svg_x": 720, "svg_y": 412},
    "New Brunswick":                 {"province_code": "NB", "svg_x": 683, "svg_y": 362},
    "Newfoundland and Labrador":     {"province_code": "NL", "svg_x": 770, "svg_y": 250},
    "Prince Edward Island":          {"province_code": "PE", "svg_x": 746, "svg_y": 355},
    "Yukon":                         {"province_code": "YT", "svg_x": 100, "svg_y": 145},
    "Northwest Territories":         {"province_code": "NT", "svg_x": 280, "svg_y": 140},
    "Nunavut":                       {"province_code": "NU", "svg_x": 560, "svg_y": 105},
    "National":                      {"province_code": "CA", "svg_x": 450, "svg_y": 280},
}

# ── THREAT SCORE WEIGHTS ─────────────────────────────────────────────
SEVERITY_SCORE   = {"high": 30, "medium": 20, "low": 10}
CATEGORY_BONUS   = {"cyber": 5, "fincrime": 5}
TARGET_BONUS     = {"Government": 10, "Healthcare": 8, "Businesses": 5, "Individuals": 3}
VALIDATION_BONUS = {3: 15, 2: 8, 1: 0}  # Council agreement count → bonus
SOURCE_TIER_BONUS = {"gov": 10, "police": 7, "x": 5, "osint": 3}

SYNTHESIS_SYSTEM = """You are the synthesis engine for North E.Y.E. (Electronic Yield Exchange), 
Canada's open-source Cyber Threat Intelligence dashboard. 

Your role is to write a concise, plain-language tactical summary for each validated Canadian threat event.

SUMMARY RULES:
- 2–4 sentences maximum
- Written for a security-aware but non-technical audience (e.g. a CFO, a city manager, a police chief)
- Lead with WHO was targeted and WHAT happened
- Include the approximate scale/impact (dollar amounts, record counts, duration)
- End with the current status or recommended action
- Use precise language — no vague qualifiers
- No jargon acronyms without explaining them (e.g. write "RDP (Remote Desktop Protocol)" not just "RDP")
- Tone: neutral, factual, urgent where appropriate

OUTPUT FORMAT: Return ONLY a JSON object:
{
  "event_id": "<id>",
  "summary": "<2-4 sentence plain-language summary>",
  "headline": "<10-word max punchy headline>",
  "impact_estimate": "<dollar amount or record count if known, else null>",
  "status": "<active|contained|under-investigation|resolved>"
}

Return ONLY valid JSON — no markdown, no preamble."""


def compute_threat_score(event: dict) -> int:
    """Compute a 0–100 threat score for map pulse intensity."""
    score = 0
    score += SEVERITY_SCORE.get(event.get("severity", "low"), 10)
    score += CATEGORY_BONUS.get(event.get("category", ""), 0)

    for target in event.get("target_types", []):
        score += TARGET_BONUS.get(target, 0)

    council = event.get("council_votes", {})
    agree_count = sum(1 for v in council.values() if v)
    score += VALIDATION_BONUS.get(agree_count, 0)

    # Social signal bonus
    sigs = event.get("signal_sources", [])
    for sig in sigs:
        score += SOURCE_TIER_BONUS.get(sig.get("type", "osint"), 0)

    return min(score, 100)


def generate_event_id(event: dict) -> str:
    """Generate a stable NEY-YYYY-NNN style ID from event content."""
    year = datetime.now(timezone.utc).year
    raw = f"{event.get('title', '')}{event.get('province', '')}{event.get('timestamp', '')}"
    hex_hash = hashlib.md5(raw.encode()).hexdigest()[:4].upper()
    return f"NEY-{year}-{hex_hash}"


def synthesize_batch(client: anthropic.Anthropic, model: str, events: list) -> list:
    """Send a batch of events to Claude for summary generation."""
    # Prepare minimal event descriptions for the AI
    batch_input = []
    for e in events:
        batch_input.append({
            "event_id": e.get("event_id") or e.get("id"),
            "category": e.get("category"),
            "subcategory": e.get("subcategory"),
            "title": e.get("title") or e.get("raw_text", "")[:100],
            "province": e.get("province"),
            "severity": e.get("severity"),
            "target_types": e.get("target_types", []),
            "description": e.get("description", "")[:500],
            "iocs_count": len(e.get("iocs", [])),
            "source": e.get("source"),
            "signal_source_count": len(e.get("signal_sources", [])),
        })

    user_msg = (
        f"Generate tactical summaries for these {len(batch_input)} "
        f"validated Canadian threat events. Return a JSON array of summary objects:\n\n"
        f"{json.dumps(batch_input, indent=2)}"
    )

    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=SYNTHESIS_SYSTEM,
        messages=[{"role": "user", "content": user_msg}]
    )

    raw = response.content[0].text.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:-1])

    parsed = json.loads(raw)

    # Normalize — could be array or single object
    if isinstance(parsed, dict):
        parsed = [parsed]

    return parsed


def build_final_event(raw_event: dict, synthesis: dict) -> dict:
    """Merge raw event data + synthesis into the final threats.json schema."""
    province = raw_event.get("province") or "National"
    coords = PROVINCE_COORDS.get(province, PROVINCE_COORDS["National"])

    threat_score = compute_threat_score(raw_event)

    # Compute TTL expiry (30 days from event timestamp)
    ts_str = raw_event.get("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(timezone.utc)

    from datetime import timedelta
    expires = (ts + timedelta(days=30)).isoformat()

    event_id = raw_event.get("event_id") or raw_event.get("id") or generate_event_id(raw_event)

    return {
        # Core identity
        "id":              event_id,
        "category":        raw_event.get("category", "cyber"),
        "subcategory":     raw_event.get("subcategory", "Unknown"),
        "tags":            raw_event.get("tags", []),

        # Classification
        "title":           synthesis.get("headline") or raw_event.get("title", "")[:120],
        "province":        province,
        "target_types":    raw_event.get("target_types", []),
        "severity":        raw_event.get("severity", "medium"),
        "threat_score":    threat_score,

        # Intelligence
        "iocs":            raw_event.get("iocs", []),
        "ioas":            raw_event.get("ioas", []),
        "summary":         synthesis.get("summary", ""),
        "impact_estimate": synthesis.get("impact_estimate"),
        "status":          synthesis.get("status", "active"),

        # Provenance
        "council_votes":   raw_event.get("council_votes", {}),
        "validated":       raw_event.get("validated", False),
        "confidence":      raw_event.get("confidence", 0.5),
        "source":          raw_event.get("source", "OSINT"),
        "signal_sources":  raw_event.get("signal_sources", []),

        # Temporal
        "timestamp":       ts_str,
        "expires":         expires,

        # Map
        "map_coordinates": coords,
        "mapPos": {
            "x": coords["svg_x"],
            "y": coords["svg_y"]
        }
    }


def main():
    parser = argparse.ArgumentParser(description="North E.Y.E. AI Synthesizer")
    parser.add_argument("--input",  required=True, help="validated_threats.json")
    parser.add_argument("--output", required=True, help="summarized_threats.json")
    parser.add_argument("--model",  default="claude-sonnet-4-6", help="Claude model to use")
    parser.add_argument("--batch-size", type=int, default=5, help="Events per synthesis call")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY not set")

    client = anthropic.Anthropic(api_key=api_key)

    # Load validated events
    with open(args.input) as f:
        data = json.load(f)

    events = data.get("validated", [])
    print(f"Synthesizer: {len(events)} validated events → {args.model}")
    print(f"Batch size: {args.batch_size}")
    print("─" * 60)

    # Index events by event_id for quick lookup
    events_by_id = {
        (e.get("event_id") or e.get("id")): e
        for e in events
    }

    summarized = []
    failed_ids = []

    for i in range(0, len(events), args.batch_size):
        batch = events[i:i + args.batch_size]
        batch_num = (i // args.batch_size) + 1
        batch_ids = [e.get("event_id") or e.get("id", "?") for e in batch]
        print(f"  Batch {batch_num}: {batch_ids}")

        try:
            syntheses = synthesize_batch(client, args.model, batch)

            # Map syntheses back to their source events
            synth_by_id = {s.get("event_id"): s for s in syntheses}

            for event in batch:
                eid = event.get("event_id") or event.get("id", "")
                synthesis = synth_by_id.get(eid) or {}

                # Fallback summary if synthesis failed for this event
                if not synthesis.get("summary"):
                    synthesis = {
                        "event_id": eid,
                        "summary": f"A {event.get('severity', 'medium')}-severity {event.get('category', 'cyber')} incident was detected in {event.get('province', 'Canada')}. Review IOCs and consult the primary source for details.",
                        "headline": event.get("title", "")[:80],
                        "impact_estimate": None,
                        "status": "active"
                    }

                final = build_final_event(event, synthesis)
                summarized.append(final)
                print(f"    ✅ {eid} — score:{final['threat_score']} — {final['status']}")

        except Exception as e:
            print(f"  ❌ Batch {batch_num} failed: {e}")
            for event in batch:
                eid = event.get("event_id") or event.get("id", "unknown")
                failed_ids.append(eid)
                # Still include the event with a fallback summary
                fallback = {
                    "event_id": eid,
                    "summary": f"A {event.get('severity', 'medium')}-severity {event.get('category', 'cyber')} incident was detected affecting Canadian targets. Automated summary unavailable — review source data.",
                    "headline": (event.get("title", "") or "")[:80],
                    "impact_estimate": None,
                    "status": "active"
                }
                summarized.append(build_final_event(event, fallback))

        # Rate limit buffer
        if i + args.batch_size < len(events):
            time.sleep(1.5)

    # Sort by threat_score descending
    summarized.sort(key=lambda e: e.get("threat_score", 0), reverse=True)

    output = {
        "meta": {
            "synthesizer_model": args.model,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_summarized": len(summarized),
            "total_failed_synthesis": len(failed_ids),
            "failed_ids": failed_ids
        },
        "threats": summarized
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'─' * 60}")
    print(f"✅ Synthesis complete")
    print(f"   Summarized : {len(summarized)}")
    print(f"   Failed     : {len(failed_ids)}")
    print(f"   → {args.output}")


if __name__ == "__main__":
    main()
