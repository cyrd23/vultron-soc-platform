#!/usr/bin/env python3
import json
from datetime import datetime, UTC
from pathlib import Path

import feedparser
import yaml

BASE = Path.home() / "soc"
INTEL_DIR = BASE / "intel"
SOURCES_DIR = INTEL_DIR / "sources"
RAW_DIR = INTEL_DIR / "raw"
SUMMARIES_DIR = INTEL_DIR / "summaries"
PRIORITIES_DIR = INTEL_DIR / "priorities"
HUNT_CANDIDATES_DIR = INTEL_DIR / "hunt_candidates"

SOURCE_LIST_FILE = SOURCES_DIR / "source_list.yaml"
SOURCE_WEIGHTS_FILE = SOURCES_DIR / "source_weights.yaml"


THEME_RULES = [
    {
        "name": "OAuth consent phishing",
        "keywords": [
            "oauth", "consent", "delegated permission", "permission grant",
            "app role assignment", "grant to user"
        ],
        "category": "identity",
        "mapped_ttps": ["T1528", "T1078"],
        "recommended_hunts": ["oauth_consent_abuse"],
        "base_severity": "high",
    },
    {
        "name": "Password spraying against Microsoft 365",
        "keywords": [
            "password spray", "password spraying", "credential spray",
            "brute force against m365", "microsoft 365 login attack"
        ],
        "category": "identity",
        "mapped_ttps": ["T1110.003"],
        "recommended_hunts": ["password_spray"],
        "base_severity": "high",
    },
    {
        "name": "Graph API or cloud file abuse",
        "keywords": [
            "graph api", "sharepoint", "onedrive", "mass download",
            "microsoft graph", "cloud file access"
        ],
        "category": "cloud_activity",
        "mapped_ttps": ["T1530", "T1529"],
        "recommended_hunts": ["graph_api_mass_access"],
        "base_severity": "medium",
    },
    {
        "name": "DNS and malicious domain activity",
        "keywords": [
            "dga", "malicious domain", "dns tunneling", "command and control domain",
            "rare domain", "newly registered domain"
        ],
        "category": "dns",
        "mapped_ttps": ["T1071.004", "T1568"],
        "recommended_hunts": ["rare_domain_access", "malicious_domain_requests"],
        "base_severity": "medium",
    },
    {
        "name": "Ransomware or malware delivery activity",
        "keywords": [
            "ransomware", "loader", "malware delivery", "payload delivery",
            "trojan", "infostealer"
        ],
        "category": "endpoint",
        "mapped_ttps": ["T1204", "T1059"],
        "recommended_hunts": ["suspicious_powershell", "credential_dumping"],
        "base_severity": "medium",
    },
]


def ensure_dirs():
    for d in [RAW_DIR, SUMMARIES_DIR, PRIORITIES_DIR, HUNT_CANDIDATES_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def load_yaml(path: Path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_sources():
    data = load_yaml(SOURCE_LIST_FILE)
    return data.get("sources", [])


def load_weights():
    return load_yaml(SOURCE_WEIGHTS_FILE)


def get_source_weight(source: dict, weights: dict) -> float:
    tier = source.get("tier")
    tier_weight = weights.get("tier_weights", {}).get(tier, 0.5)
    override = weights.get("source_overrides", {}).get(source.get("name"))
    if override is not None:
        return float(override)
    return float(tier_weight)


def get_focus_weight(source: dict, weights: dict) -> float:
    focus_weights = weights.get("focus_weights", {})
    focuses = source.get("focus", [])
    if not focuses:
        return 0.5
    vals = [float(focus_weights.get(f, 0.4)) for f in focuses]
    return max(vals) if vals else 0.5


def fetch_rss_source(source: dict):
    feed = feedparser.parse(source["url"])
    entries = []

    for entry in feed.entries[:25]:
        entries.append({
            "source": source["name"],
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "published": entry.get("published", "") or entry.get("updated", ""),
            "summary": entry.get("summary", "") or entry.get("description", ""),
        })

    return entries


def fetch_sources(sources):
    all_entries = []

    for source in sources:
        if not source.get("enabled", False):
            continue

        source_type = source.get("type")
        parser = source.get("parser")

        try:
            if source_type == "rss" and parser == "rss":
                entries = fetch_rss_source(source)
                all_entries.extend(entries)
            else:
                # placeholder for future parsers like OTX API
                continue
        except Exception as e:
            print(f"Failed to fetch {source.get('name')}: {e}")

    return all_entries


def save_raw_entries(entries):
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    out_file = RAW_DIR / f"{date_str}_feed_entries.json"
    out_file.write_text(json.dumps(entries, indent=2))
    return out_file


def score_theme(rule: dict, entries: list, source_meta: dict, weights: dict) -> dict | None:
    matched_entries = []
    score = 0.0

    for entry in entries:
        source_name = entry["source"]
        source = source_meta.get(source_name)
        if not source:
            continue

        haystack = " ".join([
            entry.get("title", ""),
            entry.get("summary", ""),
        ]).lower()

        if any(keyword.lower() in haystack for keyword in rule["keywords"]):
            src_weight = get_source_weight(source, weights)
            focus_weight = get_focus_weight(source, weights)
            entry_score = src_weight * focus_weight
            score += entry_score
            matched_entries.append({
                "source": source_name,
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "score": round(entry_score, 3),
            })

    if not matched_entries:
        return None

    if score >= 2.5:
        relevance = "high"
    elif score >= 1.2:
        relevance = "medium"
    else:
        relevance = "low"

    return {
        "theme": rule["name"],
        "relevance": relevance,
        "category": rule["category"],
        "mapped_ttps": rule["mapped_ttps"],
        "recommended_hunts": rule["recommended_hunts"],
        "base_severity": rule["base_severity"],
        "score": round(score, 3),
        "matched_entries": matched_entries[:10],
    }


def derive_themes(entries, sources, weights):
    source_meta = {s["name"]: s for s in sources}
    themes = []

    for rule in THEME_RULES:
        result = score_theme(rule, entries, source_meta, weights)
        if result:
            themes.append(result)

    themes.sort(key=lambda x: x["score"], reverse=True)
    return themes


def write_summary(themes):
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    generated_at = datetime.now(UTC).isoformat()

    summary = {
        "date": date_str,
        "generated_at": generated_at,
        "themes": themes,
    }

    out_file = SUMMARIES_DIR / f"{date_str}_intel_summary.json"
    out_file.write_text(json.dumps(summary, indent=2))
    return out_file


def write_priorities(themes):
    generated_at = datetime.now(UTC).isoformat()

    priorities = {
        "generated_at": generated_at,
        "priority_themes": [t["theme"] for t in themes if t["relevance"] in ("high", "medium")],
        "priority_categories": sorted(list(set(
            t["category"] for t in themes if t["relevance"] in ("high", "medium")
        ))),
        "recommended_hunts": sorted(list(set(
            hunt
            for t in themes if t["relevance"] in ("high", "medium")
            for hunt in t["recommended_hunts"]
        ))),
    }

    out_file = PRIORITIES_DIR / "current_priority_ttps.json"
    out_file.write_text(json.dumps(priorities, indent=2))
    return out_file


def write_hunt_candidates(themes):
    created = []

    existing_builtin = {"oauth_consent_abuse", "password_spray", "impossible_travel"}

    for theme in themes:
        for hunt in theme["recommended_hunts"]:
            if hunt in existing_builtin:
                continue

            candidate = {
                "name": hunt,
                "category": theme["category"],
                "description": f"Proposed hunt based on intel theme: {theme['theme']}",
                "reason": theme["theme"],
                "mapped_ttps": theme["mapped_ttps"],
                "relevance": theme["relevance"],
                "status": "proposed",
            }

            out_file = HUNT_CANDIDATES_DIR / f"{hunt}.json"
            out_file.write_text(json.dumps(candidate, indent=2))
            created.append(out_file)

    return created


def main():
    ensure_dirs()

    if not SOURCE_LIST_FILE.exists():
        raise FileNotFoundError(f"Missing source list: {SOURCE_LIST_FILE}")

    if not SOURCE_WEIGHTS_FILE.exists():
        raise FileNotFoundError(f"Missing source weights: {SOURCE_WEIGHTS_FILE}")

    sources = load_sources()
    weights = load_weights()

    enabled_sources = [s for s in sources if s.get("enabled", False)]
    print(f"Enabled intel sources: {len(enabled_sources)}")

    entries = fetch_sources(enabled_sources)
    print(f"Fetched entries: {len(entries)}")

    raw_file = save_raw_entries(entries)
    themes = derive_themes(entries, enabled_sources, weights)

    summary_file = write_summary(themes)
    priorities_file = write_priorities(themes)
    candidate_files = write_hunt_candidates(themes)

    print(f"Raw entries saved: {raw_file}")
    print(f"Intel summary saved: {summary_file}")
    print(f"Priority file saved: {priorities_file}")

    if candidate_files:
        print("Hunt candidates created:")
        for c in candidate_files:
            print(f"  - {c}")

    if not themes:
        print("No themes derived from current feeds.")
    else:
        print("Derived themes:")
        for theme in themes:
            hunts = ", ".join(theme["recommended_hunts"])
            print(f"  - {theme['theme']} [{theme['relevance']}] -> {hunts}")


if __name__ == "__main__":
    main()
