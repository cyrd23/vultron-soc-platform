#!/usr/bin/env python3
import json
import re
from datetime import datetime, UTC
from pathlib import Path

BASE = Path.home() / "soc"
RAW_DIR = BASE / "intel" / "raw"
IOC_DIR = BASE / "intel" / "iocs"

ip_regex = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
domain_regex = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
hash_regex = r"\b[a-fA-F0-9]{32,64}\b"

TRUSTED_DOMAINS = {
    "microsoft.com",
    "github.com",
    "google.com",
    "twitter.com",
    "x.com",
    "sans.edu",
    "isc.sans.edu",
    "paloaltonetworks.com",
    "unit42.paloaltonetworks.com",
    "checkpoint.com",
    "research.checkpoint.com",
    "securelist.com",
    "krebsonsecurity.com",
    "securityweek.com",
    "bellingcat.com",
    "webbreacher.com",
    "proofpoint.com",
    "darkreading.com",
    "thehackernews.com",
    "bleepingcomputer.com",
    "cyberwire.com",
    "timeapi.io",
    "crates.io",
    "start.me",
    "gmail.com",
    "cloudinary.com",
    "doubleclick.net",
    "constantcontact.com",
    "wsimg.com",
    "jsdelivr.net",
    "cloudfront.net",
    "akamai.net",
    "googleapis.com",
    "live.com",
}

BLOCKED_SUFFIXES = {
    ".html", ".htm", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".js", ".css", ".xml", ".ico", ".webp", ".php", ".aspx", ".txt"
}

BLOCKED_CONTAINS = {
    "feedburner",
    "rss",
    "feeds.",
    "blog.",
}

BLOCKED_EXACT = {
    "next.js",
}

MALICIOUS_CONTEXT_TERMS = {
    "malware": 3,
    "malicious": 3,
    "phishing": 3,
    "payload": 3,
    "c2": 4,
    "command-and-control": 4,
    "beacon": 3,
    "callback": 3,
    "botnet": 3,
    "trojan": 3,
    "infostealer": 3,
    "ransomware": 3,
    "downloader": 3,
    "loader": 3,
    "stealer": 3,
    "exploit": 2,
    "exfiltration": 3,
    "credential theft": 3,
    "ioc": 2,
    "indicator": 2,
    "observed": 1,
    "hosted": 1,
    "infrastructure": 2,
    "domain": 1,
    "ip": 1,
}

BENIGN_CONTEXT_TERMS = {
    "image": -3,
    "cdn": -3,
    "javascript": -3,
    "library": -3,
    "docs": -2,
    "documentation": -2,
    "blog": -2,
    "article": -2,
    "webinar": -3,
    "marketing": -3,
    "newsletter": -3,
    "signup": -2,
    "login with google": -2,
    "github": -3,
    "google": -3,
    "microsoft": -3,
    "cloudinary": -3,
    "doubleclick": -3,
    "constantcontact": -3,
    "wsimg": -3,
    "jsdelivr": -3,
}

SUSPICIOUS_TLDS = {
    "ru", "su", "cn", "top", "xyz", "shop", "click", "monster", "buzz", "live"
}


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".,);:]}>\"'")
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]
    if d.startswith("www."):
        d = d[4:]
    d = d.split("/")[0]
    return d


def is_trusted_domain(domain: str) -> bool:
    d = normalize_domain(domain)
    return d in TRUSTED_DOMAINS or any(d.endswith("." + t) for t in TRUSTED_DOMAINS)


def valid_domain(domain: str) -> bool:
    d = normalize_domain(domain)

    if len(d) < 5:
        return False

    if d in BLOCKED_EXACT:
        return False

    if "/" in d:
        return False

    if any(x in d for x in BLOCKED_CONTAINS):
        return False

    if any(d.endswith(ext) for ext in BLOCKED_SUFFIXES):
        return False

    if d.count(".") < 1 or d.count(".") > 4:
        return False

    parts = d.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    if not tld.isalpha() or len(tld) < 2:
        return False

    if len(parts) == 2 and "-" in parts[0] and len(parts[0]) > 20:
        return False

    if is_trusted_domain(d):
        return False

    return True


def score_domain_by_context(domain: str, text: str) -> int:
    d = normalize_domain(domain)
    lowered = text.lower()

    score = 0

    # bonus for suspicious TLDs
    tld = d.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 2

    # find nearby context around domain mentions
    idx = lowered.find(d)
    if idx != -1:
        start = max(0, idx - 200)
        end = min(len(lowered), idx + len(d) + 200)
        context = lowered[start:end]
    else:
        context = lowered

    for term, weight in MALICIOUS_CONTEXT_TERMS.items():
        if term in context:
            score += weight

    for term, weight in BENIGN_CONTEXT_TERMS.items():
        if term in context:
            score += weight

    return score


def extract_iocs_from_text(text: str) -> dict:
    ips = set(re.findall(ip_regex, text))
    hashes = set(re.findall(hash_regex, text))

    domains = set()
    scored_domains = []

    for match in re.findall(domain_regex, text):
        d = normalize_domain(match)
        if not valid_domain(d):
            continue

        score = score_domain_by_context(d, text)

        # only keep domains with meaningful suspicious context
        if score >= 3:
            domains.add(d)
            scored_domains.append({"domain": d, "score": score})

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "hashes": sorted(hashes),
        "scored_domains": sorted(scored_domains, key=lambda x: x["score"], reverse=True),
    }


def merge_iocs(all_iocs: dict, new_iocs: dict) -> None:
    for k in ("ips", "domains", "hashes"):
        all_iocs[k].update(new_iocs.get(k, []))

    all_iocs["scored_domains"].extend(new_iocs.get("scored_domains", []))


def load_raw_entries(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Skipping unreadable file {path}: {e}")
        return []


def run():
    IOC_DIR.mkdir(parents=True, exist_ok=True)

    if not RAW_DIR.exists():
        raise FileNotFoundError(f"Raw intel directory does not exist: {RAW_DIR}")

    raw_files = sorted([p for p in RAW_DIR.iterdir() if p.is_file() and p.suffix == ".json"])

    all_iocs = {
        "ips": set(),
        "domains": set(),
        "hashes": set(),
        "scored_domains": [],
    }

    processed_files = []

    for path in raw_files:
        data = load_raw_entries(path)
        processed_files.append(path.name)

        if not isinstance(data, list):
            continue

        for entry in data:
            if not isinstance(entry, dict):
                continue

            text = " ".join([
                str(entry.get("title", "")),
                str(entry.get("summary", "")),
            ])

            iocs = extract_iocs_from_text(text)
            merge_iocs(all_iocs, iocs)

    # dedupe scored domains by best score
    best_scores = {}
    for item in all_iocs["scored_domains"]:
        d = item["domain"]
        s = item["score"]
        if d not in best_scores or s > best_scores[d]:
            best_scores[d] = s

    final_iocs = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source_type": "rss_research_extraction",
        "source_files": processed_files,
        "ips": sorted(all_iocs["ips"]),
        "domains": sorted(all_iocs["domains"]),
        "hashes": sorted(all_iocs["hashes"]),
        "scored_domains": [
            {"domain": d, "score": best_scores[d]}
            for d in sorted(best_scores, key=lambda x: best_scores[x], reverse=True)
        ],
    }

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d")
    out_file = IOC_DIR / f"{timestamp}_rss_iocs.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(final_iocs, f, indent=2)

    print("IOC file created:", out_file)
    print("Source files processed:", len(processed_files))
    print("IPs:", len(final_iocs["ips"]))
    print("Domains:", len(final_iocs["domains"]))
    print("Hashes:", len(final_iocs["hashes"]))

    if final_iocs["scored_domains"]:
        print("Top scored domains:")
        for item in final_iocs["scored_domains"][:10]:
            print(f"  - {item['domain']} (score={item['score']})")


if __name__ == "__main__":
    run()
