"""
Payer exclusion/procedure change scraper.
Fetches policy pages, detects changes, and identifies exclusion keywords.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import requests
import yaml
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "config" / "sources.yml"
KEYWORDS_CONFIG = ROOT / "config" / "keywords.yml"
SNAPSHOTS = ROOT / "data" / "snapshots.json"
REPORT = ROOT / "reports" / "latest_findings.md"

# Exclusion keywords
KEYWORDS = [
    "excluded", "exclusion", "non-covered", "not covered",
    "not reasonable and necessary", "experimental", "investigational",
    "unproven", "cosmetic", "medical necessity criteria updated",
    "prior authorization", "precertification", "site of service",
    "archived", "deleted policy", "coding update", "payment policy",
    "claim edit", "disallowed", "not separately billable",
    "self-administered drug exclusion"
]


def load_json(path: Path, default):
    """Load JSON file or return default if not found."""
    if path.exists():
        return json.loads(path.read_text())
    return default


def clean_text(html: str) -> str:
    """Extract and clean text from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    # Remove script, style, nav, footer tags
    for tag in soup(["script", "style", "nav", "footer"]):
        tag.decompose()
    # Extract text
    text = soup.get_text("\n")
    # Normalize whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def fingerprint(text: str) -> str:
    """Generate SHA256 hash of text content."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def keyword_hits(text: str) -> List[str]:
    """Find all keywords present in text."""
    lower = text.lower()
    return [kw for kw in KEYWORDS if kw.lower() in lower]


def fetch(url: str) -> str:
    """Fetch URL content with proper headers."""
    headers = {
        "User-Agent": "payer-policy-monitor/1.0 compliance-review-bot"
    }
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.text


def main():
    """Main scraper pipeline."""
    # Create directories
    ROOT.joinpath("data").mkdir(exist_ok=True)
    ROOT.joinpath("reports").mkdir(exist_ok=True)

    # Load configuration
    sources = yaml.safe_load(SOURCES.read_text())["sources"]
    snapshots = load_json(SNAPSHOTS, {})
    findings = []

    # Process each source
    for source in sources:
        url = source["url"]
        payer = source["payer"]
        source_type = source["source_type"]
        priority = source.get("priority", "medium")

        try:
            # Fetch and clean content
            html = fetch(url)
            text = clean_text(html)
            new_hash = fingerprint(text)
            old_hash = snapshots.get(url, {}).get("hash")

            # Find keywords
            hits = keyword_hits(text)

            # Report if content changed AND keywords found
            if old_hash and old_hash != new_hash and hits:
                findings.append({
                    "payer": payer,
                    "source_type": source_type,
                    "priority": priority,
                    "url": url,
                    "keywords_found": hits,
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })
                print(f"✓ Found exclusion keywords in {payer} - {source_type}")
            elif old_hash and old_hash != new_hash:
                print(f"⚠ Content changed but no keywords in {payer} - {source_type}")
            else:
                print(f"✓ No changes in {payer} - {source_type}")

            # Update snapshot
            snapshots[url] = {
                "payer": payer,
                "source_type": source_type,
                "hash": new_hash,
                "last_checked": datetime.now(timezone.utc).isoformat()
            }

        except Exception as exc:
            findings.append({
                "payer": payer,
                "source_type": source_type,
                "priority": priority,
                "url": url,
                "error": str(exc),
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
            print(f"✗ Error fetching {payer} - {source_type}: {exc}")

    # Save snapshots
    SNAPSHOTS.write_text(json.dumps(snapshots, indent=2))
    print(f"\nSnapshots saved: {SNAPSHOTS}")

    # Generate report
    if findings:
        lines = [
            "# Payer exclusion/procedure update review\n",
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
        ]
        
        # Sort by priority (high first) then by payer
        findings.sort(key=lambda x: (x.get("priority") != "high", x["payer"]))
        
        for item in findings:
            lines.append(f"## {item['payer']}")
            lines.append(f"- **Source type:** `{item['source_type']}`")
            lines.append(f"- **Priority:** {item.get('priority', 'medium')}")
            lines.append(f"- **URL:** {item['url']}")
            
            if "keywords_found" in item:
                lines.append(f"- **Keywords found:** {', '.join(sorted(set(item['keywords_found'])))}")
            
            if "error" in item:
                lines.append(f"- **Error:** {item['error']}")
            
            lines.append(f"- **Detected:** {item['detected_at']}")
            lines.append("")
        
        REPORT.write_text("\n".join(lines))
        print(f"✓ Report generated: {REPORT}")
        print(f"\n{len(findings)} findings require review.")
    else:
        REPORT.write_text("")
        print("✓ No findings. All sources clean.")


if __name__ == "__main__":
    main()
