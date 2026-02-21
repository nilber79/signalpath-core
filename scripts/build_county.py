#!/usr/bin/env python3
"""
build_county.py — Run during Docker image build to inject county-specific values.

Usage:
    python build_county.py <config.yaml> <web_root>

What it does:
    1. Reads the county config.yaml
    2. Writes <web_root>/county-config.json  (used by app.js at runtime)
    3. Patches <web_root>/index.html         (title, subtitle, contact email, etc.)
"""

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


PLACEHOLDER_MAP = {
    "SIGNALPATH_TITLE":          lambda cfg: cfg["app"]["title"],
    "SIGNALPATH_SUBTITLE":       lambda cfg: cfg["app"]["subtitle"],
    "SIGNALPATH_CONTACT_EMAIL":  lambda cfg: cfg["app"]["contact_email"],
    "SIGNALPATH_OWNER_NAME":     lambda cfg: cfg["app"]["owner_name"],
    "SIGNALPATH_COPYRIGHT_YEAR": lambda cfg: str(cfg["app"]["copyright_year"]),
    "SIGNALPATH_COUNTY_STATE":   lambda cfg: f"{cfg['county']['name']}, {cfg['county']['state']}",
}


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <config.yaml> <web_root>", file=sys.stderr)
        sys.exit(1)

    config_path = Path(sys.argv[1])
    web_root    = Path(sys.argv[2])

    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    with config_path.open() as f:
        cfg = yaml.safe_load(f)

    # ── 1. Write county-config.json ────────────────────────────────────────────
    county_config = {
        # Map / geolocation
        "center":               cfg["county"]["center"],
        "default_zoom":         cfg["county"]["default_zoom"],
        "proximity_radius_km":  cfg["county"]["proximity_radius_km"],

        # PMTiles file basename (becomes tiles/<name>.pmtiles in the container)
        "pmtiles_file":         cfg["data"]["pmtiles_area_name"],

        # UI text
        "title":                cfg["app"]["title"],
        "subtitle":             cfg["app"]["subtitle"],
        "contact_email":        cfg["app"]["contact_email"],
        "county_name":          cfg["county"]["name"],
        "county_state":         cfg["county"]["state"],
    }

    out_json = web_root / "county-config.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(county_config, indent=2))
    print(f"✓ Wrote {out_json}")

    # ── 2. Patch index.html ────────────────────────────────────────────────────
    html_path = web_root / "index.html"
    if not html_path.exists():
        print(f"WARNING: index.html not found at {html_path} — skipping HTML patch",
              file=sys.stderr)
        return

    html = html_path.read_text()
    for placeholder, value_fn in PLACEHOLDER_MAP.items():
        value = value_fn(cfg)
        html = html.replace(placeholder, value)

    html_path.write_text(html)
    print(f"✓ Patched {html_path}")


if __name__ == "__main__":
    main()
