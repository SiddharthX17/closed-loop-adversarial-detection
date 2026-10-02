"""
scripts/fetch_atomic_tests.py

Downloads the Atomic Red Team technique YAML files needed for this
project's emulator, straight from the real upstream repo, at build
time. Driven entirely by config/techniques.yaml -- add or remove a
technique there, rebuild the image, done.

Nothing is vendored in this git repo. This runs once, during
`docker build`, and the fetched files become part of the image layer
-- the running container never re-fetches anything at request time.

Usage:
    python scripts/fetch_atomic_tests.py
(run from the repo root; reads config/techniques.yaml relative to cwd)
"""

import os
import sys
import urllib.request
import urllib.error

import yaml

TECHNIQUES_YAML = "config/techniques.yaml"
OUTPUT_ROOT = "data/atomic-red-team/atomics"

# Pin to a specific commit for build stability. To intentionally pull
# newer upstream test content, bump this to a newer commit SHA from
# https://github.com/redcanaryco/atomic-red-team/commits/master
ATOMIC_RED_TEAM_REF = "master"


def load_active_technique_ids(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("techniques", []) or []


def fetch_technique(tid):
    url = (
        f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
        f"{ATOMIC_RED_TEAM_REF}/atomics/{tid}/{tid}.yaml"
    )
    dest_dir = os.path.join(OUTPUT_ROOT, tid)
    dest_path = os.path.join(dest_dir, f"{tid}.yaml")
    os.makedirs(dest_dir, exist_ok=True)

    try:
        urllib.request.urlretrieve(url, dest_path)
    except urllib.error.HTTPError as e:
        print(
            f"ERROR: failed to fetch {tid} ({url}): HTTP {e.code}", file=sys.stderr)
        sys.exit(1)

    size = os.path.getsize(dest_path)
    print(f"  {tid}: {size} bytes -> {dest_path}")


def main():
    technique_ids = load_active_technique_ids(TECHNIQUES_YAML)
    if not technique_ids:
        print(
            f"No active techniques found in {TECHNIQUES_YAML} -- nothing to fetch.")
        return
    print(f"Fetching {len(technique_ids)} technique(s) from upstream Atomic Red Team "
          f"(ref={ATOMIC_RED_TEAM_REF}):")
    for tid in technique_ids:
        fetch_technique(tid)
    print("Done.")


if __name__ == "__main__":
    main()
