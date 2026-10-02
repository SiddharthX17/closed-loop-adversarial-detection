# ---------------------------------------------------------------------------
# Closed-Loop Adversarial Detection Pipeline — Cloud Run Service
# ---------------------------------------------------------------------------
# Image bakes in: 5 in-scope Atomic Red Team technique YAMLs, STIX bundle,
# and benign corpus. No runtime GCS reads required. sentence-transformers/
# torch removed (gap scorer + embedder retired). Target: stay under the
# 0.5GB Artifact Registry free tier.
# ---------------------------------------------------------------------------

FROM python:3.11-slim

WORKDIR /app

# Install Python deps first — layer cache survives code-only changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# NOTE: build-essential/git removed — pydantic-core, pandas, etc. ship
# prebuilt wheels for python3.11-slim/linux. If a `pip install` above fails
# with a compiler error, add back:
#   RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
# NOTE: sentence-transformers preload removed — gap scorer + embedder retired,
# torch is no longer a dependency. If this comes back in scope, re-add:
#   RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# ---------------------------------------------------------------------------
# Application code and data
# ---------------------------------------------------------------------------
COPY pipeline/  pipeline/
COPY config/    config/
COPY rules/     rules/
COPY corpus/    corpus/

# MITRE STIX bundle — metadata only. Fetched at build time instead of
# vendored in git (was 44MB, stripped from history 2026-09). Source is
# MITRE's own attack-stix-data repo. Uses stdlib urllib, not curl --
# python:3.11-slim doesn't ship curl and this avoids adding it.
RUN mkdir -p data/mitre && \
    python -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json', 'data/mitre/enterprise-attack.json')"

# Atomic Red Team — fetched at build time, driven entirely by
# config/techniques.yaml (must be copied in before this step runs).
# Rotating which techniques are in scope is a one-line edit to that
# file.
COPY scripts/fetch_atomic_tests.py scripts/fetch_atomic_tests.py
RUN python scripts/fetch_atomic_tests.py

# ---------------------------------------------------------------------------
# Runtime
# Cloud Run injects PORT (default 8080). uvicorn reads it at startup.
# Single worker — pipeline is CPU/API-bound and runs one job at a time.
# ---------------------------------------------------------------------------
ENV PORT=8080

EXPOSE 8080

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
 
ENTRYPOINT ["/entrypoint.sh"]