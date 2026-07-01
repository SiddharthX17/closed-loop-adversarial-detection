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

# MITRE STIX bundle — metadata only, small file, no trimming needed
COPY data/mitre/ data/mitre/

# Atomic Red Team — ONLY the 5 in-scope technique YAML files, not the full
# repo. We never execute these tests, just feed the YAML procedure text to
# the LLM, so no scripts/payloads/.git history are needed. Filenames
# verified against actual local clone via successful build.
COPY data/atomic-red-team/atomics/T1059.001/T1059.001.yaml data/atomic-red-team/atomics/T1059.001/T1059.001.yaml
COPY data/atomic-red-team/atomics/T1053.005/T1053.005.yaml data/atomic-red-team/atomics/T1053.005/T1053.005.yaml
COPY data/atomic-red-team/atomics/T1036.005/T1036.005.yaml data/atomic-red-team/atomics/T1036.005/T1036.005.yaml
COPY data/atomic-red-team/atomics/T1003.001/T1003.001.yaml data/atomic-red-team/atomics/T1003.001/T1003.001.yaml
COPY data/atomic-red-team/atomics/T1567.003/T1567.003.yaml data/atomic-red-team/atomics/T1567.003/T1567.003.yaml
COPY data/atomic-red-team/atomics/T1003.002/T1003.002.yaml data/atomic-red-team/atomics/T1003.002/T1003.002.yaml

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