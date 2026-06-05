import json
from pathlib import Path
from dataclasses import dataclass, field

# Relative to pipeline/data/ → up 2 levels = project root
_DEFAULT_STIX_PATH = Path(
    __file__).parents[2] / "data" / "mitre" / "enterprise-attack.json"


@dataclass
class MITREMetadata:
    technique_id: str
    technique_name: str
    tactic: str                      # primary tactic (first in kill chain)
    tactics: list[str]               # all tactics this technique appears under
    data_sources: list[str]          # e.g. ["Process: Process Creation"]
    permissions_required: list[str]  # e.g. ["Administrator", "SYSTEM"]
    detection_hint: str = ""         # MITRE x_mitre_detection free-text guidance


class STIXLoader:
    """
    Loads the MITRE ATT&CK STIX bundle once and indexes techniques by ID.
    Singleton pattern — use the module-level lookup_technique() function.
    """

    def __init__(self, stix_path: Path = _DEFAULT_STIX_PATH):
        self._path = stix_path
        self._index: dict[str, MITREMetadata] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return

        if not self._path.exists():
            raise FileNotFoundError(
                f"[stix_loader] STIX bundle not found at {self._path}\n"
                f"Download from: https://github.com/mitre/cti/raw/master/"
                f"enterprise-attack/enterprise-attack.json"
            )

        with open(self._path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        count = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            # Skip deprecated / revoked entries
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue

            # Extract technique ID from external references
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            self._index[technique_id] = MITREMetadata(
                technique_id=technique_id,
                technique_name=obj.get("name", "Unknown"),
                tactic=tactics[0] if tactics else "unknown",
                tactics=tactics,
                data_sources=obj.get("x_mitre_data_sources", []),
                permissions_required=obj.get(
                    "x_mitre_permissions_required", []),
                detection_hint=obj.get("x_mitre_detection", ""),
            )
            count += 1

        self._loaded = True
        print(f"[stix_loader] Indexed {count} techniques from STIX bundle")

    def lookup(self, technique_id: str) -> MITREMetadata | None:
        """
        Lookup technique metadata by ID.
        Falls back to parent technique if subtechnique not found
        e.g. T1059.001 → T1059 if T1059.001 missing.
        """
        self._load()

        result = self._index.get(technique_id)
        if result is not None:
            return result

        # Subtechnique fallback
        if "." in technique_id:
            base_id = technique_id.split(".")[0]
            result = self._index.get(base_id)
            if result:
                print(
                    f"[stix_loader] No exact match for {technique_id}, "
                    f"falling back to parent {base_id}"
                )
            return result

        return None

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def technique_count(self) -> int:
        self._load()
        return len(self._index)


# Module-level singleton
_loader = STIXLoader()


def lookup_technique(technique_id: str) -> MITREMetadata | None:
    """Public interface — prefer this over instantiating STIXLoader directly."""
    return _loader.lookup(technique_id)


def get_loader(stix_path: Path | None = None) -> STIXLoader:
    """
    Returns the default singleton, or a new loader for a custom path.
    Useful for testing with a custom STIX fixture.
    """
    if stix_path is not None:
        return STIXLoader(stix_path)
    return _loader
