import yaml
from pathlib import Path


def load_valid_fields(mapping_path: str = "config/field_mapping.yaml") -> set[str]:
    with open(mapping_path) as f:
        data = yaml.safe_load(f)
    return set(data["valid_fields"])
