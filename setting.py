import os
import yaml
from pathlib import Path


def Setting() -> dict:
    # Step 1: Determine environment
    env_name = os.getenv("APP_ENV").lower()
    config_path = Path(__file__).resolve().parent / "env" / f"{env_name}.yaml"

    # Step 2: Load YAML if it exists
    config = {}
    if config_path.exists():
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

    return config
