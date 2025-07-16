import os
import yaml
from pathlib import Path
from dotenv import load_dotenv


def Setting() -> dict:
    # Step 1: Load environment variables from .env file (always override existing values)
    load_dotenv(override=True)
    
    # Step 2: Determine environment
    env_name = os.getenv("APP_ENV", "uat").lower()
    config_path = Path(__file__).resolve().parent / "env" / f"{env_name}.yaml"

    # Step 3: Load YAML if it exists
    config = {}
    if config_path.exists():
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

    return config
