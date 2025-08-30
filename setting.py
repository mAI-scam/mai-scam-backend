import os
import yaml
import re
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
            yaml_content = f.read()
            
        # Step 4: Substitute environment variables in YAML content
        yaml_content = _substitute_env_variables(yaml_content)
        
        # Step 5: Parse the substituted YAML
        config = yaml.safe_load(yaml_content)

    return config


def _substitute_env_variables(yaml_content: str) -> str:
    """
    Substitute ${VARIABLE_NAME} patterns in YAML content with environment variable values
    """
    def replace_env_var(match):
        var_name = match.group(1)
        return os.getenv(var_name, f"${{{var_name}}}")  # Keep original if env var not found
    
    # Replace ${VARIABLE_NAME} with environment variable values
    return re.sub(r'\$\{([^}]+)\}', replace_env_var, yaml_content)
