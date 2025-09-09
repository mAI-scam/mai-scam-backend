import os
import yaml
import re
from pathlib import Path
from dotenv import load_dotenv


def Setting() -> dict:
    # Step 1: Load environment variables from .env file (don't override in Lambda)
    # In Lambda, prefer Lambda environment variables over .env file
    is_lambda = os.getenv('AWS_LAMBDA_FUNCTION_NAME') is not None
    load_dotenv(override=not is_lambda)
    
    # Step 2: Determine environment
    env_name = os.getenv("APP_ENV", "uat").lower()
    config_path = Path(__file__).resolve().parent / "env" / f"{env_name}.yaml"

    # Debug logging
    print(f"DEBUG: AWS_LAMBDA_FUNCTION_NAME = {os.getenv('AWS_LAMBDA_FUNCTION_NAME')}")
    print(f"DEBUG: is_lambda = {is_lambda}")
    print(f"DEBUG: APP_ENV = {os.getenv('APP_ENV')}")
    print(f"DEBUG: env_name = {env_name}")
    print(f"DEBUG: config_path = {config_path}")
    print(f"DEBUG: config_path.exists() = {config_path.exists()}")

    # Step 3: Load YAML if it exists
    config = {}
    if config_path.exists():
        with open(config_path, "r") as f:
            yaml_content = f.read()
            
        # Step 4: Substitute environment variables in YAML content
        yaml_content = _substitute_env_variables(yaml_content)
        
        # Step 5: Parse the substituted YAML
        config = yaml.safe_load(yaml_content)
        print(f"DEBUG: Loaded config with SMTP_HOST = {config.get('SMTP_HOST')}")
    else:
        print(f"DEBUG: Config file not found at {config_path}")

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
