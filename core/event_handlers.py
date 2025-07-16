import logging
from fastapi import FastAPI
from typing import Callable
from setting import Setting

config = Setting()
logger = logging.getLogger("Application Initialization")


def _startup(app: FastAPI) -> None:
    app.state.settings = {
        "APP_ENV": config.get("APP_ENV"),
        "APP_API_VERSION": config.get("APP_API_VERSION")
    }


def start_app_handler(app: FastAPI) -> Callable:
    def startup() -> None:
        logging.info("Starting up...")
        _startup(app)

    return startup


def stop_app_handler(app: FastAPI) -> Callable:
    def shuddown() -> None:
        logging.info("Shutting down...")

    return shuddown
