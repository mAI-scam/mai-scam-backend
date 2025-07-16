from fastapi import APIRouter, Request
from datetime import datetime, timedelta, timezone
from models.customResponse import resp_200
from setting import Setting

config = Setting()

router = APIRouter()


@router.get("/")
def api_version(request: Request):
    environment = request.app.state.settings.get("APP_ENV")
    version = request.app.state.settings.get("APP_API_VERSION")

    return resp_200(data={"environment": environment, "version": version}, message="success")
