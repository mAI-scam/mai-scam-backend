
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from setting import Setting
from router import router as api_router
from core.event_handlers import start_app_handler, stop_app_handler
import uvicorn

config = Setting()


def get_application() -> FastAPI:
    application = FastAPI(
        title="ELZ AI API",
        debug=False,
        version="0.0.0"
    )

    # CORS settings - allow frontend to call API across domains
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register lifecycle event handlers
    application.add_event_handler("startup", start_app_handler(application))
    application.add_event_handler("shutdown", stop_app_handler(application))

    # Include all API routes
    application.include_router(api_router)

    # Enforce OpenAPI spec version
    application.openapi_version = "3.0.2"

    return application


app = get_application()

if __name__ == "__main__":
    server_url = config.get("SERVER_HOST")
    server_port = config.get("SERVER_PORT")

    uvicorn.run(app, host="0.0.0.0", port=8000)
