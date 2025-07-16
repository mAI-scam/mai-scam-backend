from fastapi import APIRouter
from apis import main

router = APIRouter()

# Main routes (e.g. health check, version info)
router.include_router(main.router, prefix="", tags=[
                      "Main"], include_in_schema=True)
