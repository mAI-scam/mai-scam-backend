from fastapi import APIRouter
from apis import main
from apis import email

router = APIRouter()

# Main routes (e.g. health check, version info)
router.include_router(main.router, prefix="", tags=[
                      "Main"], include_in_schema=True)

# Email routes
router.include_router(email.router, prefix="/email", tags=[
                      "Email"], include_in_schema=True)
