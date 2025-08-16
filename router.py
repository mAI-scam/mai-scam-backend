from fastapi import APIRouter
from apis import main
from apis import email
from apis import socialmedia
from apis import website

router = APIRouter()

# Main routes (e.g. health check, version info)
router.include_router(main.router, prefix="", tags=[
                      "Main"], include_in_schema=True)

# Email routes
router.include_router(email.router, prefix="/email", tags=[
                      "Email"], include_in_schema=True)

# Social Media routes
router.include_router(socialmedia.router, prefix="/socialmedia", tags=[
                      "Social Media"], include_in_schema=True)

# Website routes
router.include_router(website.router, prefix="/website", tags=[
                      "Website"], include_in_schema=True)
