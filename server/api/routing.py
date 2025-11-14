from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from server.dtos.AppDetails import AppDetails



router = APIRouter()

limiter = Limiter(key_func=get_remote_address)



@router.post(
    "/api/",
    summary="",
    description="""
""",
    responses={
        200: {"description": "hacked"},
    }
)
@limiter.limit("10/second")
async def ask_sth(payload: AppDetails, request: Request) -> JSONResponse:
    return JSONResponse(
                status_code=200,
                content={
                    "are you hacked": True
                }
            )