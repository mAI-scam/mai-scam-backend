from fastapi import status
from fastapi.responses import JSONResponse
from typing import Union


def resp_200(*, data: Union[list, dict, str] = {}, message: str = "Success") -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "code": 200,
            "message": message,
            "success": True,
            "data": data
        }
    )


def resp_400(*, data: str = None, message: str = "Bad Request") -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "code": 400,
            "message": message,
            "success": False,
            "data": data
        }
    )


def resp_403(*, data: str = None, message: str = "Forbidden") -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "code": 403,
            "message": message,
            "success": False,
            "data": data
        }
    )


def resp_500(*, data: str = None, message: str = "Internal Server Error") -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": 500,
            "message": message,
            "success": False,
            "data": data
        }
    )
