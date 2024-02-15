import contextlib

import httpx
import pytest
from asgi_lifespan import LifespanManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from csrf_middleware import CSRFMiddleware


def get_app(**middleware_kwargs):
    async def get(request: Request):
        return JSONResponse({"item": "get"})

    async def post(response: Response):
        return JSONResponse({"item": "created"})

    app = Starlette(
        debug=True,
        routes=[
            Route("/", get, methods=["GET"]),
            Route("/", post, methods=["POST"]),
        ],
        middleware=[Middleware(CSRFMiddleware, secret="secret", **middleware_kwargs)],
    )

    return app


@contextlib.asynccontextmanager
async def get_test_client(app: Starlette):
    async with LifespanManager(app):
        async with httpx.AsyncClient(app=app, base_url="http://localhost") as client:
            yield client


@pytest.mark.asyncio
async def test_get():
    async with get_test_client(get_app()) as client:
        response = await client.get("/")

        assert "csrftoken" in response.cookies


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookies,headers",
    [
        [{}, {}],
        [{"csrftoken": "invalid"}, {}],
        [{}, {"X-CSRFToken": "invalid"}],
        [{"csrftoken": "invalid"}, {"X-CSRFToken": "invalid"}],
    ],
)
async def test_invalid_post(cookies: dict[str, str], headers: dict[str, str]):
    async with get_test_client(get_app()) as client:
        response = await client.post("/", cookies=cookies, headers=headers)
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_valid_post():
    async with get_test_client(get_app()) as client:
        response = await client.get("/")
        csrftoken = response.cookies["csrftoken"]

        response = await client.post("/", headers={"X-CSRFToken": csrftoken})
        assert response.status_code == 200
