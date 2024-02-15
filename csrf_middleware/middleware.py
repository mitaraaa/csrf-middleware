import functools
import secrets
from http.cookies import SimpleCookie

from itsdangerous import BadSignature
from itsdangerous.url_safe import URLSafeSerializer
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class CSRFMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        cookie_name: str = "csrftoken",
        cookie_domain: str = None,
        cookie_path: str = "/",
        cookie_secure: bool = False,
        cookie_httponly: bool = True,
        cookie_samesite: str = "Lax",
        header_name: str = "X-CSRFToken",
    ) -> None:
        self.app = app

        self.serializer = URLSafeSerializer(secret, cookie_name)
        self.header_name = header_name

        self.cookie_name = cookie_name
        self.cookie_domain = cookie_domain
        self.cookie_path = cookie_path
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        if request.method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            csrf_cookie = request.cookies.get(self.cookie_name)
            submitted_token = request.headers.get(self.header_name)

            if (
                not csrf_cookie
                or not submitted_token
                or not self._matching_tokens(csrf_cookie, submitted_token)
            ):
                response = PlainTextResponse(
                    "CSRF verification failed", status_code=403
                )
                await response(scope, receive, send)
                return

        send = functools.partial(self.send, send=send, scope=scope)
        await self.app(scope, receive, send)

    async def send(self, message: Message, send: Send, scope: Scope) -> None:
        request = Request(scope)
        csrf_cookie = request.cookies.get(self.cookie_name)

        if not csrf_cookie:
            message.setdefault("headers", [])
            headers = MutableHeaders(scope=message)

            cookie = self._build_cookie()

            headers.append(*("set-cookie", cookie.output(header="").strip()))

        await send(message)

    def _build_cookie(self) -> SimpleCookie:
        cookie = SimpleCookie()

        cookie[self.cookie_name] = self._generate_csrf_token()
        cookie[self.cookie_name]["path"] = self.cookie_path
        cookie[self.cookie_name]["secure"] = self.cookie_secure
        cookie[self.cookie_name]["httponly"] = self.cookie_httponly
        cookie[self.cookie_name]["samesite"] = self.cookie_samesite
        if self.cookie_domain is not None:
            cookie[self.cookie_name]["domain"] = self.cookie_domain

        return cookie

    def _generate_csrf_token(self) -> str:
        return self.serializer.dumps(secrets.token_urlsafe(128))

    def _matching_tokens(self, token1: str, token2: str) -> bool:
        try:
            decoded1 = self.serializer.loads(token1)
            decoded2 = self.serializer.loads(token2)
            return secrets.compare_digest(decoded1, decoded2)
        except BadSignature:
            return False
