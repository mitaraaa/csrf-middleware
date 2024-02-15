# Starlette CSRF Middleware

This middleware provides various methods of CSRF protection for Starlette applications.

## How it works?

This section is only for Double Submit Cookie method. Other methods are not implemented yet.

1. User makes a safe request (GET, HEAD, OPTIONS, TRACE) to the server.
2. The server sends a cookie with a CSRF token to the client.s
3. When the client makes a request that changes the server state, the server expects a CSRF token to be sent in request headers.
4. Middleware checks if the token in the request headers matches the token in the cookie.
    - If the tokens match, the request is processed.
    - If the tokens don't match, the request is rejected with `403 Forbidden` status code.

## Installation

Work in progress.

## Usage

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware

from csrf_middleware import CSRFMiddleware

routes = [...]

middleware = [
    Middleware(CSRFMiddleware, secret="secret-key", token_name="csrftoken")
]

app = Starlette(routes=routes, middleware=middleware)
```

## Todo

-   [ ] Implement other methods of CSRF protection.
    -   [x] Double Submit Cookie
    -   [ ] Synchronizer Token Pattern
    -   [ ] Encrypted Token Pattern
    -   [ ] Referer Checking
    -   [ ] Origin Header Checking
-   [ ] Write tests.
-   [ ] Write documentation.
-   [ ] Publish to PyPI.

## References

-   [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
-   [Starlette](https://www.starlette.io/)
-   [Starlette CSRF Middleware](https://github.com/frankie567/starlette-csrf)
