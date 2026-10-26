"""FastAPI application: JSON API under /api, and the built React app when no nginx is in front."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import __version__, logsetup
from ..config import get_settings
from . import auth, cluster, ddns, firewall, groups, legal, protection, queries, rpz, settings, system, templates, transfers, users, zones


def _field(loc: tuple) -> str:
    parts = [str(p) for p in loc if p not in ("body", "query", "path")]
    return ".".join(parts) or "request"


def create_app() -> FastAPI:
    logsetup.setup("api")
    app = FastAPI(title="DNSOne", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        body = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail), "errors": {}}
        return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors: dict[str, str] = {}
        for err in exc.errors():
            errors.setdefault(_field(err.get("loc", ())), err.get("msg", "Invalid value").removeprefix("Value error, "))
        first = next(iter(errors.values()), "Invalid request.")
        return JSONResponse({"message": first, "errors": errors}, status_code=422)

    @app.middleware("http")
    async def no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            # An open console compares this with the version it loaded with, and offers a reload after an update.
            response.headers["X-DNSOne-Version"] = __version__
        return response

    for module in (auth, zones, transfers, ddns, templates, rpz, legal, groups, queries, protection, firewall, users, settings, cluster, system):
        app.include_router(module.router)

    dist = get_settings().frontend_dist
    if dist and (dist / "index.html").exists():
        # Development / no-nginx mode: serve the SPA; unknown paths fall back to index.html.
        root = dist.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"message": "Not found.", "errors": {}}, status_code=404)
            candidate = (root / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(root):
                return FileResponse(candidate)
            return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
