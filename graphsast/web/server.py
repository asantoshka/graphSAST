"""FastAPI web server for GraphSAST — graph + findings visualization."""

from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from graphsast.web.routes import findings as findings_router
from graphsast.web.routes import graph as graph_router
from graphsast.web.routes import stats as stats_router

_STATIC = Path(__file__).parent / "static"


def create_app(db_path: Path, target: Path) -> FastAPI:
    """Create the FastAPI application bound to a project's graph.db."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[type-arg]
        # Validate DB is readable
        if not db_path.exists():
            raise RuntimeError(
                f"graph.db not found at {db_path}. "
                "Run `graphsast scan <target>` first."
            )
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        app.state.db = conn
        app.state.db_path = db_path
        app.state.target = str(target)
        yield
        conn.close()

    app = FastAPI(
        title="GraphSAST UI",
        description="Security graph + findings visualization",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.include_router(graph_router.router, prefix="/api/graph")
    app.include_router(findings_router.router, prefix="/api/findings")
    app.include_router(stats_router.router, prefix="/api")

    # Serve static files (JS/CSS)
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    # SPA catch-all — serve index.html for any non-API route
    @app.get("/", include_in_schema=False)
    async def root() -> FileResponse:
        return FileResponse(str(_STATIC / "index.html"))

    return app
