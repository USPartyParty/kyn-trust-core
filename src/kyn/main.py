"""Standalone KYN ASGI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from kyn.api import router
from kyn.auth import ActionAuthorizationError
from kyn.config import Settings, get_settings, read_secret_file
from kyn.crypto import Ed25519Signer
from kyn.database import create_database_engine, create_session_factory
from kyn.models import TrustPolicy
from kyn.persistence import DurableStateError, DurableTrustService
from kyn.service import TrustCore, TrustCoreError


def create_core_factory(
    *, settings: Settings, signing_seed: bytes, pairwise_secret: bytes, receipt_secret: bytes
) -> Callable[[], TrustCore]:
    def factory() -> TrustCore:
        return TrustCore(
            issuer=str(settings.issuer).rstrip("/"),
            signer=Ed25519Signer.from_seed(settings.signing_key_id, signing_seed),
            pairwise_secret=pairwise_secret,
            receipt_secret=receipt_secret,
            policy=TrustPolicy(
                profile_id=settings.policy_profile,
                enforce_authority=True,
                enforce_release=True,
                require_consent=True,
                bootstrap_public_label=settings.bootstrap_public_label,
            ),
        )

    return factory


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        signing_seed = read_secret_file(resolved.signing_seed_file, expected_bytes=32)
        pairwise_secret = read_secret_file(resolved.pairwise_secret_file)
        receipt_secret = read_secret_file(resolved.receipt_secret_file)
        bootstrap_token = read_secret_file(resolved.bootstrap_token_file)
        engine = create_database_engine(resolved.resolved_database_url())
        app.state.database_engine = engine
        app.state.trust_service = DurableTrustService(
            session_factory=create_session_factory(engine),
            core_factory=create_core_factory(
                settings=resolved,
                signing_seed=signing_seed,
                pairwise_secret=pairwise_secret,
                receipt_secret=receipt_secret,
            ),
        )
        app.state.bootstrap_token = bootstrap_token
        app.state.action_clock_skew_seconds = resolved.action_clock_skew_seconds
        yield
        await engine.dispose()

    app = FastAPI(
        title="Know Your Neighbor Trust Core",
        version="0.3.0",
        docs_url=None if resolved.environment == "production" else "/docs",
        openapi_url=None if resolved.environment == "production" else "/openapi.json",
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(ActionAuthorizationError)
    async def action_auth_error(_request: Request, exc: ActionAuthorizationError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(TrustCoreError)
    async def trust_core_error(_request: Request, exc: TrustCoreError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(DurableStateError)
    async def durable_state_error(_request: Request, exc: DurableStateError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.get("/v1/system/health")
    async def health(request: Request) -> dict[str, str]:
        async with request.app.state.database_engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return {"status": "ok", "policy_profile": resolved.policy_profile}

    app.include_router(router, prefix="/v1")
    return app
