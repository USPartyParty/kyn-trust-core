"""Transactional durable snapshot and idempotency store for the KYN beta."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from kyn.contracts import TrustRecord, from_record, to_record
from kyn.crypto import canonical_json
from kyn.models import JsonValue, Receipt
from kyn.service import TrustCore, TrustCoreError


class Base(DeclarativeBase):
    pass


class KynStateModel(Base):
    __tablename__ = "kyn_state"

    singleton_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KynCommandModel(Base):
    __tablename__ = "kyn_commands"

    command_id: Mapped[str] = mapped_column(String(240), primary_key=True)
    operation: Mapped[str] = mapped_column(String(120), nullable=False)
    actor_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    result_records: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    response_payload: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DurableStateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    records: tuple[TrustRecord, ...]
    receipt: Receipt
    replayed: bool
    response_payload: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class TransitionResult:
    records: tuple[TrustRecord, ...]
    receipt: Receipt
    response_payload: dict[str, object] | None = None


type Transition = Callable[[TrustCore], TransitionResult]


class DurableTrustService:
    """Loads, mutates, and atomically snapshots one KYN trust domain per command."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        core_factory: Callable[[], TrustCore],
    ) -> None:
        self._session_factory = session_factory
        self._core_factory = core_factory

    async def execute(
        self,
        *,
        command_id: str,
        operation: str,
        actor_reference: str,
        request_payload: dict[str, JsonValue],
        transition: Transition,
    ) -> ExecutionResult:
        request_digest = f"sha256:{hashlib.sha256(canonical_json(request_payload)).hexdigest()}"
        async with self._session_factory() as session, session.begin():
            existing = await session.get(KynCommandModel, command_id)
            if existing is not None:
                if existing.request_digest != request_digest or existing.operation != operation:
                    raise DurableStateError("command identifier was reused for different input")
                records = tuple(from_record(item) for item in existing.result_records)
                if not records or not isinstance(records[-1], Receipt):
                    raise DurableStateError("stored command result has no receipt")
                return ExecutionResult(
                    records=records[:-1],
                    receipt=records[-1],
                    replayed=True,
                    response_payload=existing.response_payload,
                )

            state = await session.scalar(
                select(KynStateModel).where(KynStateModel.singleton_id == 1).with_for_update()
            )
            core = self._core_factory()
            if state is not None:
                core.restore_snapshot(state.snapshot)
            try:
                transitioned = transition(core)
            except TrustCoreError:
                raise
            serialized = [to_record(item) for item in (*transitioned.records, transitioned.receipt)]
            now = datetime.now(tz=UTC)
            if state is None:
                state = KynStateModel(
                    singleton_id=1,
                    version=1,
                    snapshot=core.export_snapshot(),
                    updated_at=now,
                )
                session.add(state)
            else:
                state.version += 1
                state.snapshot = core.export_snapshot()
                state.updated_at = now
            session.add(
                KynCommandModel(
                    command_id=command_id,
                    operation=operation,
                    actor_reference=actor_reference,
                    request_digest=request_digest,
                    receipt_id=transitioned.receipt.receipt_id,
                    result_records=serialized,
                    response_payload=transitioned.response_payload,
                    occurred_at=transitioned.receipt.occurred_at,
                )
            )
            return ExecutionResult(
                records=transitioned.records,
                receipt=transitioned.receipt,
                replayed=False,
                response_payload=transitioned.response_payload,
            )

    async def load_core(self) -> TrustCore:
        async with self._session_factory() as session:
            state = await session.get(KynStateModel, 1)
            core = self._core_factory()
            if state is not None:
                core.restore_snapshot(state.snapshot)
            return core
