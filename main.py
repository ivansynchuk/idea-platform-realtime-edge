"""
Realtime edge — standalone Socket.IO transport service (strangler Phase 1/2/4).

A stateless transport edge for the NestJS monolith's WebSocket layer:
  * validates the monolith's JWT cryptographically (HS256, shared JWT_SECRET),
  * has ZERO database access (no SQLAlchemy / asyncpg / drivers),
  * joins each authenticated socket to its personal `user:{id}` room,
  * bridges monolith broadcasts: a background consumer reads the
    `edge:downstream` Redis stream (consumer group `edge`) and re-emits each
    DownstreamEnvelope to the matching Socket.IO namespace + room.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
from contextlib import asynccontextmanager
from typing import Any

import jwt
import redis.asyncio as redis_async
import socketio
from fastapi import FastAPI
from pydantic import BaseModel, ValidationError
from redis.exceptions import ResponseError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("realtime-edge")

# --- Configuration (environment) ---------------------------------------------

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

JWT_ALGORITHM = "HS256"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")

# --- Redis bridge constants ---------------------------------------------------

DOWNSTREAM_STREAM = "edge:downstream"
CONSUMER_GROUP = "edge"
DLQ_STREAM = "edge:downstream:dlq"
READ_COUNT = 50
BLOCK_MS = 5000
DLQ_MAXLEN = 10_000

# Maps the envelope namespace name to the Socket.IO namespace path.
NAMESPACE_BY_NAME = {"root": "/", "live-chat": "/live-chat"}
LIVE_CHAT_NAMESPACE = "/live-chat"

# --- Socket.IO server ---------------------------------------------------------

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[FRONTEND_URL],
)


# --- Downstream envelope schema (must match backend realtime.types.ts) --------


class DownstreamTarget(BaseModel):
    type: str
    room: str


class DownstreamMeta(BaseModel):
    id: str | None = None
    ts: str | None = None
    source: str | None = None


class DownstreamEnvelope(BaseModel):
    v: int
    namespace: str
    target: DownstreamTarget
    event: str
    payload: Any = None
    meta: DownstreamMeta | None = None


# --- Auth helpers -------------------------------------------------------------


def _extract_token(auth: object, environ: dict) -> str | None:
    """Token from the Socket.IO `auth` payload (auth.token), falling back to a
    Bearer Authorization header — mirroring the monolith's handshake."""
    if isinstance(auth, dict):
        token = auth.get("token")
        if isinstance(token, str) and token:
            return token

    header = environ.get("HTTP_AUTHORIZATION", "")
    if isinstance(header, str) and header.startswith("Bearer "):
        token = header[len("Bearer ") :].strip()
        if token:
            return token

    return None


def _resolve_user_id(claims: dict) -> str | None:
    """The monolith signs the user id in the `id` claim (see
    backend/src/notification/lib/ws-auth.util.ts). `sub`/`userId` are accepted
    as fallbacks for forward-compatibility."""
    for key in ("id", "sub", "userId"):
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    return None


async def _authenticate_socket(
    sid: str, environ: dict, auth: object, namespace: str = "/"
) -> str:
    """Strict, stateless JWT handshake shared by every namespace.

    Returns the authenticated user id or raises ConnectionRefusedError. No DB
    access — the token signature and claims are the sole source of truth."""
    # Defense-in-depth: reject HTTP long-polling. Fail open if the transport
    # cannot be determined so a valid client is never blocked.
    try:
        transport = sio.transport(sid, namespace=namespace)
    except Exception:  # pragma: no cover - python-socketio API/version safety
        transport = None
    if transport == "polling":
        raise socketio.exceptions.ConnectionRefusedError(
            "websocket transport required"
        )

    token = _extract_token(auth, environ)
    if not token:
        raise socketio.exceptions.ConnectionRefusedError("missing auth token")

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise socketio.exceptions.ConnectionRefusedError("invalid token") from exc

    user_id = _resolve_user_id(claims)
    if not user_id:
        raise socketio.exceptions.ConnectionRefusedError("token missing user id")

    return user_id


def _extract_room_id(data: object) -> str | None:
    """Pull a non-empty `roomId` from a join/leave payload."""
    if isinstance(data, dict):
        room_id = data.get("roomId")
        if isinstance(room_id, str) and room_id:
            return room_id
    return None


def _live_chat_room(room_id: str) -> str:
    """Socket.IO room name for a live-chat room (matches the monolith)."""
    return f"live-chat:{room_id}"


# --- Socket.IO handlers: root namespace ("/") --------------------------------


@sio.event
async def connect(sid: str, environ: dict, auth: object) -> None:
    user_id = await _authenticate_socket(sid, environ, auth)
    await sio.save_session(sid, {"user_id": user_id})
    await sio.enter_room(sid, f"user:{user_id}")
    logger.info("socket %s authenticated as user %s (root)", sid, user_id)


@sio.event
async def disconnect(sid: str) -> None:
    logger.info("socket %s disconnected (root)", sid)


# --- Socket.IO handlers: "/live-chat" namespace ------------------------------
#
# NOTE: room *authorization* (the monolith's assertRoomAccess) requires DB
# access and is out of scope for this stateless edge. join_room only validates
# that a roomId is present; enforcing membership must happen upstream (the
# monolith) in a later phase.


@sio.on("connect", namespace=LIVE_CHAT_NAMESPACE)
async def live_chat_connect(sid: str, environ: dict, auth: object) -> None:
    user_id = await _authenticate_socket(
        sid, environ, auth, namespace=LIVE_CHAT_NAMESPACE
    )
    await sio.save_session(sid, {"user_id": user_id}, namespace=LIVE_CHAT_NAMESPACE)
    await sio.emit("connection_ready", to=sid, namespace=LIVE_CHAT_NAMESPACE)
    logger.info("socket %s authenticated as user %s (/live-chat)", sid, user_id)


@sio.on("disconnect", namespace=LIVE_CHAT_NAMESPACE)
async def live_chat_disconnect(sid: str) -> None:
    logger.info("socket %s disconnected (/live-chat)", sid)


@sio.on("join_room", namespace=LIVE_CHAT_NAMESPACE)
async def live_chat_join_room(sid: str, data: object):
    session = await sio.get_session(sid, namespace=LIVE_CHAT_NAMESPACE)
    if not session.get("user_id"):
        return {"ok": False, "error": "Unauthorized"}

    room_id = _extract_room_id(data)
    if not room_id:
        return {"ok": False, "error": "roomId is required"}

    await sio.enter_room(sid, _live_chat_room(room_id), namespace=LIVE_CHAT_NAMESPACE)
    return {"ok": True}


@sio.on("leave_room", namespace=LIVE_CHAT_NAMESPACE)
async def live_chat_leave_room(sid: str, data: object):
    room_id = _extract_room_id(data)
    if not room_id:
        return {"ok": False, "error": "roomId is required"}

    await sio.leave_room(sid, _live_chat_room(room_id), namespace=LIVE_CHAT_NAMESPACE)
    return {"ok": True}


# --- Redis downstream bridge (Phase 4) ----------------------------------------


def _resolve_namespace(name: str) -> str:
    """Map an envelope namespace name to a Socket.IO namespace path."""
    if name in NAMESPACE_BY_NAME:
        return NAMESPACE_BY_NAME[name]
    return "/" + name.lstrip("/")


async def _emit_envelope(envelope: DownstreamEnvelope) -> None:
    """Forward a validated envelope to its target Socket.IO namespace + room."""
    await sio.emit(
        envelope.event,
        envelope.payload,
        room=envelope.target.room,
        namespace=_resolve_namespace(envelope.namespace),
    )


async def _ensure_group(client: redis_async.Redis) -> None:
    """Create the `edge` consumer group on `edge:downstream` (idempotent).

    Starts at `$` so the edge only receives broadcasts produced after it comes
    online — stale broadcasts are never replayed (the monolith + DB remain the
    source of truth for history)."""
    try:
        await client.xgroup_create(
            DOWNSTREAM_STREAM, CONSUMER_GROUP, id="$", mkstream=True
        )
        logger.info(
            "created consumer group '%s' on '%s'", CONSUMER_GROUP, DOWNSTREAM_STREAM
        )
    except ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            logger.info("consumer group '%s' already exists", CONSUMER_GROUP)
        else:
            raise


async def _handle_message(
    client: redis_async.Redis, msg_id: str, fields: dict
) -> None:
    """Validate, route, and acknowledge a single stream entry.

    Poison messages (missing/invalid JSON or schema) are moved to the DLQ and
    acked so they never block the group. The entry is acked only after a
    successful emit; emit failures leave it pending for later reclaim."""
    raw = fields.get("payload")
    try:
        if raw is None:
            raise ValueError("stream entry missing 'payload' field")
        envelope = DownstreamEnvelope.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        logger.warning("poison message %s -> DLQ: %s", msg_id, exc)
        await client.xadd(
            DLQ_STREAM,
            {"payload": raw if raw is not None else "", "error": str(exc)},
            maxlen=DLQ_MAXLEN,
            approximate=True,
        )
        await client.xack(DOWNSTREAM_STREAM, CONSUMER_GROUP, msg_id)
        return

    try:
        await _emit_envelope(envelope)
    except Exception:
        # Transient delivery failure: do NOT ack so the entry stays pending and
        # can be reclaimed (XAUTOCLAIM) later. A single pending entry does not
        # block new messages read with '>'.
        logger.exception("emit failed for %s; leaving unacked", msg_id)
        return

    await client.xack(DOWNSTREAM_STREAM, CONSUMER_GROUP, msg_id)


async def _downstream_listener(client: redis_async.Redis) -> None:
    """Infinite XREADGROUP loop bridging `edge:downstream` to Socket.IO."""
    consumer = f"{socket.gethostname()}-{os.getpid()}"
    logger.info(
        "downstream listener started (group=%s consumer=%s)",
        CONSUMER_GROUP,
        consumer,
    )
    while True:
        try:
            response = await client.xreadgroup(
                CONSUMER_GROUP,
                consumer,
                {DOWNSTREAM_STREAM: ">"},
                count=READ_COUNT,
                block=BLOCK_MS,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("XREADGROUP failed; backing off 1s")
            await asyncio.sleep(1)
            continue

        if not response:
            continue

        for _stream, messages in response:
            for msg_id, fields in messages:
                await _handle_message(client, msg_id, fields)


# --- App lifespan + FastAPI ---------------------------------------------------


@asynccontextmanager
async def lifespan(_app: FastAPI):
    redis_client = redis_async.from_url(REDIS_URL, decode_responses=True)
    await _ensure_group(redis_client)
    listener = asyncio.create_task(_downstream_listener(redis_client))
    logger.info("realtime edge ready (redis=%s)", REDIS_URL)
    try:
        yield
    finally:
        listener.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await listener
        await redis_client.aclose()
        logger.info("realtime edge shut down")


fastapi_app = FastAPI(title="Realtime Edge", version="0.1.0", lifespan=lifespan)


@fastapi_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# Combined ASGI app: /socket.io/* -> Socket.IO, everything else -> FastAPI.
# socketio.ASGIApp forwards the ASGI lifespan scope to other_asgi_app, so the
# FastAPI lifespan above (and the Redis listener) runs under uvicorn.
app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app, socketio_path="socket.io")
