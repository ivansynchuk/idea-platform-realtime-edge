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
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

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
UPSTREAM_STREAM = "edge:upstream"
CONSUMER_GROUP = "edge"
DLQ_STREAM = "edge:downstream:dlq"
READ_COUNT = 50
BLOCK_MS = 5000
DLQ_MAXLEN = 10_000
UPSTREAM_MAXLEN = 100_000

# Identifies this edge process in upstream envelopes and as the consumer name.
WORKER_ID = f"{socket.gethostname()}-{os.getpid()}"

# Shared Redis client, assigned during the FastAPI lifespan startup.
redis_client: redis_async.Redis | None = None

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
    type: str  # "room" (broadcast) | "sid" (single socket, e.g. control events)
    room: str | None = None
    sid: str | None = None


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


class UpstreamMeta(BaseModel):
    id: str
    ts: str
    source: str = "edge"
    worker: str | None = None


class UpstreamEnvelope(BaseModel):
    """Client-originated event forwarded edge -> monolith over edge:upstream.

    `userId` is stamped from the verified JWT session and is authoritative; the
    monolith must ignore any identity embedded in `payload`."""

    v: int = 1
    event: str
    userId: str
    sid: str | None = None
    clientMsgId: str
    payload: Any = None
    meta: UpstreamMeta


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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _publish_upstream(
    event: str,
    user_id: str,
    payload: Any,
    sid: str | None = None,
    client_msg_id: str | None = None,
) -> str | None:
    """Stamp identity and XADD a client-originated event to edge:upstream.

    Returns the correlation clientMsgId, or None if Redis is not ready."""
    if redis_client is None:
        logger.error("cannot publish upstream '%s': redis not ready", event)
        return None

    correlation_id = client_msg_id or uuid4().hex
    envelope = UpstreamEnvelope(
        event=event,
        userId=user_id,
        sid=sid,
        clientMsgId=correlation_id,
        payload=payload,
        meta=UpstreamMeta(id=uuid4().hex, ts=_now_iso(), worker=WORKER_ID),
    )
    await redis_client.xadd(
        UPSTREAM_STREAM,
        {"payload": envelope.model_dump_json()},
        maxlen=UPSTREAM_MAXLEN,
        approximate=True,
    )
    return correlation_id


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
async def live_chat_join_room(sid: str, data: object) -> None:
    # Asynchronous authorization: the edge cannot authorize a room join (no DB).
    # It forwards a request upstream and joins the socket only when the monolith
    # replies with room:join_approved on edge:downstream. No synchronous ack.
    session = await sio.get_session(sid, namespace=LIVE_CHAT_NAMESPACE)
    user_id = session.get("user_id")
    room_id = _extract_room_id(data)

    if not user_id or not room_id:
        # A malformed/unauthenticated request the edge can reject locally — sent
        # as an async event (not a callback ack) to match the approve/deny flow.
        await sio.emit(
            "room:join_denied",
            {"roomId": room_id, "reason": "roomId is required"},
            to=sid,
            namespace=LIVE_CHAT_NAMESPACE,
        )
        return

    await _publish_upstream(
        event="room:request_join",
        user_id=user_id,
        sid=sid,
        payload={"roomId": room_id},
    )


@sio.on("send_message", namespace=LIVE_CHAT_NAMESPACE)
async def live_chat_send_message(sid: str, data: object) -> None:
    # Forward to the monolith for persistence + broadcast. The persisted message
    # returns to the room via edge:downstream; no synchronous ack here.
    session = await sio.get_session(sid, namespace=LIVE_CHAT_NAMESPACE)
    user_id = session.get("user_id")
    if not user_id:
        return

    await _publish_upstream(
        event="message:send",
        user_id=user_id,
        sid=sid,
        payload=data,
    )


@sio.on("leave_room", namespace=LIVE_CHAT_NAMESPACE)
async def live_chat_leave_room(sid: str, data: object):
    # Leaving needs no authorization, so it stays local and synchronous.
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


def _validate_envelope(envelope: DownstreamEnvelope) -> None:
    """Structural routing checks beyond schema; raises ValueError if malformed."""
    if envelope.event == "room:join_approved":
        if not envelope.target.sid:
            raise ValueError("room:join_approved missing target.sid")
        if not (
            isinstance(envelope.payload, dict) and envelope.payload.get("roomId")
        ):
            raise ValueError("room:join_approved missing payload.roomId")
        return
    if envelope.target.type == "sid":
        if not envelope.target.sid:
            raise ValueError("sid target missing 'sid'")
    elif not envelope.target.room:
        raise ValueError("room target missing 'room'")


async def _apply_join_approved(
    envelope: DownstreamEnvelope, namespace: str
) -> None:
    """Execute the deferred room join, then notify the requesting socket."""
    sid = envelope.target.sid
    payload = envelope.payload if isinstance(envelope.payload, dict) else {}
    room_id = payload.get("roomId")
    if sid and room_id:
        await sio.enter_room(sid, _live_chat_room(room_id), namespace=namespace)
    await sio.emit(
        "room:join_approved", envelope.payload, to=sid, namespace=namespace
    )


async def _dispatch_envelope(envelope: DownstreamEnvelope) -> None:
    """Route a validated downstream envelope to Socket.IO."""
    namespace = _resolve_namespace(envelope.namespace)
    if envelope.event == "room:join_approved":
        await _apply_join_approved(envelope, namespace)
        return
    to = (
        envelope.target.sid
        if envelope.target.type == "sid"
        else envelope.target.room
    )
    await sio.emit(envelope.event, envelope.payload, to=to, namespace=namespace)


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
        _validate_envelope(envelope)
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
        await _dispatch_envelope(envelope)
    except Exception:
        # Transient delivery failure: do NOT ack so the entry stays pending and
        # can be reclaimed (XAUTOCLAIM) later. A single pending entry does not
        # block new messages read with '>'.
        logger.exception("dispatch failed for %s; leaving unacked", msg_id)
        return

    await client.xack(DOWNSTREAM_STREAM, CONSUMER_GROUP, msg_id)


async def _downstream_listener(client: redis_async.Redis) -> None:
    """Infinite XREADGROUP loop bridging `edge:downstream` to Socket.IO."""
    consumer = WORKER_ID
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
    global redis_client
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
        redis_client = None
        logger.info("realtime edge shut down")


fastapi_app = FastAPI(title="Realtime Edge", version="0.1.0", lifespan=lifespan)


@fastapi_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# Combined ASGI app: /socket.io/* -> Socket.IO, everything else -> FastAPI.
# socketio.ASGIApp forwards the ASGI lifespan scope to other_asgi_app, so the
# FastAPI lifespan above (and the Redis listener) runs under uvicorn.
app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app, socketio_path="socket.io")
