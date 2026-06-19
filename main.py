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

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

JWT_ALGORITHM = "HS256"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")

DOWNSTREAM_STREAM = "edge:downstream"
UPSTREAM_STREAM = "edge:upstream"
CONSUMER_GROUP = "edge"
DLQ_STREAM = "edge:downstream:dlq"
READ_COUNT = 50
BLOCK_MS = 5000
DLQ_MAXLEN = 10_000
UPSTREAM_MAXLEN = 100_000

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}"

redis_client: redis_async.Redis | None = None

NAMESPACE_BY_NAME = {"root": "/", "live-chat": "/live-chat"}
LIVE_CHAT_NAMESPACE = "/live-chat"

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[FRONTEND_URL],
)

class DownstreamTarget(BaseModel):
    type: str
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
    v: int = 1
    event: str
    userId: str
    sid: str | None = None
    clientMsgId: str
    payload: Any = None
    meta: UpstreamMeta

def _extract_token(auth: object, environ: dict) -> str | None:
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
    for key in ("id", "sub", "userId"):
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    return None

async def _authenticate_socket(
    sid: str, environ: dict, auth: object, namespace: str = "/"
) -> str:
    try:
        transport = sio.transport(sid, namespace=namespace)
    except Exception:
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
    if isinstance(data, dict):
        room_id = data.get("roomId")
        if isinstance(room_id, str) and room_id:
            return room_id
    return None

def _live_chat_room(room_id: str) -> str:
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

@sio.event
async def connect(sid: str, environ: dict, auth: object) -> None:
    user_id = await _authenticate_socket(sid, environ, auth)
    await sio.save_session(sid, {"user_id": user_id})
    await sio.enter_room(sid, f"user:{user_id}")
    logger.info("socket %s authenticated as user %s (root)", sid, user_id)

@sio.event
async def disconnect(sid: str) -> None:
    logger.info("socket %s disconnected (root)", sid)

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
    session = await sio.get_session(sid, namespace=LIVE_CHAT_NAMESPACE)
    user_id = session.get("user_id")
    room_id = _extract_room_id(data)

    if not user_id or not room_id:
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
    room_id = _extract_room_id(data)
    if not room_id:
        return {"ok": False, "error": "roomId is required"}

    await sio.leave_room(sid, _live_chat_room(room_id), namespace=LIVE_CHAT_NAMESPACE)
    return {"ok": True}

def _resolve_namespace(name: str) -> str:
    if name in NAMESPACE_BY_NAME:
        return NAMESPACE_BY_NAME[name]
    return "/" + name.lstrip("/")

def _validate_envelope(envelope: DownstreamEnvelope) -> None:
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
    sid = envelope.target.sid
    payload = envelope.payload if isinstance(envelope.payload, dict) else {}
    room_id = payload.get("roomId")
    if sid and room_id:
        await sio.enter_room(sid, _live_chat_room(room_id), namespace=namespace)
    await sio.emit(
        "room:join_approved", envelope.payload, to=sid, namespace=namespace
    )

async def _dispatch_envelope(envelope: DownstreamEnvelope) -> None:
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
        logger.exception("dispatch failed for %s; leaving unacked", msg_id)
        return

    await client.xack(DOWNSTREAM_STREAM, CONSUMER_GROUP, msg_id)

async def _downstream_listener(client: redis_async.Redis) -> None:
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

app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app, socketio_path="socket.io")