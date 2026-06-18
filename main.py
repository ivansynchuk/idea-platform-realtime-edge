"""
Realtime edge — standalone Socket.IO transport service (strangler Phase 1/2).

A stateless transport edge for the NestJS monolith's WebSocket layer:
  * validates the monolith's JWT cryptographically (HS256, shared JWT_SECRET),
  * has ZERO database access (no SQLAlchemy / asyncpg / drivers),
  * joins each authenticated socket to its personal `user:{id}` room.

The Redis bridge to the monolith (Phase 3) is not wired here yet; `redis` is
listed in requirements.txt in preparation for it.
"""

from __future__ import annotations

import logging
import os

import jwt
import socketio
from fastapi import FastAPI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("realtime-edge")

# --- Configuration (environment) ---------------------------------------------

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

JWT_ALGORITHM = "HS256"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")

# --- Socket.IO server ---------------------------------------------------------

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[FRONTEND_URL],
)

# --- FastAPI (REST surface) ---------------------------------------------------

fastapi_app = FastAPI(title="Realtime Edge", version="0.1.0")


@fastapi_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# Combined ASGI app: /socket.io/* -> Socket.IO, everything else -> FastAPI.
app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app, socketio_path="socket.io")


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


# --- Socket.IO handlers -------------------------------------------------------


@sio.event
async def connect(sid: str, environ: dict, auth: object) -> None:
    # Defense-in-depth: reject HTTP long-polling. Websocket-only is primarily
    # enforced by the client (transports: ["websocket"]); we fail open if the
    # transport cannot be determined so a valid client is never blocked.
    try:
        transport = sio.transport(sid)
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

    await sio.save_session(sid, {"user_id": user_id})
    await sio.enter_room(sid, f"user:{user_id}")
    logger.info("socket %s authenticated as user %s", sid, user_id)


@sio.event
async def disconnect(sid: str) -> None:
    logger.info("socket %s disconnected", sid)
