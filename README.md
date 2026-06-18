# realtime-edge

Standalone Socket.IO transport edge for the platform's real-time layer
(strangler Phase 1/2). Stateless: validates the monolith's JWT (HS256), joins
each socket to its `user:{id}` room, and holds **no** database access.

## Endpoints

- `GET /health` → `{ "status": "ok" }`
- `GET|WS /socket.io/` → Socket.IO (websocket transport)

## Configuration

Copy `.env.example` to `.env` and set `JWT_SECRET` to the **same value** as the
monolith (`backend/.env`). Other vars: `FRONTEND_URL` (CORS), `REDIS_URL`
(Phase 3, unused for now), `PORT`.

## Local setup & run (Windows PowerShell)

```powershell
cd realtime-edge
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # then edit JWT_SECRET to match the backend
uvicorn main:app --host 0.0.0.0 --port 3002 --env-file .env --reload
```

## Local setup & run (bash / macOS / Linux)

```bash
cd realtime-edge
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then edit JWT_SECRET to match the backend
uvicorn main:app --host 0.0.0.0 --port 3002 --env-file .env --reload
```

Verify: `curl http://localhost:3002/health` → `{"status":"ok"}`.

## Auth handshake

The client connects with the JWT in the Socket.IO `auth` payload and websocket
transport only:

```ts
io("http://localhost:3002", {
  transports: ["websocket"],
  auth: { token: accessToken },
});
```

The edge decodes the token with `JWT_SECRET` (HS256) and reads the user id from
the `id` claim (the monolith's claim name), falling back to `sub` / `userId`.
Invalid/missing tokens are rejected with a `ConnectionRefusedError`.
