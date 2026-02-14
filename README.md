# OffTheGrid (mesez)

Resilient messaging app focused on low-friction communication with Socket.io, authentication, and per-user key management.

## Current Architecture

- `server/`: Express + Socket.io + Supabase-backed API/events.
- `client-cli/`: TypeScript CLI chat client (`inquirer`, `chalk`, `socket.io-client`).
- `client-web/`: React + Vite web chat client.

## Implemented Features

- User registration and login over Socket.io (`register`, `login`) with JWT session handling.
- Direct (user-to-user) messaging with schema validation (AJV).
- Message persistence to Supabase (`messages` table).
- Chat history retrieval (`get_chat_history`).
- Online/offline presence updates (`user_status`, `get_online_users`, `get_all_users_status`).
- Public key upload and lookup for users (`upload_public_keys`, `check_public_keys`, `get_user_public_keys`).
- Local keypair generation in clients:
  - CLI: filesystem `.keys/<username>.json`
  - Web: browser storage (via `keyManagerBrowser`)

## Fragmentation Architecture

Fragmentation is implemented to support constrained transports (including future mesh/BLE paths) where smaller packets are more reliable than sending a full JSON payload in one frame.

- Client side:
  - Direct message object is `JSON.stringify`-ed.
  - Payload is split into UTF-8-safe fragments of 20-31 bytes.
  - Each fragment includes `msg_id`, `frag_id`, `total_frags`, `checksum`, `payload`, and `to`.
  - Fragments are emitted over Socket.io via `socket.emit('fragment', fragment)`.
- Server side:
  - Fragments are buffered by `msg_id`.
  - Reassembly starts only when all fragments are present.
  - SHA-256 checksum is verified before parsing.
  - Reassembled JSON is parsed and validated with existing AJV schema.
  - JWT sender identity is verified against message sender (`from`).
  - Valid messages are persisted to Supabase, then routed to recipient via `direct_message`.
- Security protections:
  - Rejects invalid fragments (`total_frags > 500`, payload > 31 bytes, invalid checksum format).
  - Per-socket fragment rate limiting.
  - Duplicate `frag_id` packets are ignored.
  - Incomplete fragment buffers are auto-cleaned after 30 seconds to prevent memory leaks.

```text
Client -> fragment -> Server buffer -> reassemble -> validate -> DB -> broadcast
```

## Project Structure

```text
mesez/
  server/
    src/
      index.ts
      sockets/socketHandler.ts
      config/supabase.ts
      schemas/message.schema.json
  client-cli/
    index.ts
    src/
      core/transport/SocketProvider.ts
      crypto/keyManager.ts
  client-web/
    src/
      context/SocketContext.tsx
      components/Login.tsx
      components/Chat.tsx
  README.md
```

## Prerequisites

- Node.js 18+ (recommended)
- npm
- Supabase project with expected tables (`users`, `publickeys`, `messages`)

## Environment Variables

### Server (`server/.env`)

```env
PORT=3000
JWT_SECRET=supersecretkey
SUPABASE_URL=https://imnwsdbyhhxnikzfyvhc.supabase.co
SUPABASE_ANON_KEY=sb_publishable_-3PaDcpKEuhQEv4SlqPfqQ_m61PZ3MD
```

### CLI Client (`client-cli/.env`, optional)

```env
SERVER_URL=http://localhost:3000
```

Note: web client server URL is currently hardcoded to `http://localhost:3000` in `client-web/src/context/SocketContext.tsx`.

## Setup

```bash
cd server && npm install
cd ../client-cli && npm install
cd ../client-web && npm install
```

## Run

Use separate terminals.

1. Start server:

```bash
cd server
npm start
```

2. Start CLI client:

```bash
cd client-cli
npm start
```

3. Start web client:

```bash
cd client-web
npm run dev
```

## Notes

- Bluetooth transport files exist as placeholders; runtime transport is Socket.io/internet.
- Web client requests `get_inbox`, but the current server socket handler does not implement that event yet.
