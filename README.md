# Local HTTP request smuggling lab (CL.TE)

This is an intentionally vulnerable, toy reverse proxy in front of a toy origin. The proxy frames incoming request bodies using `Content-Length` and ignores `Transfer-Encoding`; the origin honors `Transfer-Encoding: chunked`. A fixed proxy mode rejects ambiguous framing before forwarding bytes upstream.

Everything runs in a private Compose network. Only the proxy is published, bound to `127.0.0.1:8080`. This is for the local lab only; it is not production proxy code.

## Requirements

- Docker Engine and Docker Compose plugin
- Python 3 for the local demonstration client

## Reproduce the desync

From this directory:

```bash
docker compose up --build -d
python3 demo.py --expect vulnerable
```

The script pipelines a CL.TE request followed by an ordinary `/legit` request. The front proxy treats the smuggled request bytes as part of the first request body, while the origin stops at the zero-length chunk and parses `GET /smuggled` as a second request. The proxy then pairs the origin's queued `/smuggled` response with the next front-end request. The demo checks the origin-path response header and exits nonzero if this does not occur.

## Apply and confirm the fix

Recreate the proxy in strict mode:

```bash
SAFE_MODE=1 docker compose up --build -d --force-recreate
python3 demo.py --expect fixed
```

In safe mode, the proxy rejects any request with `Transfer-Encoding` (and duplicate Content-Length) with `400` and closes that client connection. The demo then sends a clean request on a new connection and verifies that `/legit` reaches the origin normally.

Restore the intentionally vulnerable mode with:

```bash
SAFE_MODE=0 docker compose up --build -d --force-recreate
```

Stop and remove the lab:

```bash
docker compose down --rmi local
```

## What to observe

- `docker compose logs -f proxy origin` shows proxy mode, parsing, and the origin paths it handled.
- Vulnerable run: response 2 is marked `X-Lab-Origin-Path: /smuggled`, despite being received in the client's `/legit` response position.
- Fixed run: the ambiguous request gets `400`; a fresh clean request receives `X-Lab-Origin-Path: /legit`.

## Fix principle

Every hop must agree on HTTP message boundaries. A real reverse proxy should use a maintained HTTP implementation, reject ambiguous or malformed framing at ingress, and normalize requests before forwarding. Do not try to reproduce this toy parser as a production proxy.
