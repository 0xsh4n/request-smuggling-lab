#!/usr/bin/env python3
"""Toy reverse proxy: vulnerable mode frames client requests by CL only."""
import os
import socket
import threading

HOST, PORT = "0.0.0.0", int(os.getenv("PROXY_PORT", "8080"))
ORIGIN_HOST = os.getenv("ORIGIN_HOST", "127.0.0.1")
ORIGIN_PORT = int(os.getenv("ORIGIN_PORT", "8081"))
SAFE_MODE = os.getenv("SAFE_MODE", "0").lower() in {"1", "true", "yes"}
MAX_LINE = 8192
MAX_BODY = 1024 * 1024


class BadRequest(Exception):
    pass


def read_line(reader):
    line = reader.readline(MAX_LINE + 1)
    if not line:
        return None
    if len(line) > MAX_LINE or not line.endswith(b"\r\n"):
        raise BadRequest("bad line")
    return line


def read_front_request(reader):
    request_line = read_line(reader)
    if request_line is None:
        return None
    headers = []
    names = []
    while True:
        line = read_line(reader)
        if line is None:
            raise BadRequest("truncated headers")
        if line == b"\r\n":
            break
        if b":" not in line:
            raise BadRequest("bad header")
        name, value = line[:-2].split(b":", 1)
        names.append(name.strip().lower())
        headers.append(line)
    has_te = b"transfer-encoding" in names
    length_values = []
    for line in headers:
        name, value = line[:-2].split(b":", 1)
        if name.strip().lower() == b"content-length":
            length_values.append(value.strip())

    # The safe proxy rejects ambiguity before forwarding any bytes upstream.
    if SAFE_MODE and (has_te or len(length_values) > 1):
        raise BadRequest("Transfer-Encoding or duplicate Content-Length rejected")

    # Intentionally vulnerable behavior: ignore TE and use only CL for framing.
    size = 0
    if length_values:
        if len(set(length_values)) != 1:
            raise BadRequest("conflicting Content-Length")
        try:
            size = int(length_values[0])
        except ValueError as exc:
            raise BadRequest("invalid Content-Length") from exc
    if size < 0 or size > MAX_BODY:
        raise BadRequest("body too large")
    body = reader.read(size)
    if len(body) != size:
        raise BadRequest("truncated body")
    return request_line + b"".join(headers) + b"\r\n" + body


def read_origin_response(reader):
    status = read_line(reader)
    if status is None:
        raise ConnectionError("origin closed connection")
    headers = []
    length = None
    while True:
        line = read_line(reader)
        if line is None:
            raise ConnectionError("truncated origin response")
        if line == b"\r\n":
            break
        headers.append(line)
        name, _, value = line[:-2].partition(b":")
        if name.lower() == b"content-length":
            length = int(value.strip())
    if length is None or length < 0 or length > MAX_BODY:
        raise ConnectionError("origin response missing/invalid Content-Length")
    body = reader.read(length)
    if len(body) != length:
        raise ConnectionError("truncated origin body")
    return status + b"".join(headers) + b"\r\n" + body


def send_error(client, code, reason):
    body = (reason + "\n").encode()
    response = (
        f"HTTP/1.1 {code} {reason}\r\n".encode()
        + b"Content-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    try:
        client.sendall(response)
    except OSError:
        pass


def serve_client(client, addr):
    print(f"proxy client {addr}; SAFE_MODE={SAFE_MODE}", flush=True)
    front = client.makefile("rb")
    upstream = None
    upstream_reader = None
    try:
        upstream = socket.create_connection((ORIGIN_HOST, ORIGIN_PORT), timeout=5)
        upstream_reader = upstream.makefile("rb")
        while True:
            try:
                request = read_front_request(front)
            except (BadRequest, OSError) as exc:
                send_error(client, 400, "Bad Request")
                print(f"proxy rejected request: {exc}", flush=True)
                break
            if request is None:
                break
            upstream.sendall(request)
            response = read_origin_response(upstream_reader)
            client.sendall(response)
    except (BrokenPipeError, ConnectionResetError, ConnectionError, OSError) as exc:
        print(f"proxy connection ended: {exc}", flush=True)
    finally:
        try:
            front.close()
        except OSError:
            pass
        if upstream_reader:
            try:
                upstream_reader.close()
            except OSError:
                pass
        if upstream:
            upstream.close()
        client.close()


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(64)
    print(f"toy reverse proxy listening on {HOST}:{PORT}; SAFE_MODE={SAFE_MODE}", flush=True)
    while True:
        client, addr = server.accept()
        threading.Thread(target=serve_client, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
