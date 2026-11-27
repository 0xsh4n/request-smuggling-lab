#!/usr/bin/env python3
"""Toy origin: parses Transfer-Encoding: chunked before Content-Length."""
import os
import socket
import threading

HOST, PORT = "0.0.0.0", int(os.getenv("ORIGIN_PORT", "8081"))
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


def read_request(reader):
    line = read_line(reader)
    if line is None:
        return None
    try:
        method, path, version = line[:-2].decode("ascii").split(" ", 2)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BadRequest("bad request line") from exc
    headers = []
    while True:
        line = read_line(reader)
        if line is None:
            raise BadRequest("truncated headers")
        if line == b"\r\n":
            break
        if b":" not in line:
            raise BadRequest("bad header")
        name, value = line[:-2].split(b":", 1)
        headers.append((name.strip().lower(), value.strip()))

    transfer = [v.lower() for n, v in headers if n == b"transfer-encoding"]
    lengths = [v for n, v in headers if n == b"content-length"]
    if transfer:
        if len(transfer) != 1 or transfer[0] != b"chunked":
            raise BadRequest("unsupported transfer coding")
        total = 0
        while True:
            size_line = read_line(reader)
            if size_line is None:
                raise BadRequest("truncated chunk")
            try:
                size = int(size_line[:-2].split(b";", 1)[0], 16)
            except ValueError as exc:
                raise BadRequest("bad chunk size") from exc
            if size < 0 or total + size > MAX_BODY:
                raise BadRequest("body too large")
            if size == 0:
                # Consume optional trailers through the terminating empty line.
                while True:
                    trailer = read_line(reader)
                    if trailer is None:
                        raise BadRequest("truncated trailers")
                    if trailer == b"\r\n":
                        break
                break
            data = reader.read(size)
            if len(data) != size or reader.read(2) != b"\r\n":
                raise BadRequest("truncated chunk data")
            total += size
    elif lengths:
        if len(lengths) != 1:
            raise BadRequest("duplicate content length")
        try:
            size = int(lengths[0])
        except ValueError as exc:
            raise BadRequest("bad content length") from exc
        if size < 0 or size > MAX_BODY or len(reader.read(size)) != size:
            raise BadRequest("bad body length")
    return method, path, version


def serve_client(conn, addr):
    print(f"origin client {addr}", flush=True)
    reader = conn.makefile("rb")
    try:
        while True:
            try:
                request = read_request(reader)
            except (BadRequest, OSError) as exc:
                print(f"origin parse error: {exc}", flush=True)
                break
            if request is None:
                break
            method, path, _ = request
            if path == "/smuggled":
                body = b"SMUGGLED request reached the origin\n"
            elif path == "/legit":
                body = b"LEGIT request reached the origin\n"
            else:
                body = f"ORIGIN received {method} {path}\n".encode()
            response = (
                b"HTTP/1.1 200 OK\r\n"
                + b"Content-Type: text/plain\r\n"
                + f"X-Lab-Origin-Path: {path}\r\n".encode("ascii", "replace")
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: keep-alive\r\n\r\n"
                + body
            )
            conn.sendall(response)
            print(f"origin handled {method} {path}", flush=True)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            reader.close()
        finally:
            conn.close()


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(64)
    print(f"toy origin listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=serve_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
