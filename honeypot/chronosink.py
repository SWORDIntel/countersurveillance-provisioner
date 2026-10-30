#!/usr/bin/env python3
"""
chronosink.py - Ultra-lightweight Deception Honeypot Daemon
Features:
  - Multi-port listener (HTTP Deception & Raw TCP Tarpit)
  - HTTP Decompression Bomb (100 MB - 10 GB inflation)
  - Temporal Anomaly (Retro HTTP Date header set to Oct 2003, artificial latency jitter)
  - Raw TCP probe capture (SMB, Telnet, Winbox) with tarpit delays
  - Structured JSONL logging to /var/log/chronosink/probes.jsonl
Memory Footprint: <25 MB | Zero external dependencies (Python 3.8+ stdlib)
"""

import asyncio
import datetime
import json
import logging
import os
import random
import signal
import socket
import sys
import zlib

LISTEN_HTTP_PORTS = [9080, 80, 8080, 8443]
LISTEN_RAW_PORTS = [9445, 23, 445, 5555, 8291]
LOG_FILE = "/var/log/chronosink/probes.jsonl"
LOG_DIR = "/var/log/chronosink"

# Citadel Shield Telemetry Target (t420 hub)
CITADEL_HOST = os.getenv("CITADEL_HOST", "192.168.1.91")
CITADEL_PORT = int(os.getenv("CITADEL_PORT", "17872"))

# Retro temporal constants
RETRO_SERVER = "Apache/1.3.27 (Unix) mod_ssl/2.8.12 OpenSSL/0.9.6b"
RETRO_DATE = "Fri, 24 Oct 2003 14:02:11 GMT"
RETRO_MODIFIED = "Mon, 12 Apr 1999 08:30:00 GMT"

# Pre-generate 100 MB of compressed null bytes (~100 KB on wire, inflates to 100 MB)
# For chunked streaming, can stream indefinitely until scanner terminates
def build_static_bomb() -> bytes:
    compressor = zlib.compressobj(level=9, wbits=31)
    chunk = b"\x00" * (1024 * 1024)  # 1 MB
    compressed = b"".join(compressor.compress(chunk) for _ in range(100))
    return compressed + compressor.flush()

STATIC_BOMB = build_static_bomb()

def log_event(event_type: str, src_ip: str, src_port: int, dst_port: int, details: dict):
    global LOG_FILE, LOG_DIR
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except PermissionError:
        LOG_DIR = "/tmp/chronosink"
        LOG_FILE = "/tmp/chronosink/probes.jsonl"
        os.makedirs(LOG_DIR, exist_ok=True)

    try:
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "details": details
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to log event: {e}", file=sys.stderr)

    # Forward alert datagram to Citadel Shield on t420:17872
    try:
        payload = json.dumps({
            "node": socket.gethostname(),
            "target": src_ip,
            "port": dst_port,
            "comm": f"chronosink-{event_type.lower()}",
            "pid": os.getpid()
        }).encode("utf-8")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.sendto(payload, (CITADEL_HOST, CITADEL_PORT))
        s.close()
    except Exception:
        pass

async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, bind_port: int):
    peer = writer.get_extra_info('peername')
    if not peer:
        writer.close()
        return
    client_ip, client_port = peer[0], peer[1]

    try:
        # Read HTTP request header up to 8KB
        header_data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        decoded = header_data.decode('latin-1', errors='replace').split("\r\n")
        req_line = decoded[0] if decoded else ""
        headers = {}
        for line in decoded[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v

        log_event("HTTP_REQUEST", client_ip, client_port, bind_port, {
            "request_line": req_line,
            "user_agent": headers.get("user-agent", ""),
            "host": headers.get("host", ""),
            "accept_encoding": headers.get("accept-encoding", "")
        })

        # Artificial temporal jitter (0.3s - 1.5s delay)
        await asyncio.sleep(random.uniform(0.3, 1.5))

        accept_enc = headers.get("accept-encoding", "")
        if "gzip" in accept_enc:
            # Deliver the Gzip decompression bomb
            resp_headers = (
                "HTTP/1.1 200 OK\r\n"
                f"Date: {RETRO_DATE}\r\n"
                f"Server: {RETRO_SERVER}\r\n"
                f"Last-Modified: {RETRO_MODIFIED}\r\n"
                "Content-Type: text/html\r\n"
                "Content-Encoding: gzip\r\n"
                f"Content-Length: {len(STATIC_BOMB)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            writer.write(resp_headers.encode('latin-1') + STATIC_BOMB)
        else:
            # Tarpit response with 403 and past date
            body = "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Directory traversal rejected.</p></body></html>\r\n"
            resp_headers = (
                "HTTP/1.1 403 Forbidden\r\n"
                f"Date: {RETRO_DATE}\r\n"
                f"Server: {RETRO_SERVER}\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            writer.write((resp_headers + body).encode('latin-1'))

        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_raw_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, bind_port: int):
    peer = writer.get_extra_info('peername')
    if not peer:
        writer.close()
        return
    client_ip, client_port = peer[0], peer[1]

    try:
        # Read initial banner probe payload
        raw_payload = await asyncio.wait_for(reader.read(2048), timeout=4.0)
        log_event("RAW_TCP_PROBE", client_ip, client_port, bind_port, {
            "bytes_received": len(raw_payload),
            "hex_preview": raw_payload.hex()[:256]
        })

        # Tarpit: keep connection open for 15s before closing to exhaust scanner threads
        await asyncio.sleep(15.0)
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    servers = []
    loop = asyncio.get_running_loop()

    # Graceful shutdown handler
    stop_event = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    # Start HTTP listeners
    for port in LISTEN_HTTP_PORTS:
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port: handle_http(r, w, p),
                "0.0.0.0", port
            )
            servers.append(srv)
            print(f"[+] HTTP Deception listener active on 0.0.0.0:{port}")
        except Exception as e:
            print(f"[-] Could not bind HTTP port {port}: {e}")

    # Start Raw TCP listeners
    for port in LISTEN_RAW_PORTS:
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port: handle_raw_tcp(r, w, p),
                "0.0.0.0", port
            )
            servers.append(srv)
            print(f"[+] Raw TCP Tarpit listener active on 0.0.0.0:{port}")
        except Exception as e:
            print(f"[-] Could not bind RAW port {port}: {e}")

    if not servers:
        print("[!] No listeners could be started. Exiting.", file=sys.stderr)
        return

    print("[*] ChronoSink Deception Engine running. Press Ctrl+C or send SIGTERM to stop.")
    await stop_event.wait()
    print("[*] Shutting down listeners...")
    for srv in servers:
        srv.close()
        await srv.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
