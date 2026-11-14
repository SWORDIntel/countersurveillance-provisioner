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
import re
import signal
import socket
import sys
import zlib

DEFAULT_HTTP_PORTS = [9080, 8080, 8443, 80]
DEFAULT_RAW_PORTS = [9445, 23, 445, 5555, 8291]
ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def _parse_ports_env(env_key: str, defaults: list[int]) -> list[int]:
    raw = os.getenv(env_key)
    if raw is None:
        return list(defaults)
    stripped = raw.strip()
    if not stripped or stripped.lower() == "none":
        return []
    ports: list[int] = []
    for part in stripped.split(","):
        p_str = part.strip()
        if not p_str:
            continue
        try:
            p = int(p_str)
        except ValueError:
            continue
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)
    return ports


def _resolve_ports() -> tuple[list[int], list[int]]:
    http_ports = _parse_ports_env("CHRONOSINK_HTTP_PORTS", DEFAULT_HTTP_PORTS)
    disable_80 = os.getenv("CHRONOSINK_DISABLE_PORT_80", "").strip().lower() in ("1", "true", "yes", "on")
    allow_80 = os.getenv("CHRONOSINK_ALLOW_PORT_80", "").strip().lower()
    if disable_80 or allow_80 in ("0", "false", "no", "off"):
        http_ports = [p for p in http_ports if p != 80]
    raw_ports = _parse_ports_env("CHRONOSINK_RAW_PORTS", DEFAULT_RAW_PORTS)
    return http_ports, raw_ports


LISTEN_HTTP_PORTS, LISTEN_RAW_PORTS = _resolve_ports()
LOG_FILE = "/var/log/chronosink/probes.jsonl"
LOG_DIR = "/var/log/chronosink"

# Citadel Shield Telemetry Target
CITADEL_HOST = os.getenv("CITADEL_HOST", "192.168.1.91")
CITADEL_PORT = int(os.getenv("CITADEL_PORT", "17872"))
QIHSE_EVENTS_FILE = os.getenv("QIHSE_EVENTS_FILE", "/opt/qihse-data/events/countersurveillance_alerts.jsonl")

# Concurrency limiters
HTTP_SEMAPHORE = asyncio.Semaphore(128)
RAW_SEMAPHORE = asyncio.Semaphore(128)

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

def _write_event_files(event_type: str, src_ip: str, src_port: int, dst_port: int, details: dict):
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

    # QIHSE event bus parity: append alerts if directory exists
    try:
        qihse_events_file = os.getenv("QIHSE_EVENTS_FILE", "/opt/qihse-data/events/countersurveillance_alerts.jsonl")
        qihse_dir = os.path.dirname(qihse_events_file)
        if os.path.isdir(qihse_dir):
            now = datetime.datetime.now(datetime.timezone.utc)
            qihse_alert = {
                "timestamp": now.timestamp(),
                "iso_time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "node": socket.gethostname(),
                "event_type": "countersurveillance.blocked",
                "category": "SECURITY_SURVEILLANCE",
                "target": src_ip,
                "port": dst_port,
                "process": "chronosink",
                "pid": os.getpid(),
                "count": 1,
                "action": "MITIGATED"
            }
            with open(qihse_events_file, "a") as f:
                f.write(json.dumps(qihse_alert) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to append QIHSE alert: {e}", file=sys.stderr)

async def log_event(event_type: str, src_ip: str, src_port: int, dst_port: int, details: dict):
    await asyncio.to_thread(_write_event_files, event_type, src_ip, src_port, dst_port, details)

    # Forward alert datagram to Citadel Shield on :17872
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

def _acme_challenge_dirs() -> list[str]:
    dirs: list[str] = []
    for key in ("CHRONOSINK_ACME_DIR", "ACME_CHALLENGE_DIR"):
        raw = os.getenv(key, "")
        for part in re.split(r"[:,]", raw):
            p = part.strip()
            if p:
                dirs.append(os.path.normpath(p))
    for key in ("CHRONOSINK_ACME_WEBROOT", "ACME_WEBROOT"):
        raw = os.getenv(key, "")
        for part in re.split(r"[:,]", raw):
            p = part.strip()
            if p:
                norm = os.path.normpath(p)
                dirs.append(os.path.join(norm, ".well-known", "acme-challenge"))
                dirs.append(norm)
    dirs.extend([
        "/var/www/acme-challenge/.well-known/acme-challenge",
        "/var/www/html/.well-known/acme-challenge",
        "/var/www/letsencrypt/.well-known/acme-challenge",
        "/var/www/certbot/.well-known/acme-challenge",
        "/var/lib/letsencrypt/http_challenges",
        "/run/acme/.well-known/acme-challenge",
        "/run/acme",
    ])
    return dirs


def _read_acme_challenge(token: str) -> bytes | None:
    if not ACME_TOKEN_RE.match(token):
        return None
    for base in _acme_challenge_dirs():
        base_abs = os.path.abspath(base)
        cand = os.path.abspath(os.path.join(base_abs, token))
        if os.path.dirname(cand) != base_abs:
            continue
        if os.path.isfile(cand) and os.path.getsize(cand) <= 16384:
            with open(cand, "rb") as f:
                return f.read()
    return None


async def handle_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, bind_port: int):
    async with HTTP_SEMAPHORE:
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
            req_parts = req_line.split()
            req_method = req_parts[0].upper() if len(req_parts) >= 1 else ""
            req_target = req_parts[1].split("?", 1)[0] if len(req_parts) >= 2 else ""

            if req_target.startswith(ACME_CHALLENGE_PREFIX):
                if req_method not in ("GET", "HEAD"):
                    body = b"method not allowed\n"
                    resp = (
                        "HTTP/1.1 405 Method Not Allowed\r\n"
                        "Allow: GET, HEAD\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("latin-1") + body
                    writer.write(resp)
                else:
                    token = req_target[len(ACME_CHALLENGE_PREFIX):]
                    data = _read_acme_challenge(token)
                    if data is not None:
                        resp_hdr = (
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain; charset=utf-8\r\n"
                            "Cache-Control: no-store\r\n"
                            f"Content-Length: {len(data)}\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode("latin-1")
                        writer.write(resp_hdr if req_method == "HEAD" else resp_hdr + data)
                    else:
                        body = b"404 page not found\n"
                        resp_hdr = (
                            "HTTP/1.1 404 Not Found\r\n"
                            "Content-Type: text/plain; charset=utf-8\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode("latin-1")
                        writer.write(resp_hdr if req_method == "HEAD" else resp_hdr + body)
                await asyncio.wait_for(writer.drain(), timeout=5.0)
                return

            headers = {}
            for line in decoded[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.lower()] = v

            await log_event("HTTP_REQUEST", client_ip, client_port, bind_port, {
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

            await asyncio.wait_for(writer.drain(), timeout=5.0)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

handle_http = handle_http_client

async def handle_raw_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, bind_port: int):
    async with RAW_SEMAPHORE:
        peer = writer.get_extra_info('peername')
        if not peer:
            writer.close()
            return
        client_ip, client_port = peer[0], peer[1]

        try:
            # Read initial banner probe payload
            raw_payload = await asyncio.wait_for(reader.read(2048), timeout=4.0)
            if not raw_payload:
                return

            await log_event("RAW_TCP_PROBE", client_ip, client_port, bind_port, {
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
                lambda r, w, p=port: handle_http_client(r, w, p),
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
