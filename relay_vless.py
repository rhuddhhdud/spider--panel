# relay_vless.py
# Ø¨Ø®Ø´ VLESS Relay â€” Ø¬Ø¯Ø§ Ø´Ø¯Ù‡ Ø§Ø² main.py (Ù…Ù†Ø·Ù‚ Ø§ØµÙ„ÛŒ Ø¯Ø³Øªâ€ŒÙ†Ø®ÙˆØ±Ø¯Ù‡)
# ØªØºÛŒÛŒØ±: Ø«Ø¨Øª IP ÙˆØ§Ù‚Ø¹ÛŒ Ú©Ù„Ø§ÛŒÙ†Øª (Ø¨Ø§ Ø§Ø­ØªØ³Ø§Ø¨ Ù‡Ø¯Ø± x-forwarded-for Ù¾Ø´Øª Ù¾Ø±Ø§Ú©Ø³ÛŒ) Ø¯Ø± connections

import asyncio
import secrets
import logging
from datetime import datetime, timezone, timedelta

from fastapi import WebSocket, WebSocketDisconnect

from shared import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    RELAY_BUF,
)

logger = logging.getLogger("Spider-Gateway")
IRAN_TZ = timezone(timedelta(hours=3, minutes=30))

# Lazy imports for functions from main.py (circular import fix)
_main = None
def _get_main():
    global _main
    if _main is None:
        import main as _main
    return _main

def __now_ir():
    return datetime.now(IRAN_TZ)

def __is_link_allowed(link):
    return _get_main()._is_link_allowed(link)

def __save_state():
    return _get_main()._save_state()

def __log_activity(*args, **kwargs):
    return _get_main()._log_activity(*args, **kwargs)

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# VLESS Relay â€” Ø¨Ù‡ÛŒÙ†Ù‡â€ŒØ´Ø¯Ù‡ Ø¨Ø±Ø§ÛŒ Ø­Ø¯Ø§Ú©Ø«Ø± throughput
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

RELAY_BUF = 256 * 1024   # 256 KB buffer

def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "Ù†Ø§Ù…Ø´Ø®Øµ"

async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not _is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[_now_ir().strftime("%H:00")] += n
    return True

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await asyncio.wait_for(ws.receive(), timeout=120.0)
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled")
                break
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except asyncio.TimeoutError:
        logger.debug(f"WS recv timeout [{conn_id}]")
    except (WebSocketDisconnect, Exception) as exc:
        logger.debug(f"WS->TCP end [{conn_id}]: {exc}")
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    first = True
    try:
        while True:
            data = await asyncio.wait_for(reader.read(RELAY_BUF), timeout=120.0)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled")
                break
            connections[conn_id]["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
    except asyncio.TimeoutError:
        logger.debug(f"TCP recv timeout [{conn_id}]")
    except Exception as exc:
        logger.debug(f"TCP->WS end [{conn_id}]: {exc}")

async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not _is_link_allowed(link):
        logger.warning(f"ðŸš« WS rejected uuid={uuid[:8]}â€¦ (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)
    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"âœ… WS [{conn_id}] uuid={uuid[:8]}â€¦ ip={ip} total={len(connections)}")
    _log_activity("connection", f"Ø§ØªØµØ§Ù„ Ø¬Ø¯ÛŒØ¯ Ø§Ø² {ip} (Ú©Ø§Ù†ÙÛŒÚ¯ {link.get('label','?')})", "info")
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"âž¡ï¸  [{conn_id}] â†’ {address}:{port}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=10.0
        )
        sock = writer.transport.get_extra_info('socket')
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if payload:
            writer.write(payload)
            await writer.drain()

        # Run bi-directional relay
        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(_save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"ðŸ”Œ WS closed [{conn_id}] total={len(connections)}")
