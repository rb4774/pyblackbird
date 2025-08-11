import threading
import os
import socket
import sys
import time
try:
    import pty  # type: ignore
    HAS_PTY = True
except Exception:  # pragma: no cover - windows fallback
    pty = None
    HAS_PTY = False


def create_dummy_port(responses, terminator: bytes = b"\r"):
    """Create a dummy PTY port if available; otherwise raise RuntimeError.

    On platforms without pty (e.g., Windows), tests using this will be skipped.
    """
    if not HAS_PTY:  # pragma: no cover - platform dependent
        raise RuntimeError("PTY not available on this platform")

    def listener(port):
        while True:
            res = b''
            while not res.endswith(terminator):
                res += os.read(port, 1)
            if res in responses:
                resp = responses[res]
                del responses[res]
                os.write(port, resp)

    master, slave = pty.openpty()
    thread = threading.Thread(target=listener, args=[master], daemon=True)
    thread.start()
    return os.ttyname(slave)

def create_dummy_socket(responses, host: str = '127.0.0.1', port: int | None = None, banner: bytes | None = b'Welcome\r\n'):
    """Create a persistent dummy TCP server that mimics the matrix (multi-connection).

    Supports both legacy (commands end with '\r') and PTN (commands end with '.') styles.
    For legacy `Status1.\r` we purposefully wait for the trailing carriage return so we
    don't prematurely terminate at the period. For PTN commands (e.g. `STA_VIDEO.` or
    `OUT01:02.`) we terminate at the period.
    """

    ready = threading.Event()

    def handle_client(conn):  # pragma: no cover - simple test harness
        if banner:
            try:
                conn.sendall(banner)
            except OSError:
                return
        buf = b''
        try:
            while True:
                chunk = conn.recv(1)
                if not chunk:
                    break
                buf += chunk
                if chunk == b'.':
                    # Don't finalize legacy Status* commands yet (they end with .\r)
                    if buf.startswith(b'Status'):
                        continue
                    cmd = buf
                    buf = b''
                    if cmd in responses:
                        resp_entry = responses[cmd]
                        # Support list/tuple of responses for repeated commands (e.g., auto-detect then real use)
                        if isinstance(resp_entry, (list, tuple)):
                            if len(resp_entry) == 0:
                                del responses[cmd]
                                continue
                            resp = resp_entry[0]
                            # Keep remaining for future requests
                            remaining = list(resp_entry[1:])
                            if remaining:
                                responses[cmd] = remaining
                            else:
                                del responses[cmd]
                        elif isinstance(resp_entry, dict) and 'chunks' in resp_entry:
                            # Chunked delayed response; send each chunk with optional delay
                            for piece in resp_entry['chunks']:
                                if isinstance(piece, tuple):
                                    data_part, delay = piece
                                    if data_part:
                                        conn.sendall(data_part)
                                    time.sleep(delay)
                                else:
                                    if piece:
                                        conn.sendall(piece)
                            del responses[cmd]
                            continue
                        else:
                            resp = resp_entry
                            del responses[cmd]
                        if resp:
                            conn.sendall(resp)
                elif chunk == b'\r':
                    cmd = buf
                    buf = b''
                    if cmd in responses:
                        resp_entry = responses[cmd]
                        if isinstance(resp_entry, (list, tuple)):
                            if len(resp_entry) == 0:
                                del responses[cmd]
                                continue
                            resp = resp_entry[0]
                            remaining = list(resp_entry[1:])
                            if remaining:
                                responses[cmd] = remaining
                            else:
                                del responses[cmd]
                        elif isinstance(resp_entry, dict) and 'chunks' in resp_entry:
                            for piece in resp_entry['chunks']:
                                if isinstance(piece, tuple):
                                    data_part, delay = piece
                                    if data_part:
                                        conn.sendall(data_part)
                                    time.sleep(delay)
                                else:
                                    if piece:
                                        conn.sendall(piece)
                            del responses[cmd]
                            continue
                        else:
                            resp = resp_entry
                            del responses[cmd]
                        if resp:
                            conn.sendall(resp)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def listener():  # pragma: no cover
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_port = port if port is not None else 0
        srv.bind((host, bind_port))
        actual_port = srv.getsockname()[1]
        nonlocal_port_holder['port'] = actual_port
        srv.listen(5)
        ready.set()
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

    nonlocal_port_holder: dict = {}
    threading.Thread(target=listener, daemon=True).start()
    ready.wait(timeout=2)
    actual = nonlocal_port_holder.get('port', port or 4001)
    return f"{host}:{actual}"