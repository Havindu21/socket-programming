#!/usr/bin/env python3
# server.py - simple threaded TCP relay server (chat + file relay)

import socket
import threading
import argparse
import traceback

clients_lock = threading.Lock()
clients = {}  # sock -> {'addr': (ip,port), 'name': str}

BUFFER = 4096

def broadcast(sender_sock, header, payload_stream=None, payload_size=0):
    """Send header (bytes) and optionally payload_stream (a bytes iterator / generator / file-like) to all clients except sender."""
    with clients_lock:
        targets = [s for s in clients.keys() if s is not sender_sock]
    header_bytes = header if isinstance(header, bytes) else header.encode('utf-8')
    for s in targets:
        try:
            s.sendall(header_bytes)
            if payload_stream and payload_size > 0:
                remaining = payload_size
                while remaining > 0:
                    chunk = payload_stream.read(min(BUFFER, remaining))
                    if not chunk:
                        break
                    s.sendall(chunk)
                    remaining -= len(chunk)
        except Exception:
            # ignore one client failing, remove it
            try:
                with clients_lock:
                    del clients[s]
                s.close()
            except:
                pass

def handle_client(conn, addr):
    try:
        # initial handshake: expect "NAME:<username>\n"
        first = conn.recv(BUFFER).decode('utf-8', errors='ignore')
        if not first:
            conn.close()
            return
        if first.startswith("NAME:"):
            username = first.strip().split(":",1)[1]
        else:
            username = f"{addr[0]}:{addr[1]}"
        with clients_lock:
            clients[conn] = {'addr': addr, 'name': username}
        print(f"[+] {username} connected from {addr}")

        # notify others
        broadcast(conn, f"MSG:SERVER:{username} has joined the chat\n")

        # now loop for messages. Because recv can contain header+payload, maintain a small buffer
        leftover = b''
        while True:
            data = conn.recv(BUFFER)
            if not data:
                break
            buf = leftover + data
            # process one header line at a time
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                line = line.decode('utf-8', errors='ignore')
                if line.startswith("MSG:"):
                    # MSG:username:the text
                    # forward as-is to others
                    broadcast(conn, (line + '\n').encode('utf-8'))
                elif line.startswith("FILE:"):
                    # FILE:username:filename:filesize
                    parts = line.split(":", 3)
                    if len(parts) < 4:
                        print("Malformed FILE header:", line)
                        continue
                    _, uname, filename, filesize_s = parts
                    try:
                        filesize = int(filesize_s)
                    except:
                        print("Bad filesize:", filesize_s)
                        filesize = 0
                    header_to_send = f"FILE:{uname}:{filename}:{filesize}\n".encode('utf-8')
                    # Now we need to read filesize bytes from 'buf' + subsequent recv calls
                    # create a temporary bytes buffer-like object to feed broadcast
                    from io import BytesIO
                    bytes_buffer = BytesIO()
                    # first take what remains in buf
                    take = min(len(buf), filesize)
                    if take:
                        bytes_buffer.write(buf[:take])
                        buf = buf[take:]
                    remaining = filesize - bytes_buffer.tell()
                    while remaining > 0:
                        chunk = conn.recv(min(BUFFER, remaining))
                        if not chunk:
                            break
                        bytes_buffer.write(chunk)
                        remaining -= len(chunk)
                    bytes_buffer.seek(0)
                    # broadcast header + payload to other clients
                    broadcast(conn, header_to_send, payload_stream=bytes_buffer, payload_size=filesize)
                else:
                    print("Unknown header:", line)
            leftover = buf
    except Exception as e:
        print("Exception in client handler:", e)
        traceback.print_exc()
    finally:
        with clients_lock:
            if conn in clients:
                name = clients[conn]['name']
                del clients[conn]
            else:
                name = str(addr)
        print(f"[-] {name} disconnected")
        broadcast(conn, f"MSG:SERVER:{name} has left the chat\n")
        try:
            conn.close()
        except:
            pass

def main(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(10)
    print(f"Server listening on {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()
    main(args.host, args.port)
