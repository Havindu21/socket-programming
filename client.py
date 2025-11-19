#!/usr/bin/env python3
# client.py - simple client for server.py
import socket
import threading
import argparse
import sys
import os

BUFFER = 4096

def recv_loop(sock):
    leftover = b''
    while True:
        try:
            data = sock.recv(BUFFER)
            if not data:
                print("[*] Connection closed by server")
                os._exit(0)
            buf = leftover + data
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                text = line.decode('utf-8', errors='ignore')
                if text.startswith("MSG:"):
                    _, sender, msg = text.split(":", 2)
                    print(f"[{sender}] {msg}")
                elif text.startswith("FILE:"):
                    # FILE:username:filename:filesize
                    parts = text.split(":", 3)
                    _, uname, filename, filesize_s = parts
                    filesize = int(filesize_s)
                    # read filesize bytes (may be in buf already)
                    received = b''
                    take = min(len(buf), filesize)
                    if take:
                        received += buf[:take]
                        buf = buf[take:]
                    remaining = filesize - len(received)
                    while remaining > 0:
                        chunk = sock.recv(min(BUFFER, remaining))
                        if not chunk:
                            break
                        received += chunk
                        remaining -= len(chunk)
                    # save file with prefix to avoid overwrite
                    save_name = f"recv_{uname}_{filename}"
                    with open(save_name, "wb") as f:
                        f.write(received)
                    print(f"[{uname}] sent file saved as {save_name} ({filesize} bytes)")
                else:
                    print("Unknown header:", text)
            leftover = buf
        except Exception as e:
            print("Recv error:", e)
            os._exit(1)

def send_msg(sock, username, text):
    header = f"MSG:{username}:{text}\n".encode('utf-8')
    sock.sendall(header)

def send_file(sock, username, filepath):
    if not os.path.exists(filepath):
        print("File not found:", filepath)
        return
    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    header = f"FILE:{username}:{filename}:{filesize}\n".encode('utf-8')
    sock.sendall(header)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(BUFFER)
            if not chunk:
                break
            sock.sendall(chunk)
    print(f"Sent {filename} ({filesize} bytes)")

def main(server_ip, server_port, username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, server_port))
    # send name handshake
    sock.sendall(f"NAME:{username}\n".encode('utf-8'))
    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()
    print("Type '/file <path>' to send a file. Type messages to chat. Ctrl+C to exit.")
    while True:
        try:
            line = input()
            if line.startswith("/file "):
                path = line.split(" ",1)[1].strip()
                send_file(sock, username, path)
            else:
                send_msg(sock, username, line)
        except KeyboardInterrupt:
            print("Exiting...")
            sock.close()
            break
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("server_ip")
    parser.add_argument("server_port", type=int)
    parser.add_argument("username")
    args = parser.parse_args()
    main(args.server_ip, args.server_port, args.username)
