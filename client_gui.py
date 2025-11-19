#!/usr/bin/env python3
# client_gui.py - simple GUI TCP chat + file client for server.py

import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os

BUFFER = 4096

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Socket Chat Client")

        self.sock = None
        self.connected = False

        # --- Connection Frame ---
        connect_frame = tk.Frame(root)
        connect_frame.pack(pady=5)

        tk.Label(connect_frame, text="Server IP:").grid(row=0, column=0)
        self.ip_entry = tk.Entry(connect_frame, width=15)
        self.ip_entry.grid(row=0, column=1)
        self.ip_entry.insert(0, "20.244.4.92")     # default

        tk.Label(connect_frame, text="Port:").grid(row=0, column=2)
        self.port_entry = tk.Entry(connect_frame, width=6)
        self.port_entry.grid(row=0, column=3)
        self.port_entry.insert(0, "5001")          # default

        tk.Label(connect_frame, text="Username:").grid(row=0, column=4)
        self.name_entry = tk.Entry(connect_frame, width=10)
        self.name_entry.grid(row=0, column=5)
        self.name_entry.insert(0, "Havindu")

        self.connect_button = tk.Button(connect_frame, text="Connect", command=self.connect_server)
        self.connect_button.grid(row=0, column=6, padx=5)

        # --- Chat Display ---
        self.chat_box = scrolledtext.ScrolledText(root, width=70, height=20, state=tk.DISABLED)
        self.chat_box.pack(padx=10, pady=5)

        # --- Message Entry ---
        msg_frame = tk.Frame(root)
        msg_frame.pack()

        self.msg_entry = tk.Entry(msg_frame, width=50)
        self.msg_entry.grid(row=0, column=0, padx=5)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())

        self.send_btn = tk.Button(msg_frame, text="Send", command=self.send_message)
        self.send_btn.grid(row=0, column=1)

        self.file_btn = tk.Button(msg_frame, text="Send File", command=self.send_file)
        self.file_btn.grid(row=0, column=2, padx=5)

    # --------------------------------------------------------------
    # Connect to server
    # --------------------------------------------------------------
    def connect_server(self):
        if self.connected:
            messagebox.showinfo("Info", "Already connected!")
            return

        ip = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())
        username = self.name_entry.get().strip()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((ip, port))
            self.sock.sendall(f"NAME:{username}\n".encode("utf-8"))

            self.connected = True
            self.connect_button.config(state=tk.DISABLED)
            self.log(f"Connected to {ip}:{port} as {username}")

            threading.Thread(target=self.recv_loop, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    # --------------------------------------------------------------
    # Receive Loop
    # --------------------------------------------------------------
    def recv_loop(self):
        leftover = b''
        try:
            while True:
                data = self.sock.recv(BUFFER)
                if not data:
                    self.log("[*] Disconnected from server")
                    break

                buf = leftover + data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", errors="ignore")

                    if text.startswith("MSG:"):
                        _, sender, msg = text.split(":", 2)
                        self.log(f"[{sender}] {msg}")

                    elif text.startswith("FILE:"):
                        _, uname, filename, size_s = text.split(":", 3)
                        size = int(size_s)

                        received = b''
                        take = min(size, len(buf))
                        if take:
                            received += buf[:take]
                            buf = buf[take:]

                        remaining = size - len(received)
                        while remaining > 0:
                            chunk = self.sock.recv(min(BUFFER, remaining))
                            if not chunk:
                                break
                            received += chunk
                            remaining -= len(chunk)

                        save_name = f"recv_{uname}_{filename}"
                        with open(save_name, "wb") as f:
                            f.write(received)

                        self.log(f"[{uname}] sent file saved as {save_name} ({size} bytes)")

                    else:
                        self.log(f"Unknown header: {text}")

                leftover = buf
        except:
            self.log("Connection closed.")

    # --------------------------------------------------------------
    def send_message(self):
        if not self.connected:
            return
        msg = self.msg_entry.get().strip()
        if msg == "":
            return
        username = self.name_entry.get().strip()
        header = f"MSG:{username}:{msg}\n".encode("utf-8")
        self.sock.sendall(header)
        self.msg_entry.delete(0, tk.END)

    # --------------------------------------------------------------
    def send_file(self):
        if not self.connected:
            return

        path = filedialog.askopenfilename()
        if not path:
            return

        try:
            username = self.name_entry.get().strip()
            size = os.path.getsize(path)
            filename = os.path.basename(path)

            header = f"FILE:{username}:{filename}:{size}\n".encode("utf-8")
            self.sock.sendall(header)

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(BUFFER)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)

            self.log(f"Sent file {filename} ({size} bytes)")

        except Exception as e:
            self.log(f"File send error: {e}")

    # --------------------------------------------------------------
    def log(self, text):
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, text + "\n")
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)


# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
