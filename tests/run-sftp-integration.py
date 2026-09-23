"""Run regression tests against a disposable SSH/SFTP server on loopback."""
import logging
import os
import posixpath
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "obj" / "sftp-test-python"))
import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
STOP = threading.Event()
TRANSPORTS = []


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("test", "test") else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        def shell():
            try:
                channel.sendall(b"test$ \x1b[0m")
                buffer = b""
                while not STOP.is_set():
                    data = channel.recv(1024)
                    if not data:
                        return
                    buffer += data
                    while b"\n" in buffer:
                        command, buffer = buffer.split(b"\n", 1)
                        if command.strip() == b"sudo -s":
                            channel.sendall(b"root# \x1b[0m")
                        elif command.strip() == b"stall":
                            pass
                        else:
                            channel.sendall(b"test output\r\nroot# ")
            except (OSError, EOFError):
                pass
        threading.Thread(target=shell, daemon=True).start()
        return True


class Handle(paramiko.SFTPHandle):
    def __init__(self, flags, file, stalled):
        super().__init__(flags)
        self.readfile = self.writefile = file
        self.stalled = stalled

    def stat(self):
        return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))

    def read(self, offset, length):
        if self.stalled:
            STOP.wait(30)
            return paramiko.SFTP_FAILURE
        return super().read(offset, length)

    def write(self, offset, data):
        if self.stalled:
            STOP.wait(30)
            return paramiko.SFTP_FAILURE
        return super().write(offset, data)


class Sftp(paramiko.SFTPServerInterface):
    def __init__(self, server, root):
        super().__init__(server)
        self.root = root

    def canonicalize(self, path):
        return posixpath.normpath("/" + path.lstrip("/"))

    def local(self, path):
        target = (self.root / path.lstrip("/")).resolve()
        if not target.is_relative_to(self.root):
            raise PermissionError("Outside test root")
        return target

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(self.local(path).stat())
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    lstat = stat

    def list_folder(self, path):
        if path == "/stall-dir":
            STOP.wait(30)
            return paramiko.SFTP_FAILURE
        try:
            entries = []
            for child in self.local(path).iterdir():
                attributes = paramiko.SFTPAttributes.from_stat(child.stat())
                attributes.filename = child.name
                entries.append(attributes)
            return entries
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def mkdir(self, path, attr):
        try:
            self.local(path).mkdir()
            return paramiko.SFTP_OK
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def open(self, path, flags, attr):
        try:
            descriptor = os.open(self.local(path), flags | getattr(os, "O_BINARY", 0), 0o600)
            mode = "r+b" if flags & os.O_RDWR else "wb" if flags & os.O_WRONLY else "rb"
            return Handle(flags, os.fdopen(descriptor, mode), path == "/stall.bin" or path.startswith("/stall-upload/"))
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)


def run():
    key = paramiko.RSAKey.generate(2048)
    with tempfile.TemporaryDirectory(prefix="AutoSSH-server-") as directory:
        root = Path(directory).resolve()
        (root / "stall.bin").write_bytes(b"stalled content")
        (root / "stall-dir").mkdir()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.2)
            port = listener.getsockname()[1]

            def serve():
                while not STOP.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    transport = paramiko.Transport(connection)
                    TRANSPORTS.append(transport)
                    transport.add_server_key(key)
                    transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Sftp, root)
                    transport.start_server(server=Server())

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                # AUTOSSH_TEST_EXE runs a prebuilt (e.g. native AOT) test executable instead of dotnet run.
                test_exe = os.environ.get("AUTOSSH_TEST_EXE")
                command = [test_exe] if test_exe else ["dotnet", "run", "--project", "tests/AutoSSH.RegressionTests", "-c", "Release", "--"]
                result = subprocess.run(
                    command + ["--integration-port", str(port)],
                    cwd=REPO, timeout=60, capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                print(result.stdout, end="")
                print(result.stderr, end="", file=sys.stderr)
                return result.returncode
            finally:
                STOP.set()
                for transport in TRANSPORTS:
                    transport.close()
                thread.join(timeout=2)


if __name__ == "__main__":
    sys.exit(run())
