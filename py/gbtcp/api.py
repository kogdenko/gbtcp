import sys
import os
import errno
import socket
import struct
import inspect
import importlib
import importlib.util

from google.protobuf.message import Message

import gbtcp.config

class Info:
    rq = None
    rp = None
    is_dump = False

def _create_api_dict(package_path):
    messages = {}

    for root, _, files in os.walk(package_path):
        for file in files:
            if file.endswith('.py'):
#            if file.endswith('_pb2.py'):
                filepath = os.path.join(root, file)
                module_name = file[:-3]

                path = os.path.relpath(root, package_path)
                if path != '.':
                    parts = path.split(os.sep)
                    module_name = '.'.join(parts + [module_name])
    
                spec = importlib.util.spec_from_file_location(module_name, filepath)
                module = importlib.util.module_from_spec(spec)

                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, Message):
                        if messages.get(name) != None:
                            raise APIClient.InitException(msg, 'duplicate')
                        messages[name] = obj

    api_dict = {}
    for name, obj in messages.items():
        if name.endswith("Reply"):
            rq_name = name[:-5]
            is_dump = False
        elif name.endswith("Details"):
            rq_name = name[:-7] + "Dump"
            is_dump = True
        else:
            continue

        msg = messages.get(rq_name)
        if msg == None:
            raise APIClient.InitException(name, f"`{rq_name}` not defined")

        info = Info()
        info.rq = msg
        info.rpl = obj
        info.is_dump = is_dump
        api_dict[rq_name] = info

    return api_dict

class APIClient:
    MSG_REQUEST = 1
    MSG_REPLY = 2

    class InitException(Exception):
        def __init__(self, msg, cause):
            self.msg = msg;
            super().__init__(f"gbtcp `{msg}` initialization error: {cause}")

    class ExecFailed(Exception):
        def __init__(self, msg, code):
            self.msg = msg
            self.code = code
            super().__init__(f"gbtcp `{msg}` execution failed ({code}:{os.strerror(code)})")

    class ExecError(Exception):
        def __init__(self, msg, cause):
            self.msg = msg
            self.cause = cause
            super().__init__(f"gbtcp `{msg}` execution error ({cause})")

    def __init__(self, sock_path=None):
        if sock_path == None:
            sock_path=gbtcp.config.GT_API_SOCK_PATH
        self._sock = None
        self.sock_path = sock_path

        proto_path = os.path.dirname(os.path.abspath(__file__)) + "/proto"
        sys.path.insert(0, proto_path)

        self.dict = _create_api_dict(proto_path)

    def __del__(self):
        self._close()

    def _open(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self.sock_path)
        self._sock.settimeout(10)
        self._buf = b''

    def _close(self):
        if self._sock is not None:
            self._sock.close()
            self._sock = None
            self.buf = None

    def _recv(self, msg, size):
        while len(self._buf) < size:
            received = self._sock.recv(65536)
            if len(received) == 0:
                raise ConnectionAbortedError(f"connection was closed during `{msg}` processing")
            self._buf += received

        res = self._buf[:size]
        self._buf = self._buf[size:]
        return res

    def _parse(self, info, s):
        rp = info.rpl()
        try:
            rp.ParseFromString(s)
        except Exception as e:
            self._close()
            raise self.ExecError(msg, 'invalid response')
        return rp

    def _get_info(self, msg):
        info = self.dict.get(msg)
        if info == None:
            raise ExecError(msg, "unknown message")
        return info


    def send(self, m):
        msg = type(m).__name__
        info = self._get_info(msg)

        data = m.SerializeToString()

        rq = struct.pack('>IHH', len(data), self.MSG_REQUEST, 0)
        rq += msg.encode('utf-8') +  b'\x00'

        if self._sock is None:
            self._open()

        self._sock.sendall(rq + data)

    def recv(self, msg):
        info = self._get_info(msg)

        details = []
        while True:
            hdr = self._recv(msg, 8)
            size, type, code = struct.unpack('>IHH', hdr)

            data = self._recv(msg, size)

            if info.is_dump:
                if code == errno.EAGAIN:
                    return details
                elif code != 0:
                    raise self.ExecFailed(msg, code)
                else:
                    details.append(self._parse(info, data)) 
            else:
                if code != 0:
                    raise self.ExecFailed(msg, code)
                return self._parse(info, data);

    def exec(self, m):
        msg = type(m).__name__

        self.send(m)

        return self.recv(msg)
