from common import *
from framework import Framework
from application import Repl
from network import Network

class TestSocket(Framework):
    def _w(self, app, line, hang=False):
        print(line)
        app.proc.stdin.write(line + "\n")
        app.proc.stdin.flush()
        if not hang:
            out = self._r(app)
            if len(out):
                print(out)

    def _r(self, app):
        state = 1
        out = ""
        pipe = app.proc.stdout
        while True:
            ch = pipe.read(1)
            #print(">", ch, "<")
            if state == 0:
                if ch == '\n':
                    state += 1
                    continue
            elif state == 1:
                if ch == '>':
                    pipe.read(1)
                    out += "\n"
                    break
                else:
                    state = 0
                    out += '\n'
            out += ch

        return out

    # TODO: Пересмотреть систему редиректа пакетов в ОС, так чтобы интерфейс^
    # можно было использовать также как остальные интерфейсы
    def _test_repl(self):
        test_intf = Interface.create(singleton.tested_interface)
        test_intf.name += '^'
        host_intf = Interface.create(singleton.tested_interface)

        test_network = Network() 
        test_network.set_ip_network(ipaddress.ip_network("10.10.0.0/16"))
        test_network.set_interface(test_intf)
        test_network.set_gw_mac(host_intf.mac)

        host_network = Network() 
        host_network.set_ip_network(ipaddress.ip_network("10.10.0.0/16"))
        host_network.set_interface(host_intf)
        host_network.set_gw_mac(test_intf.mac)

        test = Repl(test_network, Transport.NETMAP)
        host = Repl(host_network, Transport.NATIVE)

        test.start(self, Mode.CLIENT, Impl.BSD44)
        host.start(None, Mode.SERVER, None)

        c = test.proc
        s = host.proc

        self._r(test);
        self._r(host)

        self._w(host, "import socket")
        self._w(host, "fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
        self._w(host, "fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)")
        self._w(host, f"fd.bind(('{host_network.server}', 6666))")
        self._w(host, "fd.listen()")
        self._w(host, "fd2 = fd.accept()", True)

        self._w(test, "import socket")
        self._w(test, "fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
        self._w(test, "fd.settimeout(2)")
        self._w(test, f"fd.connect(('{host_network.server}', 6666))")

        self._w(host, "print(fd2.fd)")
        while True:
            out = self._r(host)
            print(">>>")
            print(out)
            print("<<<")
