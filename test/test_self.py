#!/usr/bin/python

# SPDX-License-Identifier: LGPL-2.1-only

import threading

from common import Socket
from framework import Framework
from database import Database

class TestCase(Framework):
    def test_database(self):
        name = "gbtcp_self"

        db = Database(name)
        db.execute("drop database %s" % name)

        db = Database(name)

        tags = ""
        test = "database"
        git = "1.0"
        driver = "veth"
        cpus = 1
        pps = 100
        bps = 200
 
        test_id = db.insert_into_test(tags, test, git, driver, cpus, 0, pps, bps)
        self.assertGreater(test_id, 0)

        res = db.select_pps_from_test(tags, test, git, driver, cpus)
        self.assertNotEqual(res, None)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], pps)
        self.assertEqual(res[1], bps)

        db.execute("drop database %s" % name)

    def server_thread(self):
        server = Socket()
        server.listen(self.addr)
        self.ready.set()
        server = server.accept()
        server.set_timeout(2)
        rp = server.recv()
        self.assertEqual(len(rp), 3)
        self.assertEqual(rp[0], "111")
        self.assertEqual(rp[1], "222")
        self.assertEqual(rp[2], "333")

        rp = server.recv()
        self.assertEqual(len(rp), 0)

        self.ready.wait()

        server.close()
        print("Closed")

    def test_socket(self):
        self.addr = ('127.0.0.1', 6666)
        self.ready = threading.Event()

        thread = threading.Thread(target=self.server_thread)
        thread.start()

        client = Socket()

        self.ready.wait()
        self.ready.clear()

        client.set_timeout(3)
        client.connect(self.addr)

        client.send(["111", "222", "333"]);
        client.send([])

        self.ready.set()
        rp = client.recv()
        self.assertEqual(len(rp), 0)

        thread.join()

