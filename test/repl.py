#!/usr/bin/python

import os
import sys
import code
from io import StringIO

class Interpreter():
    def __init__(self):
        self.interpreter = code.InteractiveInterpreter()
        self.stdout = sys.stdout
        sys.stdout = self.captured = StringIO()
        self.log = open("/tmp/log.txt", "w")

    def __del__(self):
        sys.stdout = self.stdout

    def write(self, s):
        self.stdout.write(s)
        self.stdout.flush()

    def exec(self, command):
        self.log.write(command + "\n")
        self.log.flush()

        stdout_empty = self.interpreter.runsource(command)
        if not stdout_empty:
            output = self.captured.getvalue().strip()
            self.captured.truncate(0)
            self.write(output)

def main():
    i = Interpreter()

    i.write("> ");
    for line in sys.stdin:
        i.exec(line)
        i.write("> ")

if __name__ == "__main__":
    try:
        code = main()
    except Exception as e:
        print(e)
        code = 1
    sys.exit(code)
