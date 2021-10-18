import select
import sys

from angr import SimPacketsStream


def heardEnter():
    if sys.stdin is not None:
        i, o, e = select.select([sys.stdin], [], [], 0.0001)
        for s in i:
            if s == sys.stdin:
                sys.stdin.readline()
                return True
    return False


def all_bytes(file):
    if type(file) == SimPacketsStream:
        return file.content
    max_size = file.state.solver.max(file.size)
    return file.load(0, max_size)

