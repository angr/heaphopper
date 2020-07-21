import select
import sys

from angr import SimPacketsStream


def heardEnter():
    i, o, e = select.select([sys.stdin], [], [], 0.0001)
    for s in i:
        if s == sys.stdin:
            input = sys.stdin.readline()
            return True
    return False


def all_bytes(file):
    if type(file) == SimPacketsStream:
        return file.content
    indexes = list(file.mem.keys())
    if len(indexes) == 0:
        return file.state.solver.BVV("")
    max_size = file.state.solver.max(file.size)
    return file.load(0, max_size)

