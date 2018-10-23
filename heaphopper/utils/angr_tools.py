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
        # import IPython; IPython.embed()
        return file.content
    indexes = list(file.mem.keys())
    if len(indexes) == 0:
        return file.state.solver.BVV("")
    min_idx = min(indexes)
    max_idx = max(indexes)
    buff = [ ]
    for i in range(min_idx, max_idx+1):
        buff.append(file.load(i, 1))
    return file.state.solver.Concat(*buff)

