import angr
import logging

logger = logging.getLogger('Concretizer')


class Concretizer(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, addrs):
        super(Concretizer, self).__init__()
        self.addrs = addrs

    def step(self, simgr, stash, **kwargs):
        for addr in self.addrs:
            for s in simgr.active:
                var = s.memory.load(addr, s.arch.bits // s.arch.byte_width, endness="Iend_LE")
                if not var.symbolic:
                    return simgr.step(stash=stash)

                vals = s.solver.eval_upto(var, 2)
                if len(vals) == 1:
                    new_var = s.solver.BVV(vals[0], s.arch.bits)
                    s.memory.store(addr, new_var, endness="Iend_LE")
                    logger.info('Concretized {} @ {} to {}'.format(var, hex(addr), hex(vals[0])))

        return simgr.step(stash=stash)
