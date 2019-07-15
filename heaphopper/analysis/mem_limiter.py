import angr
import psutil
import os
import logging

logger = logging.getLogger('MemLimiter')


class MemLimiter(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, max_mem, drop_errored):
        super(MemLimiter, self).__init__()
        self.max_mem = max_mem
        self.drop_errored = drop_errored
        self.process = psutil.Process(os.getpid())

    def step(self, simgr, stash='active', **kwargs):
        if psutil.virtual_memory().percent > 90 or (self.max_mem - 1) < self.memory_usage_psutil:
            simgr.move(from_stash='active', to_stash='out_of_memory')
            simgr.move(from_stash='deferred', to_stash='out_of_memory')

        simgr.drop(stash='deadended')
        simgr.drop(stash='avoid')
        simgr.drop(stash='found')
        if self.drop_errored:
            del simgr.errored[:]

        return simgr.step(stash=stash)

    @property
    def memory_usage_psutil(self):
        # return the memory usage in MB
        mem = self.process.memory_info().vms / float(2 ** 30)
        return mem
