import angr
import psutil
import os
import sys
import logging

logger = logging.getLogger('MemLimiter')

class MemLimiter(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, max_mem, drop_errored):
        super(MemLimiter, self).__init__()
        self.max_mem = max_mem
        self.drop_errored = drop_errored
        self.process = psutil.Process(os.getpid())

    def step(self, sm, stash, **kwargs):
        if psutil.virtual_memory().percent > 90 or self.memory_usage_psutil() > (self.max_mem - 1):
            sm.move(from_stash='active', to_stash='out_of_memory')
            sm.move(from_stash='deferred', to_stash='out_of_memory')

        sm.drop(stash='deadended')
        sm.drop(stash='avoid')
        sm.drop(stash='found')
        if self.drop_errored:
            del sm.errored[:]

        return sm.step(stash=stash)

    def memory_usage_psutil(self):
        # return the memory usage in MB
        mem = self.process.memory_info().vms / float(2 ** 30)
        return mem
