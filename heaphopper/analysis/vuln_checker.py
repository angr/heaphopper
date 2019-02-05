import angr
import logging
from ..utils.input import check_input

logger = logging.getLogger('VulnChecker')


class VulnChecker(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, fd, pre_constraint, stdin_values, stop_found, filter_fake_free):
        super(VulnChecker, self).__init__()
        self.pre_constraint = pre_constraint
        self.stdin_values = stdin_values
        self.fd = fd
        self.stop_found = stop_found
        self.filter_fake_free = filter_fake_free

    def step(self, sm, stash, **kwargs):
        # We stop if we find the first vuln
        sm.move(from_stash='active', to_stash='vuln', filter_func=lambda p: p.heaphopper.vulnerable)

        if not self.pre_constraint and len(sm.vuln):
            sm.move(from_stash='vuln', to_stash='unsat_input',
                    filter_func=lambda p: check_input(p, self.stdin_values, self.fd) is None)
            if not len(sm.vuln):
                logger.info('Vuln path not reachable through stdin constraints')

        if self.stop_found and len(sm.vuln):
            sm.move(from_stash='deferred', to_stash='unused')
        elif self.filter_fake_free and len(sm.vuln):
            if any(p.state.heaphopper.fake_frees for p in sm.vuln):
                sm.move(from_stash='deferred', to_stash='unused')

        return sm.step(stash=stash)
