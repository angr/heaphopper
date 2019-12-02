import os
import re
import math
import IPython
import logging

import angr
from angr import SimHeapBrk
import claripy

from ..heap_condition_tracker import HeapConditionTracker, MallocInspect, FreeInspect
from ...utils.angr_tools import all_bytes, heardEnter
from . import GlibcPlugin

logger = logging.getLogger('post-corruption-analysis')

def use_sim_procedure(name):
    if name in ['puts', 'printf', '__libc_start_main']:
        return False
    else:
        return True

class PostCorruptionPlugin(GlibcPlugin):
    def __init__(self, binary_name, config):
        super().__init__(binary_name, config)
        logging.basicConfig()
        logger.setLevel(config['log_level'])

    @classmethod
    def name(self):
        return "post_corruption"

    def setup_project(self):
        super().setup_project()
        # Find alloc_target
        self.alloc_target_var = self.proj.loader.main_object.get_symbol('alloc_target')

    def setup_state(self):
        '''
        Configure state and fill memory with symbolic variables
        '''
        super().setup_state()
        self.state.heaphopper.atarget = (self.alloc_target_var.rebased_addr, self.alloc_target_var.size)


    def setup_vars(self):
        super().setup_vars()
        self.var_dict['global_vars'].append(self.alloc_target_var.rebased_addr)
        # get target_func addr
        self.target_func = self.proj.loader.main_object.get_symbol(self.config['target_func'])
        self.var_dict['target_func'] = self.target_func.rebased_addr

        return self.var_dict

    def post_corruption_analysis(self, state):
        logger.info("Starting post-corruption analysis")
        logger.info("Checking if target_func is reachable")
        sm = self.proj.factory.simgr(state)
        sm.use_technique(angr.exploration_techniques.Explorer(find=self.finds, avoid=self.avoids))

        # Manual inspection loop
        debug = False
        stop = False
        while len(sm.active) > 0 and len(sm.found) == 0 and not stop:
            if debug:
                debug = False
                IPython.embed()

            sm.step()

            if heardEnter():
                debug = True
            if len(sm.unconstrained) > 0:
                if self.check_target_func_reachability(sm.unconstrained[0]):
                    sm.move(from_stash='unconstrained', to_stash='active')
                    #sm.move(from_stash='unconstrained', to_stash='found')
                    #sm.move(from_stash='active', to_stash='unused')
        if len(sm.found) > 0:
            logger.info("Reached target func")
            found = sm.found[0]
            found.vuln_state = found.copy()
            return found
        else:
            logger.info("Couldn't reach target func")
            return state

    def check_target_func_reachability(self, state):
        constr = state.ip == self.target_func.rebased_addr
        if state.solver.satisfiable(extra_constraints=[constr]):
            state.add_constraints(constr)
            return True
        else:
            return False