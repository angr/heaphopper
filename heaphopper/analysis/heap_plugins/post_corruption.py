import os
import re
import math

import angr
from angr import SimHeapBrk
import claripy

from ..heap_condition_tracker import HeapConditionTracker, MallocInspect, FreeInspect
from ...utils.angr_tools import all_bytes
from . import GlibcPlugin

def use_sim_procedure(name):
    if name in ['puts', 'printf', '__libc_start_main']:
        return False
    else:
        return True

class PostCorruptionPlugin(GlibcPlugin):
    @classmethod
    def name(self):
        return "glibc"

    def setup_project(self):
        super().setup_project()
        # Find alloc_target
        self.alloc_target_var = self.proj.loader.main_object.get_symbol('alloc_target')

    def setup_state(self):
        '''
        Configure state and fill memory with symbolic variables
        '''
        super().setup_state()


    def setup_vars(self):
        super().setup_vars()

        # get target_func addr
        target_func = self.proj.loader.main_object.get_symbol(self.config['target_func'])
        self.var_dict['target_func'] = target_func.rebased_addr

        return self.var_dict

    def post_corruption_analysis(self):
        # TODO
        pass