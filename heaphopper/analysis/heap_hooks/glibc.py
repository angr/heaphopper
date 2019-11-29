import os
import re
import math

import angr
from angr import SimHeapBrk
import claripy

from ..heap_condition_tracker import HeapConditionTracker, MallocInspect, FreeInspect
from ...utils.angr_tools import all_bytes
from . import AbstractHeapHook

def use_sim_procedure(name):
    if name in ['puts', 'printf', '__libc_start_main']:
        return False
    else:
        return True

class GlibcHook(AbstractHeapHook):
    @classmethod
    def name(self):
        return "glibc"

    def setup_project(self):
        # Get libc path
        self.libc_path = os.path.expanduser(self.config['libc'])
        self.libc_name = os.path.basename(self.libc_path)

        # Get allocator path
        self.allocator_path = os.path.expanduser(self.config['allocator'])
        if self.allocator_path == 'default':
            self.allocator_path = self.libc_path

        self.allocator_name = os.path.basename(self.allocator_path)

        # Create project and disable sim_procedures for the libc
        self.proj = angr.Project(self.binary_name, exclude_sim_procedures_func=use_sim_procedure,
                            load_options={'ld_path':[os.path.dirname(self.allocator_path), os.path.dirname(self.libc_path)],
                                                'auto_load_libs':True})

        # Find write_target
        self.write_target_var = self.proj.loader.main_object.get_symbol('write_target')

        # Get libc
        self.libc = self.proj.loader.shared_objects[self.libc_name]

        # Get allocator
        self.allocator = self.proj.loader.shared_objects[self.allocator_name]


    def hook(self):
        # Hook malloc and free
        malloc_addr = self.allocator.get_symbol('malloc').rebased_addr
        free_addr = self.allocator.get_symbol('free').rebased_addr
        malloc_plt = self.proj.loader.main_object.plt.get('malloc')
        free_plt = self.proj.loader.main_object.plt.get('free')
        self.proj.hook(addr=malloc_plt,
                hook=MallocInspect(malloc_addr=malloc_addr, vulns=self.config['vulns'], ctrl_data=self.var_dict['allocs']))
        self.proj.hook(addr=free_plt,
                hook=FreeInspect(free_addr=free_addr, vulns=self.config['vulns'], sym_data=self.var_dict['sdata_addrs']))



    '''
    cle issue related workarounds
    '''
    def fix_loader_problem(self, proj, state, loader_name, version):
        loader_bin = proj.loader.shared_objects[loader_name]
        rtld_global = loader_bin.get_symbol('_rtld_global').rebased_addr

        # magic_offset = 0x227160
        # magic_offset = 0xef0

        if version == '2.27':
            where = rtld_global + 0xf00
            magic_offset = 0x10e0
            what = loader_bin.mapped_base + magic_offset
        else:
            raise Exception("Don't know how to fix loader problem for libc-{}".format(version))

        state.memory.store(where, what, endness="Iend_LE")

    '''
    Configure state and fill memory with symbolic variables
    '''


    def setup_state(self):
                # Create state and enable reverse memory map
        added_options = set()
        added_options.add(angr.options.REVERSE_MEMORY_NAME_MAP)
        added_options.add(angr.options.STRICT_PAGE_ACCESS)
        added_options.add(angr.options.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES)
        added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        added_options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        added_options.add(angr.options.SIMPLIFY_EXPRS)
        added_options.update(angr.options.simplification)
        added_options.update(angr.options.unicorn)

        if self.config['use_vsa']:
            added_options.add(angr.options.APPROXIMATE_SATISFIABILITY)  # vsa for satisfiability
            added_options.add(angr.options.APPROXIMATE_GUARDS)          # vsa for guards
            added_options.add(angr.options.APPROXIMATE_MEMORY_SIZES)    # vsa for mem_sizes
            added_options.add(angr.options.APPROXIMATE_MEMORY_INDICES)  # vsa for mem_indices

        removed_options = set()
        removed_options.add(angr.options.LAZY_SOLVES)

        # set heap location right after bss
        bss = self.proj.loader.main_object.sections_map['.bss']
        heap_base = ((bss.vaddr + bss.memsize) & ~0xfff) + 0x1000
        heap_size = 64 * 4096
        new_brk = claripy.BVV(heap_base + heap_size, self.proj.arch.bits)


        heap = SimHeapBrk(heap_base=heap_base, heap_size=heap_size)
        self.state = self.proj.factory.entry_state(add_options=added_options, remove_options=removed_options)
        self.state.register_plugin('heap', heap)
        self.state.register_plugin('heaphopper', HeapConditionTracker(config=self.config,
                                                        wtarget=(self.write_target_var.rebased_addr,
                                                                    self.write_target_var.size),
                                                        libc=self.libc, allocator=self.allocator))

        self.state.posix.set_brk(new_brk)
        self.state.heaphopper.set_level(self.config['log_level'])

        if self.config['fix_loader_problem']:
            loader_name = os.path.basename(self.config['loader'])
            libc_version = re.findall(r'libc-([\d\.]+)', self.libc_path)[0]
            self.fix_loader_problem(self.proj, self.state, loader_name, libc_version)

        self.setup_vars()

        # Set memory concretization strategies
        self.state.memory.read_strategies = [
            angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategySolutions(16),
            angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyControlledData(4096,
                                                                                                                self.var_dict[
                                                                                                                    'global_vars']),
            angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyEval(4096)]
        self.state.memory.write_strategies = [
            angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategySolutions(16),
            angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyControlledData(4096,
                                                                                                                self.var_dict[
                                                                                                                    'global_vars']),
            angr.state_plugins.symbolic_memory.concretization_strategies.SimConcretizationStrategyEval(4096)]

        # Get finds and avoids
        self.finds = (self.var_dict['winning_addr'],)
        self.avoids = (self.libc.get_symbol('abort').rebased_addr,)


    def setup_vars(self):

        # Inject symbolic controlled data into memory
        self.var_dict = dict()
        self.var_dict['global_vars'] = []
        self.var_dict['allocs'] = []
        for i in range(20):
            cdata = self.proj.loader.main_object.get_symbol('ctrl_data_{}'.format(i))
            # check if ctrl_data exists
            if not cdata:
                break

            self.var_dict['global_vars'].append(cdata.rebased_addr)
            self.var_dict['allocs'].append(cdata.rebased_addr)

        # Set mem2chunk offset
        mem2chunk_var = self.proj.loader.main_object.get_symbol('mem2chunk_offset')
        self.var_dict['mem2chunk_addr'] = mem2chunk_var.rebased_addr
        mem2chunk = self.state.solver.BVV(value=self.config['mem2chunk_offset'], size=8 * 8)
        self.state.memory.store(self.var_dict['mem2chunk_addr'], mem2chunk, 8, endness='Iend_LE')

        # Inject symbolic data into memory that can't be resolved
        self.var_dict['sdata_addrs'] = []
        sdata_var = self.proj.loader.main_object.get_symbol('sym_data')
        # check if sym_data exists
        if sdata_var:
            for i in range(0, self.config['sym_data_size'], 8):
                smem_elem = self.state.solver.BVS('smem', 8 * 8)
                self.state.memory.store(sdata_var.rebased_addr + i, smem_elem, 8, endness='Iend_LE')
                self.var_dict['sdata_addrs'].append(sdata_var.rebased_addr + i)

            # create entry in sym_data state storage
            self.var_dict['sym_data_ptr'] = sdata_var.rebased_addr + self.config['mem2chunk_offset']
            self.state.heaphopper.sym_data_states[self.var_dict['sym_data_ptr']] = None
            # add sym_data_size to heap state
            self.state.heaphopper.sym_data_size = self.config['sym_data_size']
            # add global_ptr to global_vars:
            self.var_dict['global_vars'].append(sdata_var.rebased_addr)

        # Setup write_target
        self.var_dict['wtarget_addrs'] = []
        write_target_var = self.proj.loader.main_object.get_symbol('write_target')
        for i in range(0, write_target_var.size, 8):
            write_mem_elem = self.state.solver.BVS('write_mem', 8 * 8)
            self.state.memory.store(write_target_var.rebased_addr + i, write_mem_elem, 8, endness='Iend_LE')
            self.var_dict['wtarget_addrs'].append(write_target_var.rebased_addr + i)
            self.var_dict['global_vars'].append(write_target_var.rebased_addr + i)

        # Set header size
        header_size_var = self.proj.loader.main_object.get_symbol('header_size')
        self.var_dict['header_size_addr'] = header_size_var.rebased_addr
        header_size = self.state.solver.BVV(value=self.config['header_size'], size=8 * 8)
        self.state.memory.store(self.var_dict['header_size_addr'], header_size, 8, endness='Iend_LE')


        # Set malloc sizes
        malloc_size_var = self.proj.loader.main_object.get_symbol('malloc_sizes')
        self.var_dict['malloc_size_addrs'] = [malloc_size_var.rebased_addr + i for i in range(0, malloc_size_var.size, 8)]
        self.var_dict['malloc_size_bvs'] = []

        if max(self.config['malloc_sizes']) != 0:
            bvs_size = int(math.ceil(math.log(max(self.config['malloc_sizes']), 2))) + 1
        else:
            bvs_size = 8
        num_bytes = int(math.ceil(bvs_size / float(self.state.arch.byte_width)))
        bit_diff = num_bytes * self.state.arch.byte_width - bvs_size

        for msize in self.var_dict['malloc_size_addrs']:
            if len(self.config['malloc_sizes']) > 1:
                malloc_var = self.state.solver.BVS('malloc_size', bvs_size).zero_extend(bit_diff)
                constraint = claripy.Or(malloc_var == self.config['malloc_sizes'][0])
                for bin_size in self.config['malloc_sizes'][1:]:
                    constraint = claripy.Or(malloc_var == bin_size, constraint)
                self.state.add_constraints(constraint)
            else:
                malloc_var = self.state.solver.BVV(self.config['malloc_sizes'][0], self.state.arch.bits)
            self.var_dict['malloc_size_bvs'].append(malloc_var)
            self.state.memory.store(msize, claripy.BVV(0, 8 * 8), endness='Iend_LE')  # zero-fill first just in case
            self.state.memory.store(msize, malloc_var, endness='Iend_LE')

        # Set fill sizes
        fill_size_var = self.proj.loader.main_object.get_symbol('fill_sizes')
        self.var_dict['fill_size_addrs'] = [fill_size_var.rebased_addr + i for i in range(0, fill_size_var.size, 8)]
        self.var_dict['fill_size_vars'] = []
        if self.config['chunk_fill_size'] == 'zero':
            self.var_dict['fill_size_vars'] = [self.state.solver.BVV(0, 8 * 8)] * len(self.var_dict['fill_size_addrs'])
        if self.config['chunk_fill_size'] == 'header_size':
            self.var_dict['fill_size_vars'] = [header_size] * len(self.var_dict['fill_size_addrs'])
        if self.config['chunk_fill_size'] == 'chunk_size':
            self.var_dict['fill_size_vars'] = self.var_dict['malloc_size_bvs']
        if type(self.config['chunk_fill_size']) in (int, int):
            self.var_dict['fill_size_vars'] = [claripy.BVV(self.config['chunk_fill_size'], 8 * 8)] * len(self.var_dict['fill_size_addrs'])

        for fsize, fill_var in zip(self.var_dict['fill_size_addrs'], self.var_dict['fill_size_vars']):
            self.state.memory.store(fsize, claripy.BVV(0, 8 * 8), endness='Iend_LE')  # zero-fill first just in case
            self.state.memory.store(fsize, fill_var, endness='Iend_LE')

        # Set overflow sizes
        overflow_size_var = self.proj.loader.main_object.get_symbol('overflow_sizes')
        overflow_size_offset = overflow_size_var.rebased_addr
        self.var_dict['overflow_sizes_addrs'] = [overflow_size_offset + i for i in range(0, overflow_size_var.size, 8)]

        if max(self.config['overflow_sizes']) != 0:
            bvs_size = int(math.ceil(math.log(max(self.config['overflow_sizes']), 2))) + 1
        else:
            bvs_size = 8
        num_bytes = int(math.ceil(bvs_size / float(self.state.arch.byte_width)))
        bit_diff = num_bytes * self.state.arch.byte_width - bvs_size

        self.var_dict['overflow_sizes'] = []
        for overflow_size_addr in self.var_dict['overflow_sizes_addrs']:
            if len(self.config['overflow_sizes']) > 1:
                overflow_var = self.state.solver.BVS('overflow_size', bvs_size).zero_extend(bit_diff)
                constraint = claripy.Or(overflow_var == self.config['overflow_sizes'][0])
                for bin_size in self.config['overflow_sizes'][1:]:
                    constraint = claripy.Or(overflow_var == bin_size, constraint)
                self.state.add_constraints(constraint)
            else:
                overflow_var = self.state.solver.BVV(self.config['overflow_sizes'][0], self.state.arch.bits)
            self.var_dict['overflow_sizes'].append(overflow_var)

            self.state.memory.store(overflow_size_addr, overflow_var, endness='Iend_LE')

        # Get arb_write_offsets
        self.var_dict['arb_offset_vars'] = []
        arb_write_var = self.proj.loader.main_object.get_symbol('arw_offsets')
        for i in range(0, arb_write_var.size, 8):
            self.var_dict['arb_offset_vars'].append(arb_write_var.rebased_addr + i)

        # Get bf_offsets
        self.var_dict['bf_offset_vars'] = []
        bf_var = self.proj.loader.main_object.get_symbol('bf_offsets')
        for i in range(0, bf_var.size, 8):
            self.var_dict['bf_offset_vars'].append(bf_var.rebased_addr + i)

        # get winning addr
        self.var_dict['winning_addr'] = self.proj.loader.main_object.get_symbol('winning').rebased_addr

        return self.var_dict

    '''
    Post processing states
    '''
    def process_state(self, num_results, state, write_state, fd):
        result = dict()
        result['file'] = self.binary_name
        result['input_opts'] = []
        result['stdin_opts'] = []
        result['symbolic_data'] = []
        result['malloc_sizes'] = []
        result['fill_sizes'] = []
        result['header_sizes'] = []
        result['overflow_sizes'] = []
        result['write_targets'] = []
        result['mem2chunk_offset'] = state.solver.eval(state.memory.load(self.var_dict['mem2chunk_addr'], 8,
                                                                                   endness='Iend_LE'))
        result['stack_trace'] = state.heaphopper.stack_trace
        result['last_line'] = state.heaphopper.last_line
        result['heap_base'] = state.heap.heap_base
        result['allocs'] = []
        result['arb_write_offsets'] = []
        result['arb_writes'] = []
        result['bf_offsets'] = []
        result['vuln_type'] = state.heaphopper.vuln_type

        input_opts = state.solver.eval_upto(all_bytes(state.posix.fd[fd].read_storage), num_results, cast_to=bytes)
        for input_opt in input_opts:
            s = state.copy()
            write_s = write_state.copy()
            s.add_constraints(all_bytes(s.posix.fd[fd].read_storage) == input_opt)
            write_s.add_constraints(all_bytes(write_s.posix.fd[fd].read_storage) == input_opt)

            stdin_bytes = all_bytes(state.posix.fd[0].read_storage)
            if stdin_bytes:
                stdin_bytes = [b[0] for b in stdin_bytes]
                stdin_stream = stdin_bytes[0]
                for b in stdin_bytes[1:]:
                    stdin_stream = stdin_stream.concat(b)
                stdin_opt = state.solver.eval(stdin_stream, cast_to=bytes)
                s.add_constraints(stdin_stream == stdin_opt)
                write_s.add_constraints(stdin_stream == stdin_opt)
            else:
                stdin_opt = []

            svars = []
            # check if we have a saved-state for the sym_data memory
            if 'sym_data_ptr' in self.var_dict and s.heaphopper.sym_data_states[self.var_dict['sym_data_ptr']]:
                sym_s = s.heaphopper.sym_data_states[self.var_dict['sym_data_ptr']].copy()
                sym_s.add_constraints(all_bytes(sym_s.posix.fd[fd].read_storage) == input_opt)
                if stdin_opt:
                    sym_s.add_constraints(stdin_stream == stdin_opt)
            else:
                sym_s = s
            for svar in self.var_dict['sdata_addrs']:
                smem_orig = sym_s.memory.load(svar, 8, endness='Iend_LE')
                smem_final = s.memory.load(svar, 8, endness='Iend_LE')
                # If the symbolic variable was overwritten, use the orig one
                if smem_orig is not smem_final:
                    sol = sym_s.solver.min(smem_orig)
                    sym_s.add_constraints(smem_orig == sol)
                else:
                    sol = s.solver.min(smem_final)
                    s.add_constraints(smem_final == sol)
                svars.append(sol)

            header_var = s.memory.load(self.var_dict['header_size_addr'], 8, endness="Iend_LE")
            header = s.solver.min(header_var)
            s.add_constraints(header_var == header)
            write_s.add_constraints(header_var == header)

            msizes = []
            for malloc_size in self.var_dict['malloc_size_addrs']:
                size_var = s.memory.load(malloc_size, 8, endness="Iend_LE")
                sol = s.solver.min(size_var)
                msizes.append(sol)
                s.add_constraints(size_var == sol)
                write_s.add_constraints(size_var == sol)

            fsizes = []
            for fill_size in self.var_dict['fill_size_vars']:
                sol = s.solver.min(fill_size)
                fsizes.append(sol)
                s.add_constraints(fill_size == sol)
                write_s.add_constraints(fill_size == sol)

            osizes = []
            for overflow_size in self.var_dict['overflow_sizes']:
                sol = s.solver.min(overflow_size)
                osizes.append(sol)
                s.add_constraints(overflow_size == sol)
                write_s.add_constraints(overflow_size == sol)

            wt_mem = []
            for write_target in self.var_dict['wtarget_addrs']:
                wt_var = write_s.memory.load(write_target, 8, endness="Iend_LE")
                sol = write_s.solver.min(wt_var)
                wt_mem.append(sol)
                write_s.add_constraints(wt_var == sol)

            allocs = []
            for allocation in self.var_dict['allocs']:
                alloc_var = s.memory.load(allocation, 8, endness="Iend_LE")
                sol = s.solver.min(alloc_var)
                allocs.append(sol)
                s.add_constraints(alloc_var == sol)
                write_s.add_constraints(alloc_var == sol)

            arb_offsets = []
            for arb_var in self.var_dict['arb_offset_vars']:
                arb_offset = s.memory.load(arb_var, 8, endness="Iend_LE")
                sol = s.solver.min(arb_offset)
                arb_offsets.append(sol)
                s.add_constraints(arb_offset == sol)
                write_s.add_constraints(arb_offset == sol)

            bf_offsets = []
            for bf_var in self.var_dict['bf_offset_vars']:
                bf_offset = s.memory.load(bf_var, 8, endness="Iend_LE")
                sol = s.solver.min(bf_offset)
                bf_offsets.append(sol)
                s.add_constraints(bf_offset == sol)
                write_s.add_constraints(bf_offset == sol)

            arb_write = {}
            if s.heaphopper.arb_write_info:
                arb_write = {k: s.solver.eval(v) for k, v in list(s.heaphopper.arb_write_info.items())}

            result['input_opts'].append(input_opt)
            result['stdin_opts'].append(stdin_opt)
            result['symbolic_data'].append(svars)
            result['header_sizes'].append(header)
            result['malloc_sizes'].append(msizes)
            result['fill_sizes'].append(fsizes)
            result['overflow_sizes'].append(osizes)
            result['write_targets'].append(wt_mem)
            result['allocs'].append(allocs)
            result['arb_write_offsets'].append(arb_offsets)
            result['bf_offsets'].append(bf_offsets)
            result['arb_writes'].append(arb_write)
        return result