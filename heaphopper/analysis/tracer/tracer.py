#!/usr/bin/env python
import logging

import ana
import math
import re

import cle

import angr
import claripy
import os
import yaml
import sys
from elftools.elf.elffile import ELFFile

from angr.state_plugins import Flags, SimFile
from angr import SimHeapBrk
from ..heap_condition_tracker import HeapConditionTracker, MallocInspect, FreeInspect
from ..mem_limiter import MemLimiter
from ..vuln_checker import VulnChecker
from ..concretizer import Concretizer
from ...utils.angr_tools import heardEnter, all_bytes
from ...utils.parse_config import parse_config
from ...utils.input import constrain_input

logger = logging.getLogger('heap-tracer')

# global vars
DESC_HEADER = 'Vuln description for binary'
DESC_SECTION_LINE = '=========================================='
MALLOC_LIST = []

'''
cle issue related workarounds
'''


def fix_loader_problem(proj, state, loader_name, version):
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
Exploration helper functions
'''


def use_sim_procedure(name):
    if name in ['puts', 'printf', '__libc_start_main']:
        return False
    else:
        return True


def ana_setup():
    ana.set_dl(ana.DictDataLayer())


def ana_teardown():
    ana.set_dl(ana.SimpleDataLayer())


def priority_key(state):
    return hash(tuple(state.history.bbl_addrs))


'''
Map addrs to source code using DWARF info
'''


def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return filename, line
            prevstate = entry.state
    return None, None


def get_last_line(win_addr, bin_file):
    with open(bin_file, 'rb') as bf:
        elffile = ELFFile(bf)

        if not elffile.has_dwarf_info():
            print('{} has no DWARF info'.format(bin_file))
            sys.exit(1)

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        file_name, line = decode_file_line(dwarfinfo, win_addr)

        return line


def get_win_addr(proj, addr_trace):
    heap_func = None
    addr_trace = addr_trace[:-1]  # discard last element
    for addr in addr_trace[::-1]:
        if proj.loader.main_object.contains_addr(addr):
            if heap_func:
                return addr, heap_func
            else:  # heap-func in plt first
                heap_func = proj.loader.main_object.reverse_plt[addr]
        elif heap_func:
            # last main_object addr has to be right before heap_func call
            raise Exception("Couldn't find win addr")


'''
Post processing states
'''


def process_state(num_results, state, write_state, var_dict, fd):
    processed_states = []
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
        if 'sym_data_ptr' in var_dict and s.heaphopper.sym_data_states[var_dict['sym_data_ptr']]:
            sym_s = s.heaphopper.sym_data_states[var_dict['sym_data_ptr']].copy()
            sym_s.add_constraints(all_bytes(sym_s.posix.fd[fd].read_storage) == input_opt)
            if stdin_opt:
                sym_s.add_constraints(stdin_stream == stdin_opt)
        else:
            sym_s = s
        for svar in var_dict['sdata_addrs']:
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

        header_var = s.memory.load(var_dict['header_size_addr'], 8, endness="Iend_LE")
        header = s.solver.min(header_var)
        s.add_constraints(header_var == header)
        write_s.add_constraints(header_var == header)

        msizes = []
        for malloc_size in var_dict['malloc_size_addrs']:
            size_var = s.memory.load(malloc_size, 8, endness="Iend_LE")
            sol = s.solver.min(size_var)
            msizes.append(sol)
            s.add_constraints(size_var == sol)
            write_s.add_constraints(size_var == sol)

        fsizes = []
        for fill_size in var_dict['fill_size_vars']:
            sol = s.solver.min(fill_size)
            fsizes.append(sol)
            s.add_constraints(fill_size == sol)
            write_s.add_constraints(fill_size == sol)

        osizes = []
        for overflow_size in var_dict['overflow_sizes']:
            sol = s.solver.min(overflow_size)
            osizes.append(sol)
            s.add_constraints(overflow_size == sol)
            write_s.add_constraints(overflow_size == sol)

        wt_mem = []
        for write_target in var_dict['wtarget_addrs']:
            wt_var = write_s.memory.load(write_target, 8, endness="Iend_LE")
            sol = write_s.solver.min(wt_var)
            wt_mem.append(sol)
            write_s.add_constraints(wt_var == sol)

        allocs = []
        for allocation in var_dict['allocs']:
            alloc_var = s.memory.load(allocation, 8, endness="Iend_LE")
            sol = s.solver.min(alloc_var)
            allocs.append(sol)
            s.add_constraints(alloc_var == sol)
            write_s.add_constraints(alloc_var == sol)

        arb_offsets = []
        for arb_var in var_dict['arb_offset_vars']:
            arb_offset = s.memory.load(arb_var, 8, endness="Iend_LE")
            sol = s.solver.min(arb_offset)
            arb_offsets.append(sol)
            s.add_constraints(arb_offset == sol)
            write_s.add_constraints(arb_offset == sol)

        bf_offsets = []
        for bf_var in var_dict['bf_offset_vars']:
            bf_offset = s.memory.load(bf_var, 8, endness="Iend_LE")
            sol = s.solver.min(bf_offset)
            bf_offsets.append(sol)
            s.add_constraints(bf_offset == sol)
            write_s.add_constraints(bf_offset == sol)

        arb_write = {}
        if s.heaphopper.arb_write_info:
            arb_write = {k: s.solver.eval(v) for k, v in list(s.heaphopper.arb_write_info.items())}

        processed_states.append(
            (input_opt, stdin_opt, svars, header, msizes, fsizes, osizes, wt_mem, allocs, arb_offsets,
             bf_offsets, arb_write))
    return processed_states


'''
Configure state and fill memory with symbolic variables
'''


def setup_state(state, proj, config):

    # Inject symbolic controlled data into memory
    var_dict = dict()
    var_dict['global_vars'] = []
    var_dict['allocs'] = []
    for i in range(20):
        cdata = proj.loader.main_object.get_symbol('ctrl_data_{}'.format(i))
        # check if ctrl_data exists
        if not cdata:
            break

        var_dict['global_vars'].append(cdata.rebased_addr)
        var_dict['allocs'].append(cdata.rebased_addr)

    # Set mem2chunk offset
    mem2chunk_var = proj.loader.main_object.get_symbol('mem2chunk_offset')
    var_dict['mem2chunk_addr'] = mem2chunk_var.rebased_addr
    mem2chunk = state.solver.BVV(value=config['mem2chunk_offset'], size=8 * 8)
    state.memory.store(var_dict['mem2chunk_addr'], mem2chunk, 8, endness='Iend_LE')

    # Inject symbolic data into memory that can't be resolved
    var_dict['sdata_addrs'] = []
    sdata_var = proj.loader.main_object.get_symbol('sym_data')
    # check if sym_data exists
    if sdata_var:
        for i in range(0, config['sym_data_size'], 8):
            smem_elem = state.solver.BVS('smem', 8 * 8)
            state.memory.store(sdata_var.rebased_addr + i, smem_elem, 8, endness='Iend_LE')
            var_dict['sdata_addrs'].append(sdata_var.rebased_addr + i)

        # create entry in sym_data state storage
        var_dict['sym_data_ptr'] = sdata_var.rebased_addr + config['mem2chunk_offset']
        state.heaphopper.sym_data_states[var_dict['sym_data_ptr']] = None
        # add sym_data_size to heap state
        state.heaphopper.sym_data_size = config['sym_data_size']
        # add global_ptr to global_vars:
        var_dict['global_vars'].append(sdata_var.rebased_addr)

    # Setup write_target
    var_dict['wtarget_addrs'] = []
    write_target_var = proj.loader.main_object.get_symbol('write_target')
    for i in range(0, write_target_var.size, 8):
        write_mem_elem = state.solver.BVS('write_mem', 8 * 8)
        state.memory.store(write_target_var.rebased_addr + i, write_mem_elem, 8, endness='Iend_LE')
        var_dict['wtarget_addrs'].append(write_target_var.rebased_addr + i)
        var_dict['global_vars'].append(write_target_var.rebased_addr + i)

    # Set header size
    header_size_var = proj.loader.main_object.get_symbol('header_size')
    var_dict['header_size_addr'] = header_size_var.rebased_addr
    header_size = state.solver.BVV(value=config['header_size'], size=8 * 8)
    state.memory.store(var_dict['header_size_addr'], header_size, 8, endness='Iend_LE')


    # Set malloc sizes
    malloc_size_var = proj.loader.main_object.get_symbol('malloc_sizes')
    var_dict['malloc_size_addrs'] = [malloc_size_var.rebased_addr + i for i in range(0, malloc_size_var.size, 8)]
    var_dict['malloc_size_bvs'] = []

    if max(config['malloc_sizes']) != 0:
        bvs_size = int(math.ceil(math.log(max(config['malloc_sizes']), 2))) + 1
    else:
        bvs_size = 8
    num_bytes = int(math.ceil(bvs_size / float(state.arch.byte_width)))
    bit_diff = num_bytes * state.arch.byte_width - bvs_size

    for msize in var_dict['malloc_size_addrs']:
        if len(config['malloc_sizes']) > 1:
            malloc_var = state.solver.BVS('malloc_size', bvs_size).zero_extend(bit_diff)
            constraint = claripy.Or(malloc_var == config['malloc_sizes'][0])
            for bin_size in config['malloc_sizes'][1:]:
                constraint = claripy.Or(malloc_var == bin_size, constraint)
            state.add_constraints(constraint)
        else:
            malloc_var = state.solver.BVV(config['malloc_sizes'][0], state.arch.bits)
        var_dict['malloc_size_bvs'].append(malloc_var)
        state.memory.store(msize, claripy.BVV(0, 8 * 8), endness='Iend_LE')  # zero-fill first just in case
        state.memory.store(msize, malloc_var, endness='Iend_LE')

    # Set fill sizes
    fill_size_var = proj.loader.main_object.get_symbol('fill_sizes')
    var_dict['fill_size_addrs'] = [fill_size_var.rebased_addr + i for i in range(0, fill_size_var.size, 8)]
    var_dict['fill_size_vars'] = []
    if config['chunk_fill_size'] == 'zero':
        var_dict['fill_size_vars'] = [state.solver.BVV(0, 8 * 8)] * len(var_dict['fill_size_addrs'])
    if config['chunk_fill_size'] == 'header_size':
        var_dict['fill_size_vars'] = [header_size] * len(var_dict['fill_size_addrs'])
    if config['chunk_fill_size'] == 'chunk_size':
        var_dict['fill_size_vars'] = var_dict['malloc_size_bvs']
    if type(config['chunk_fill_size']) in (int, int):
        var_dict['fill_size_vars'] = [claripy.BVV(config['chunk_fill_size'], 8 * 8)] * len(var_dict['fill_size_addrs'])

    for fsize, fill_var in zip(var_dict['fill_size_addrs'], var_dict['fill_size_vars']):
        state.memory.store(fsize, claripy.BVV(0, 8 * 8), endness='Iend_LE')  # zero-fill first just in case
        state.memory.store(fsize, fill_var, endness='Iend_LE')

    # Set overflow sizes
    overflow_size_var = proj.loader.main_object.get_symbol('overflow_sizes')
    overflow_size_offset = overflow_size_var.rebased_addr
    var_dict['overflow_sizes_addrs'] = [overflow_size_offset + i for i in range(0, overflow_size_var.size, 8)]

    if max(config['overflow_sizes']) != 0:
        bvs_size = int(math.ceil(math.log(max(config['overflow_sizes']), 2))) + 1
    else:
        bvs_size = 8
    num_bytes = int(math.ceil(bvs_size / float(state.arch.byte_width)))
    bit_diff = num_bytes * state.arch.byte_width - bvs_size

    var_dict['overflow_sizes'] = []
    for overflow_size_addr in var_dict['overflow_sizes_addrs']:
        if len(config['overflow_sizes']) > 1:
            overflow_var = state.solver.BVS('overflow_size', bvs_size).zero_extend(bit_diff)
            constraint = claripy.Or(overflow_var == config['overflow_sizes'][0])
            for bin_size in config['overflow_sizes'][1:]:
                constraint = claripy.Or(overflow_var == bin_size, constraint)
            state.add_constraints(constraint)
        else:
            overflow_var = state.solver.BVV(config['overflow_sizes'][0], state.arch.bits)
        var_dict['overflow_sizes'].append(overflow_var)

        state.memory.store(overflow_size_addr, overflow_var, endness='Iend_LE')

    # Get arb_write_offsets
    var_dict['arb_offset_vars'] = []
    arb_write_var = proj.loader.main_object.get_symbol('arw_offsets')
    for i in range(0, arb_write_var.size, 8):
        var_dict['arb_offset_vars'].append(arb_write_var.rebased_addr + i)

    # Get bf_offsets
    var_dict['bf_offset_vars'] = []
    bf_var = proj.loader.main_object.get_symbol('bf_offsets')
    for i in range(0, bf_var.size, 8):
        var_dict['bf_offset_vars'].append(bf_var.rebased_addr + i)

    # get winning addr
    var_dict['winning_addr'] = proj.loader.main_object.get_symbol('winning').rebased_addr

    return var_dict


'''
Main trace function
'''


def trace(config_name, binary_name):
    # Get config
    config = parse_config(config_name)

    # Set logging
    logger.info('Searching for vulns')
    logging.basicConfig()
    # TODO: disable in production
    angr.manager.l.setLevel(config['log_level'])
    angr.exploration_techniques.spiller.l.setLevel(config['log_level'])
    cle.loader.l.setLevel(config['log_level'])
    logger.setLevel(config['log_level'])

    # Get libc path
    libc_path = os.path.expanduser(config['libc'])
    libc_name = os.path.basename(libc_path)
    # Get allocator path
    allocator_path = os.path.expanduser(config['allocator'])
    if allocator_path == 'default':
        allocator_path = libc_path

    allocator_name = os.path.basename(allocator_path)

    # Create project and disable sim_procedures for the libc
    proj = angr.Project(binary_name, exclude_sim_procedures_func=use_sim_procedure,
                        load_options={'ld_path':[os.path.dirname(allocator_path), os.path.dirname(libc_path)],
                                              'auto_load_libs':True})

    # Find write_target
    write_target_var = proj.loader.main_object.get_symbol('write_target')

    # Get libc
    libc = proj.loader.shared_objects[libc_name]

    # Get allocator
    allocator = proj.loader.shared_objects[allocator_name]

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

    if config['use_vsa']:
        added_options.add(angr.options.APPROXIMATE_SATISFIABILITY)  # vsa for satisfiability
        added_options.add(angr.options.APPROXIMATE_GUARDS)          # vsa for guards
        added_options.add(angr.options.APPROXIMATE_MEMORY_SIZES)    # vsa for mem_sizes
        added_options.add(angr.options.APPROXIMATE_MEMORY_INDICES)  # vsa for mem_indices

    removed_options = set()
    removed_options.add(angr.options.LAZY_SOLVES)

    # set heap location right after bss
    bss = proj.loader.main_object.sections_map['.bss']
    heap_base = ((bss.vaddr + bss.memsize) & ~0xfff) + 0x1000
    heap_size = 64 * 4096
    new_brk = claripy.BVV(heap_base + heap_size, proj.arch.bits)


    state = proj.factory.entry_state(add_options=added_options, remove_options=removed_options)
    # heap = SimHeapBrk(heap_base=heap_base, heap_size=heap_size)
    #state.register_plugin('heap', heap)
    state.register_plugin('heaphopper', HeapConditionTracker(config=config,
                                                       wtarget=(write_target_var.rebased_addr,
                                                                write_target_var.size),
                                                       libc=libc, allocator=allocator))

    # state.posix.set_brk(new_brk) # now handled in the heap plugin
    state.posix.brk = heap_base + heap_size
    state.heap.heap_base = heap_base
    state.heap.mmap_base = heap_base + 2*heap_size
    state.heaphopper.set_level(config['log_level'])

    if config['fix_loader_problem']:
        loader_name = os.path.basename(config['loader'])
        libc_version = re.findall(r'libc-([\d\.]+)', libc_path)[0]
        fix_loader_problem(proj, state, loader_name, libc_version)

    var_dict = setup_state(state, proj, config)

    # Set memory concretization strategies
    state.memory.read_strategies = [
        angr.concretization_strategies.SimConcretizationStrategySolutions(16),
        angr.concretization_strategies.SimConcretizationStrategyControlledData(4096,
                                                                                                             var_dict[
                                                                                                                 'global_vars']),
        angr.concretization_strategies.SimConcretizationStrategyEval(4096)]
    state.memory.write_strategies = [
        angr.concretization_strategies.SimConcretizationStrategySolutions(16),
        angr.concretization_strategies.SimConcretizationStrategyControlledData(4096,
                                                                                                             var_dict[
                                                                                                                 'global_vars']),
        angr.concretization_strategies.SimConcretizationStrategyEval(4096)]

    # Hook malloc and free
    malloc_addr = allocator.get_symbol('malloc').rebased_addr
    free_addr = allocator.get_symbol('free').rebased_addr
    malloc_plt = proj.loader.main_object.plt.get('malloc')
    free_plt = proj.loader.main_object.plt.get('free')
    proj.hook(addr=malloc_plt,
              hook=MallocInspect(malloc_addr=malloc_addr, vulns=config['vulns'], ctrl_data=var_dict['allocs']))
    proj.hook(addr=free_plt,
              hook=FreeInspect(free_addr=free_addr, vulns=config['vulns'], sym_data=var_dict['sdata_addrs']))

    found_paths = []

    # Configure simgr
    #sm = proj.factory.simgr(thing=state, immutable=False)
    sm = proj.factory.simgr(thing=state)

    sm.use_technique(VulnChecker(config['mem_corruption_fd'], config['input_pre_constraint'], config['input_values'],
                                 config['stop_found'], config['filter_fake_frees']))

    if config['use_mem_limiter']:
        sm.use_technique(MemLimiter(config['mem_limit'], config['drop_errored']))
    if config['use_dfs']:
        sm.use_technique(angr.exploration_techniques.DFS())
    if config['use_veritesting']:
        sm.use_technique(angr.exploration_techniques.Veritesting())
    if config['use_concretizer']:
        concr_addrs = var_dict['malloc_size_addrs'] + var_dict['allocs']
        sm.use_technique(Concretizer(concr_addrs))
    if config['spiller']:
        if config['dfs']:
            src_stash = 'deferred'
        else:
            src_stash = 'active'
        spill_conf = config['spiller_conf']
        ana_setup()
        spiller = angr.exploration_techniques.Spiller(
            src_stash=src_stash, min=spill_conf['min'], max=spill_conf['max'],
            staging_min=spill_conf['staging_min'], staging_max=spill_conf['staging_max'],
            priority_key=priority_key
        )
        sm.use_technique(spiller)

    avoids = (libc.get_symbol('abort').rebased_addr,)
    sm.use_technique(angr.exploration_techniques.Explorer(find=(var_dict['winning_addr'],), avoid=avoids))

    # Create fd for memory corruption input
    name = b'memory_corruption'
    path = b'/tmp/%s' % name
    mem_corr_fd = config['mem_corruption_fd']
    # backing = SimSymbolicMemory(memory_id='file_%s' % name)
    # backing.set_state(state)
    f = SimFile(name, writable=False)
    f.set_state(state)
    state.fs.insert(path, f)
    real_fd = state.posix.open(path, flags=Flags.O_RDONLY, preferred_fd=mem_corr_fd)
    if mem_corr_fd != real_fd:
        raise Exception("Overflow fd already exists.")
    #state.posix.fd[mem_corr_fd] = f
    #state.posix.fs[name] = f

    # constrain input
    if config['input_pre_constraint']:
        if 'overflow' in config['zoo_actions']:
            overflow_bytes = config['zoo_actions']['overflow'] * max(config['overflow_sizes'])
        else:
            overflow_bytes = 0

        if 'uaf' in config['zoo_actions']:
            uaf_bytes = config['zoo_actions']['uaf'] * config['header_size']
        else:
            uaf_bytes = 0

        if 'arb_relative_write' in config['zoo_actions']:
            arw_bytes = config['zoo_actions']['arb_relative'] * state.arch.byte_width * 2
        else:
            arw_bytes = 0

        num_bytes = overflow_bytes + uaf_bytes + arw_bytes
        input_bytes = state.posix.fd[mem_corr_fd].read_data(num_bytes)[0].chop(8)
        state.posix.fd[mem_corr_fd].seek(0)
        constrain_input(state, input_bytes, config['input_values'])

    # Manual inspection loop
    debug = False
    stop = False
    while len(sm.active) > 0 and not stop:
        if debug:
            debug = False

        sm.step()

        if heardEnter():
            debug = True

    sm.move(from_stash='found', to_stash='vuln', filter_func=lambda p: p.heaphopper.vulnerable)
    found_paths.extend(sm.vuln)

    if config['spiller']:
        ana_teardown()

    for path in found_paths:
        win_addr, heap_func = get_win_addr(proj, path.history.bbl_addrs.hardcopy)
        path.heaphopper.win_addr = win_addr
        last_line = get_last_line(win_addr, binary_name)
        path.heaphopper.last_line = last_line
        if path.heaphopper.arb_write_info:
            path.heaphopper.arb_write_info['instr'] = proj.loader.shared_objects[
                allocator_name].addr_to_offset(
                path.heaphopper.arb_write_info['instr'])
    logger.info('Found {} vulns'.format(len(found_paths)))

    if len(found_paths) > 0:
        arb_writes = store_results(config['num_results'], binary_name, found_paths, var_dict,
                                   config['mem_corruption_fd'])
        if config['store_desc']:
            store_vuln_descs(binary_name, found_paths, var_dict, arb_writes)
    return 0


def store_vuln_descs(desc_file, states, var_dict, arb_writes):
    global DESC_HEADER, DESC_SECTION_LINE
    logger.info('Creating vuln descriptions: {}-desc.yaml'.format(desc_file))
    with open('{}.desc'.format(desc_file.split('.')[0]), 'r') as f:
        bin_info = yaml.load(f, Loader=yaml.SafeLoader)
    '''
    bin_info['allocs'] -> list of (dst_symbol, size_symbol)
    bin_info['frees'] -> list of (dst_symbol)
    bin_info['reads'] -> list of (dst_symbol, size_symbol)
    bin_info['overflows'] -> list of (src_symbol, dst_symbol, size_symbol)
    bin_info['fake_frees'] -> list of fake_chunk_ptrs
    bin_info['double_frees'] -> list of double_frees
    bin_info['arb_relative_writes'] -> list of arb_relative_writes
    bin_info['single_bitflips'] -> list of single_bitflips
    bin_info['uafs'] -> list of use-after_frees
    '''
    descs = []
    for state_num, state in enumerate(states):
        desc = []
        desc.append('{} {}'.format(DESC_HEADER, desc_file))
        desc.append('CONSTRAINTS:')
        desc.append(DESC_SECTION_LINE)
        desc.append('\t- {} allocations:'.format(len(bin_info['allocs'])))
        # show mallocs:
        for msize, minfo in zip(var_dict['malloc_size_addrs'], bin_info['allocs']):
            size_val = state.solver.eval(state.memory.load(msize, 8, endness='Iend_LE'))
            desc.append('\t\t* {} byte allocation to {}'.format(size_val, minfo[0]))
        # show frees
        desc.append('\t- {} frees:'.format(len(bin_info['frees'])))
        for free in bin_info['frees']:
            desc.append('\t\t* free of {}'.format(free))
        # show overflows
        desc.append('\t- {} overflows:'.format(len(bin_info['overflows'])))
        for of, of_size in zip(bin_info['overflows'], var_dict['overflow_sizes_addrs']):
            size_val = state.solver.min(state.memory.load(of_size, 8, endness='Iend_LE'))
            desc.append('\t\t* {} byte overflow from {} into {}'.format(size_val, of[0], of[1]))
        # show bad frees
        desc.append('\t- {} bad_frees:'.format(len(bin_info['fake_frees'])))
        for fake_free in bin_info['fake_frees']:
            desc.append('\t\t* free of fake_chunk {}'.format(fake_free))
        if state.heaphopper.double_free:
            desc.append('\t- {} double free(s)'.format(len(state.heaphopper.double_free)))
        # show arbitrary relative writes
        desc.append('\t- {} arb_relative_writes:'.format(len(bin_info['arb_relative_writes'])))
        for dst, offset in bin_info['arb_relative_writes']:
            desc.append('\t\t* arbitrary relative write to {} at offset {}'.format(dst, offset))
        # show single bitflips
        desc.append('\t- {} single_bitflips:'.format(len(bin_info['single_bitflips'])))
        for dst, offset, bit in bin_info['single_bitflips']:
            desc.append('\t\t* single bitflip to {} at offset {} on bit {}'.format(dst, offset, bit))
        # show single bitflips
        desc.append('\t- {} uafs:'.format(len(bin_info['uafs'])))
        for dst, size in bin_info['uafs']:
            desc.append('\t\t* use-after-free of {} with size of {}'.format(dst, size))
        # check controlled_data
        desc.append('\t- controlled_data:')
        stdin_bytes = all_bytes(state.posix.fd[0].read_storage)
        if stdin_bytes:
            stdin_bytes = [b[0] for b in stdin_bytes]
            stdin = stdin_bytes[0]
            for b in stdin_bytes[1:]:
                stdin = stdin.concat(b)
        constraint_vars = [list(c.variables) for c in state.solver.constraints]
        i = 0
        for read, fill_size in zip(bin_info['reads'], var_dict['fill_size_vars']):
            sol = state.solver.min(fill_size)
            for j in range(0, sol, 8):
                i += j
                # We should never end up here if stdin doesn't exist
                curr_input = stdin.reversed[i + 7:i]
                input_vars = list(curr_input.variables)
                for input_var in input_vars:
                    if input_var in constraint_vars:
                        desc.append('\t\t* 8 byte of controlled data in the heap @ {}+{}'.format(read[0], i))

        desc.append('\t- symbolic_data:')
        for sdata in var_dict['sdata_addrs']:
            mem = state.memory.load(sdata, 8, endness='Iend_LE')
            mem_vars = list(mem.variables)
            for mem_var in mem_vars:
                if mem_var in constraint_vars:
                    desc.append('\t\t* 8 byte of symbolic data in the bss @ {}'.format(sdata))

        desc.append('\n\nRESULT:')
        desc.append(DESC_SECTION_LINE)
        if state.heaphopper.vuln_type == 'malloc_non_heap':
            desc.append('\t- malloc returns a pointer to non-heap segment')
        if state.heaphopper.vuln_type == 'malloc_allocated':
            desc.append('\t- malloc returns a pointer to an already allocated heap region')
        if state.heaphopper.stack_trace:
            desc.append('\t- arbitrary write stack_trace:')
            for idx, addr in enumerate(state.heaphopper.stack_trace):
                desc.append('\t\t[{}] {}'.format(idx, hex(addr)))
        if state.heaphopper.vuln_type == 'arbitrary_write_malloc':
            desc.append('\t- arbitrary write in malloc')
            for idx, arb_write in enumerate(arb_writes[state_num]):
                desc.append(
                    '\t\t{0:d}: Instr: 0x{1:x}; TargetAddr: 0x{2:x}; Val: 0x{3:x}'.format(idx,
                                                                                          arb_write['instr'] & 0xffffff,
                                                                                          arb_write['addr'],
                                                                                          arb_write['val']))
        if state.heaphopper.vuln_type == 'arbitrary_write_free':
            desc.append('\t- arbitrary write in free:')
            for idx, arb_write in enumerate(arb_writes[state_num]):
                desc.append(
                    '\t\t{0:d}: Instr: 0x{1:x}; TargetAddr: 0x{2:x}; Val: 0x{3:x}'.format(idx,
                                                                                          arb_write['instr'] & 0xffffff,
                                                                                          arb_write['addr'],
                                                                                          arb_write['val']))
        descs.append('\n'.join(desc))

    desc_dict = {'file': desc_file, 'text': descs}
    with open("{}-desc.yaml".format(desc_file), 'w') as f:
        yaml.dump(desc_dict, f)


# Store results as yaml-file
def store_results(num_results, bin_file, states, var_dict, fd):
    logger.info('Storing result infos to: {}-result.yaml'.format(bin_file))
    results = []
    arbitrary_writes = []
    for i, state in enumerate(states):
        result = dict()
        result['file'] = bin_file
        result['path_id'] = i
        result['input_opts'] = []
        result['stdin_opts'] = []
        result['symbolic_data'] = []
        result['malloc_sizes'] = []
        result['fill_sizes'] = []
        result['header_sizes'] = []
        result['overflow_sizes'] = []
        result['write_targets'] = []
        result['mem2chunk_offset'] = state.solver.eval(state.memory.load(var_dict['mem2chunk_addr'], 8,
                                                                                   endness='Iend_LE'))
        result['stack_trace'] = state.heaphopper.stack_trace
        result['last_line'] = state.heaphopper.last_line
        result['heap_base'] = state.heap.heap_base
        result['allocs'] = []
        result['arb_write_offsets'] = []
        result['bf_offsets'] = []
        result['vuln_type'] = state.heaphopper.vuln_type

        arbitrary_write = []

        processed_state = process_state(num_results, state, state.heaphopper.vuln_state, var_dict, fd)

        for input_opt, stdin_opt, svars, header, msizes, fsizes, osizes, wtargets, allocs, arb_offsets, bf_offsets, arb_write in processed_state:
            result['input_opts'].append(input_opt)
            result['stdin_opts'].append(stdin_opt)
            result['symbolic_data'].append(svars)
            result['header_sizes'].append(header)
            result['malloc_sizes'].append(msizes)
            result['fill_sizes'].append(fsizes)
            result['overflow_sizes'].append(osizes)
            result['write_targets'].append(wtargets)
            result['allocs'].append(allocs)
            result['arb_write_offsets'].append(arb_offsets)
            result['bf_offsets'].append(bf_offsets)
            arbitrary_write.append(arb_write)
        results.append(result)
        arbitrary_writes.append(arbitrary_write)

    with open("{}-result.yaml".format(bin_file), 'w') as f:
        yaml.dump(results, f)

    return arbitrary_writes
