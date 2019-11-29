#!/usr/bin/env python
import logging

import IPython
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
from ..heap_plugins import GlibcPlugin

logger = logging.getLogger('heap-tracer')

# global vars
DESC_HEADER = 'Vuln description for binary'
DESC_SECTION_LINE = '=========================================='
MALLOC_LIST = []


'''
Exploration helper functions
'''


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
Main trace function
'''


def trace(config_name, binary_name):
    # Get config
    config = parse_config(config_name)

    # Set logging
    logger.info('Searching for vulns')
    logging.basicConfig()

    angr.manager.l.setLevel(config['log_level'])
    angr.exploration_techniques.spiller.l.setLevel(config['log_level'])
    cle.loader.l.setLevel(config['log_level'])
    logger.setLevel(config['log_level'])

    # get heap plugin
    heap_plugin_name = config['heap_plugin']
    if heap_plugin_name == GlibcPlugin.name():
         heap_plugin = GlibcPlugin(binary_name, config)
    else:
        raise Exception("Hook {0} not implemented".format(heap_plugin_name))
    heap_plugin.setup_project()
    heap_plugin.setup_state()
    heap_plugin.hook()

    found_paths = []

    # Configure simgr
    #sm = proj.factory.simgr(thing=state, immutable=False)
    sm = heap_plugin.proj.factory.simgr(thing=heap_plugin.state)

    sm.use_technique(VulnChecker(config['mem_corruption_fd'], config['input_pre_constraint'], config['input_values'],
                                 config['stop_found'], config['filter_fake_frees']))

    if config['use_mem_limiter']:
        sm.use_technique(MemLimiter(config['mem_limit'], config['drop_errored']))
    if config['use_dfs']:
        sm.use_technique(angr.exploration_techniques.DFS())
    if config['use_veritesting']:
        sm.use_technique(angr.exploration_techniques.Veritesting())
    if config['use_concretizer']:
        concr_addrs = heap_plugin.var_dict['malloc_size_addrs'] + heap_plugin.var_dict['allocs']
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

    sm.use_technique(angr.exploration_techniques.Explorer(find=heap_plugin.finds, avoid=heap_plugin.avoids))

    # Create fd for memory corruption input
    name = b'memory_corruption'
    path = b'/tmp/%s' % name
    mem_corr_fd = config['mem_corruption_fd']
    # backing = SimSymbolicMemory(memory_id='file_%s' % name)
    # backing.set_state(state)
    f = SimFile(name, writable=False)
    f.set_state(heap_plugin.state)
    heap_plugin.state.fs.insert(path, f)
    real_fd = heap_plugin.state.posix.open(path, flags=Flags.O_RDONLY, preferred_fd=mem_corr_fd)
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
            arw_bytes = config['zoo_actions']['arb_relative'] * heap_plugin.state.arch.byte_width * 2
        else:
            arw_bytes = 0

        num_bytes = overflow_bytes + uaf_bytes + arw_bytes
        input_bytes = heap_plugin.state.posix.fd[mem_corr_fd].read_data(num_bytes)[0].chop(8)
        heap_plugin.state.posix.fd[mem_corr_fd].seek(0)
        constrain_input(heap_plugin.state, input_bytes, config['input_values'])

    # Manual inspection loop
    debug = False
    stop = False
    while len(sm.active) > 0 and not stop:
        if debug:
            debug = False
            IPython.embed()

        sm.step()

        if heardEnter():
            debug = True

    sm.move(from_stash='found', to_stash='vuln', filter_func=lambda p: p.heaphopper.vulnerable)
    found_paths.extend(sm.vuln)

    if config['spiller']:
        ana_teardown()

    for path in found_paths:
        win_addr, heap_func = get_win_addr(heap_plugin.proj, path.history.bbl_addrs.hardcopy)
        path.heaphopper.win_addr = win_addr
        last_line = get_last_line(win_addr, binary_name)
        path.heaphopper.last_line = last_line
        if path.heaphopper.arb_write_info:
            path.heaphopper.arb_write_info['instr'] = heap_plugin.proj.loader.shared_objects[
                heap_plugin.allocator_name].addr_to_offset(
                path.heaphopper.arb_write_info['instr'])
    logger.info('Found {} vulns'.format(len(found_paths)))

    if len(found_paths) > 0:
        arb_writes = store_results(heap_plugin, config['num_results'], binary_name, found_paths,
                                   config['mem_corruption_fd'])
        if config['store_desc']:
            store_vuln_descs(binary_name, found_paths, heap_plugin.var_dict, arb_writes)
    # IPython.embed()
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
            # IPython.embed()
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
def store_results(heap_plugin, num_results, bin_file, states, fd):
    logger.info('Storing result infos to: {}-result.yaml'.format(bin_file))
    results = []
    arbitrary_writes = []
    for i, state in enumerate(states):
        result = heap_plugin.process_state(num_results, state, state.heaphopper.vuln_state, fd)
        result['path_id'] = i
        results.append(result)
        arbitrary_writes.append(result['arb_writes'])

    with open("{}-result.yaml".format(bin_file), 'w') as f:
        yaml.dump(results, f)

    return arbitrary_writes
