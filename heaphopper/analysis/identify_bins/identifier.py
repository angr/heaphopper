import angr
import logging
import hashlib
import re
import subprocess
import os

from ..heap_condition_tracker import HeapConditionTracker
from ..mem_limiter import MemLimiter
from ...utils.angr_tools import heardEnter
from ...utils.parse_config import parse_config

logger = logging.getLogger('bin-identifier')


def use_sim_procedure(name):
    if name in ['puts', 'printf']:
        return False
    else:
        return True


def identify(config_file):
    config = parse_config(config_file)
    logger.setLevel(config['log_level'])
    logger.info('Identifying libc...')

    libc_path = os.path.expanduser(config['libc'])
    libc_name = os.path.basename(libc_path)
    libc_hash = hashlib.md5(open(libc_name, 'rb').read()).hexdigest()
    logger.debug('md5(libc) == {}'.format(libc_hash))

    bins_file = '{}.bin_sizes'.format(libc_hash)
    if not os.path.isfile(bins_file):
        bins = identify_bins(config)
        with open(bins_file, 'w') as f:
            for cbin in bins:
                f.write('{} - {}\n'.format(cbin[0], cbin[1]))
    else:
        bins = []
        with open(bins_file, 'r') as f:
            for line in f.read().split("\n"):
                if not line:
                    continue
                start, end = re.findall(r'(\d*) - (\d*)', line)[0]
                bins.append((int(start, 10), int(end, 10)))

    logger.info('Found {} bins'.format(len(bins)))
    return bins


def identify_bins(config):
    logger.info('Identifying bins...')
    # build identify bin
    subprocess.Popen(["make", "-C", "./heaphopper/analysis/identify_bins"], stdout=subprocess.PIPE)

    libc_path = config['libc']

    # Create project and disable sim_procedures for the libc
    proj = angr.Project('./heaphopper/analysis/identify_bins/identify',
                        auto_load_libs=True,
                        exclude_sim_procedures_func=use_sim_procedure,
                        custom_ld_path=[os.path.dirname(libc_path)])

    # Create state and enable reverse memory map
    added_options = set()
    added_options.add(angr.options.REVERSE_MEMORY_NAME_MAP)
    added_options.add(angr.options.TRACK_MEMORY_ACTIONS)
    added_options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
    added_options.add(angr.options.STRICT_PAGE_ACCESS)
    state = proj.factory.full_init_state(add_options=added_options, remove_options=angr.options.simplification)
    state.register_plugin('heap', HeapConditionTracker())
    # fix_loader_problem(proj, state)

    malloc_sizes = proj.loader.main_object.get_symbol('malloc_sizes')

    states = []
    for i in range(8, 0x1008, 8):
        s = state.copy()
        malloc_size = state.solver.BVV(i, 8 * 8)
        s.memory.store(malloc_sizes.rebased_addr, malloc_size, 8, endness='Iend_LE')

        states.append(s)

    sm = proj.factory.simgr(thing=states, immutable=False)
    sm.use_technique(MemLimiter(config['mem_limit'], config['drop_errored']))

    debug = False
    stop = False
    while len(sm.active) > 0 and not stop:
        if debug:
            debug = False

        sm.step()
        print(sm)

        if heardEnter():
            debug = True

    unique_paths = dict()
    for found in sm.deadended:
        trace = tuple(found.rebased_addr_trace.hardcopy)
        curr = found.state.solver.any_int(found.state.memory.load(malloc_sizes.rebased_addr, 8, endness='Iend_LE'))
        if trace in list(unique_paths.keys()):
            min_size, max_size = unique_paths[trace]
            if curr < min_size:
                min_size = curr
            if curr > max_size:
                max_size = curr
            unique_paths[trace] = (min_size, max_size)
        else:
            unique_paths[trace] = (curr, curr)

    sorted_bins = sorted(list(unique_paths.values()), key=lambda tup: tup[0])
    for i, curr_bin in enumerate(sorted_bins):
        logger.debug('Bin[{}]: min={} max={}'.format(i, hex(curr_bin[0]), hex(curr_bin[1])))
    return sorted_bins
