#!/usr/bin/env python

import os
import re
import time
import datetime
from subprocess import call, check_call, check_output, STDOUT, CalledProcessError
import glob
import sys
import logging
from logging import Formatter, getLogger, StreamHandler


DEVNULL = open(os.devnull, 'wb', 0)

VERBOSE = False

# Logging stuff

class Color(object):
    """
     utility to return ansi colored text.
    """

    colors = {
        'black': 30,
        'red': 31,
        'green': 32,
        'yellow': 33,
        'blue': 34,
        'magenta': 35,
        'cyan': 36,
        'white': 37,
        'bgred': 41,
        'bggrey': 100
    }

    prefix = '\033['

    suffix = '\033[0m'

    def colored(self, text, color=None):
        if color not in self.colors:
            color = 'white'

        clr = self.colors[color]
        return (self.prefix+'%dm%s'+self.suffix) % (clr, text)


colored = Color().colored

class ColoredFormatter(Formatter):

    def format(self, record):

        message = record.getMessage()

        color_mapping = {
            'INFO': 'white',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bgred',
            'DEBUG': 'bggrey',
            'SUCCESS': 'green'
        }

        symbol_mapping = {
            'INFO': '[*]',
            'WARNING': '[-]',
            'ERROR': '[!]',
            'CRITICAL': '[-]',
            'DEBUG': '[*]',
            'SUCCESS': '[+]'
        }
        clr = color_mapping.get(record.levelname, 'white')
        sym = symbol_mapping.get(record.levelname, '[*]')

        return colored(sym, clr) + ' ' + message

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = ColoredFormatter()
handler.setFormatter(formatter)
logger.addHandler(handler)

logging.SUCCESS = 25  # between WARNING and INFO
logging.addLevelName(logging.SUCCESS, 'SUCCESS')
setattr(logger, 'success', lambda message, *args: logger._log(logging.SUCCESS, message, args))

def store_results(results_dict):
    ts = time.time()
    dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H:%M:%S')
    fn = '{}_test.txt'.format(dt)

    total_time = 0
    with open(fn, 'w') as f:
        f.write('Timing results for test run from {}\n\n'.format(dt))
        for dir in results_dict.iterkeys():
            f.write('[{}]{}: {} s\n'.format('OK' if results_dict[dir]['worked'] else 'FAILED', dir,
                                            results_dict[dir]['ts']))
            total_time += results_dict[dir]['ts']
        f.write('total time: {} s\n'.format(total_time))


def run_single(folder_name, analysis_name, binary_name):
    start = time.time()
    if not VERBOSE:
        call(['python', 'src/check_heap.py', 'trace', '-c', 'tests/{}/{}'.format(folder_name, analysis_name),
              '-b', 'tests/{}/{}'.format(folder_name, binary_name)], cwd='../', stdout=DEVNULL, stderr=STDOUT)
    else:
        print check_output(['python', 'src/check_heap.py', 'trace', '-c', 'tests/{}/{}'.format(folder_name, analysis_name),
         '-b', 'tests/{}/{}'.format(folder_name, binary_name)], cwd='../')
    ts = time.time() - start
    return ts


def create_poc_single(folder_name, analysis_name, binary_name, result_name, desc_name, source_name, poc_path):

    if not VERBOSE:
        try:
            check_call(['python', 'src/check_heap.py', 'poc',
                        '-c', 'tests/{}/{}'.format(folder_name, analysis_name),
                        '-b', 'tests/{}/{}'.format(folder_name, binary_name),
                        '-r', 'tests/{}'.format(result_name),
                        '-d', 'tests/{}'.format(desc_name),
                        '-s', 'tests/{}'.format(source_name)], cwd='../', stdout=DEVNULL, stderr=STDOUT)
        except CalledProcessError:
            return False

        poc_path = glob.glob(poc_path)[0]

        try:
            check_call(['make', '-C', poc_path, 'pocs-print'], stdout=DEVNULL, stderr=STDOUT)
        except CalledProcessError:
            return False

    else:
        print check_output(['python', 'src/check_heap.py', 'poc',
                            '-c', 'tests/{}/{}'.format(folder_name, analysis_name),
                            '-b', 'tests/{}/{}'.format(folder_name, binary_name),
                            '-r', 'tests/{}'.format(result_name),
                            '-d', 'tests/{}'.format(desc_name),
                            '-s', 'tests/{}'.format(source_name)], cwd='../')

        poc_path = glob.glob(poc_path)[0]

        print check_output(['make', '-C', poc_path, 'pocs-print'])

    return True

def verify_poc_single(poc_path, poc_type):
    poc_bin = '{}/bin/poc_0_0.bin'.format(poc_path)
    try:
        output = check_output(['./run_poc.sh', poc_bin])
    except CalledProcessError:
        return False
    if VERBOSE:
        print output

    if poc_type == 'malloc_non_heap':
        return verify_non_heap(output)
    elif poc_type == 'malloc_allocated':
        return verify_malloc_allocated(output)
    elif poc_type.startswith('arbitrary_write'):
        return verify_arbitrary_write(output)


def verify_non_heap(output):
    heap_base = int(re.findall("Init printf: ([0-9a-fx]+)", output)[0], 0)
    last_alloc = int(re.findall("Allocation: ([0-9a-fx]+)", output)[-1], 0)
    if last_alloc < heap_base:
        return True
    return False

def verify_malloc_allocated(output):
    allocs = map(lambda f: (int(f[0], 0), int(f[1], 0)), re.findall("Allocation: ([0-9a-fx]+) \nSize: ([0-9a-fx]+)",
                                                                    output))
    for i, a1, s1 in enumerate(allocs):
        for a2, s2 in allocs[i+1:]:
            if a1 == a2:
                return True
            if a1 < a2 < a1 + s1:
                return True
            if a2 < a1 < a2 + s2:
                return True

    return False

def verify_arbitrary_write(output):
    write_target = map(lambda f: (int(f[0], 0), int(f[1], 0)), re.findall("write_target\[([0-9]+)\]: ([0-9a-fx]+)\n",
                                                                          output))

    size = len(write_target) / 2
    pre = dict(write_target[:size])
    post = dict(write_target[size:])
    for x, y in zip(pre, post):
        if x != y:
            return True

    return False


def how2heap_tests(results_dict):
    tests = {'how2heap_fastbin_dup': ['analysis.yaml', 'fastbin_dup.bin', 'malloc_non_heap'],
             'how2heap_house_of_lore': ['analysis.yaml', 'house_of_lore.bin', 'malloc_non_heap'],
             'how2heap_house_of_spirit': ['analysis.yaml', 'house_of_spirit.bin', 'malloc_non_heap'],
             'how2heap_overlapping_chunks': ['analysis.yaml', 'overlapping_chunks.bin', 'malloc_allocated'],
             'how2heap_unsafe_unlink': ['analysis.yaml', 'unsafe_unlink.bin', 'arbitrary_write_free'],
             'how2heap_unsorted_bin_attack': ['analysis.yaml', 'unsorted_bin_attack.bin', 'arbitrary_write_malloc']}
             #'how2heap_house_of_einherjar': ['analysis.yaml', 'house_of_einherjar.bin', 'malloc_non_heap'],
             #'how2heap_poison_null_byte': ['analysis.yaml', 'poison_null_byte.bin', 'malloc_allocated']}

    for i, test in enumerate(tests.iterkeys()):
        result_path = '{}/{}-result.yaml'.format(test, tests[test][1])
        desc_path = '{}/{}-desc.yaml'.format(test, tests[test][1])
        source_path = '{}/{}.c'.format(test, tests[test][1].split('.')[0])
        if test == 'how2heap_unsafe_unlink':
            poc_path = 'pocs/{}/*/{}'.format(tests[test][2], tests[test][1])
        elif test == 'how2heap_unsorted_bin_attack':
            poc_path = 'pocs/{}/*/{}'.format(tests[test][2], tests[test][1])
        else:
            poc_path = 'pocs/{}/{}'.format(tests[test][2], tests[test][1])
        logger.info('[{}/{}] Running: {}'.format(i + 1, len(tests.keys()), test))
        done = os.path.isfile(result_path) or os.path.isfile(desc_path)
        if done:
            logger.warn('Deleting old result/desc-file')
            try:
                os.remove(result_path)
                os.remove(desc_path)
            except:
                pass
        ts = run_single(test, tests[test][0], tests[test][1])
        logger.info('\tDone: {:.3f} seconds'.format(ts))
        worked = os.path.isfile(result_path) and os.path.isfile(desc_path)
        if worked:
            logger.success('\tOk')
            logger.info('Creating PoC')
            worked = create_poc_single(test, tests[test][0], tests[test][1], result_path, desc_path, source_path,
                                       poc_path)
            if not worked:
                logger.error('\tFailed')
            else:
                logger.success('\tOk')
                logger.info('Verifying PoC')
                worked = verify_poc_single(poc_path, tests[test][2])
                if worked:
                    logger.success('\tOk')
        else:
            logger.error('\tFailed')
        results_dict[test] = dict(ts=ts, worked=worked)


def run_tests():
    results_dict = {}
    check_call(['make'], stdout=DEVNULL, stderr=STDOUT)
    how2heap_tests(results_dict)
    store_results(results_dict)

if len(sys.argv) > 1:
    if sys.argv[1] == '-v':
        VERBOSE = True

run_tests()
