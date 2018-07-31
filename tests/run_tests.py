#!/usr/bin/env python

import os
import time
import datetime
from subprocess import call, check_call, check_output, STDOUT, CalledProcessError
import glob
import sys

DEVNULL = open(os.devnull, 'wb', 0)

VERBOSE = False


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


def how2heap_tests(results_dict):
    tests = {'how2heap_fastbin_dup': ['analysis.yaml', 'fastbin_dup.bin', 'malloc_non_heap'],
             #'how2heap_house_of_einherjar': ['analysis.yaml', 'house_of_einherjar.bin', 'malloc_non_heap'],
             'how2heap_house_of_lore': ['analysis.yaml', 'house_of_lore.bin', 'malloc_non_heap'],
             'how2heap_house_of_spirit': ['analysis.yaml', 'house_of_spirit.bin', 'malloc_non_heap'],
             'how2heap_overlapping_chunks': ['analysis.yaml', 'overlapping_chunks.bin', 'malloc_allocated'],
             'how2heap_unsafe_unlink': ['analysis.yaml', 'unsafe_unlink.bin', 'arbitrary_write_free'],
             'how2heap_unsorted_bin_attack': ['analysis.yaml', 'unsorted_bin_attack.bin', 'arbitrary_write_malloc'],
             'how2heap_poison_null_byte': ['analysis.yaml', 'poison_null_byte.bin', 'malloc_allocated']}

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
        print('[{}/{}] Running: {}'.format(i + 1, len(tests.keys()), test))
        done = os.path.isfile(result_path) or os.path.isfile(desc_path)
        if done:
            print('Warning deleting old result/desc-file')
            try:
                os.remove(result_path)
                os.remove(desc_path)
            except:
                pass
        ts = run_single(test, tests[test][0], tests[test][1])
        print('\tDone: {:.3f} seconds'.format(ts))
        worked = os.path.isfile(result_path) and os.path.isfile(desc_path)
        if worked:
            print('\tOk')
            print('Creating POC')
            worked = create_poc_single(test, tests[test][0], tests[test][1], result_path, desc_path, source_path,
                                       poc_path)
            if not worked:
                print('\tFailed')
            else:
                print('\tOk')
        else:
            print('\tFailed')
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
