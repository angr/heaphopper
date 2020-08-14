#!/usr/bin/env python
import binascii
import re
from hashlib import md5
from math import log, ceil

from os.path import basename, dirname, abspath

import angr
import logging
import yaml
import os
from itertools import takewhile

from ..utils.parse_config import parse_config

logger = logging.getLogger('poc-generator')


def load_yaml(file_name):
    with open(file_name, 'r') as f:
        result = yaml.load(f, Loader=yaml.SafeLoader)
    return result


def gen_dir(exploit_path, file_name, vuln, stack_trace):
    if not os.path.isdir(exploit_path):
        os.mkdir(exploit_path)
    dir_name = "{}/{}".format(exploit_path, vuln)
    if not os.path.isdir(dir_name):
        os.mkdir(dir_name)
    if stack_trace:
        m = md5()
        for addr in stack_trace:
            m.update(str(addr).encode())
        dir_name = "{}/stack_trace_{}".format(dir_name, m.hexdigest())
        if not os.path.isdir(dir_name):
            os.mkdir(dir_name)
    dir_name = "{}/{}".format(dir_name, os.path.basename(file_name))
    if not os.path.isdir(dir_name):
        os.mkdir(dir_name)
    return dir_name


def check_addr(addr, next_part, prev_part, main_bin, heap_base, allocs, sym, sym_off):
    shift = 0
    masks = {0: 0x00, 1: 0xff, 2: 0xffff, 3: 0xffffff, 4: 0xffffffff, 5: 0xffffffffff, 6: 0xffffffffffff,
             7: 0xffffffffffffff}
    masks_prev = {0: 0xffffffffffffffff, 1: 0xffffffffffffff00, 2: 0xffffffffffff0000, 3: 0xffffffffff000000,
                  4: 0xffffffff00000000,
                  5: 0xffffff0000000000, 6: 0xffff000000000000, 7: 0xff00000000000000}
    while shift < 8:
        actual_addr = ((next_part & masks[shift]) << (shift * 8)) | (addr >> (shift * 8))
        section = main_bin.find_section_containing(actual_addr)
        if not section:
            if 0 <= actual_addr - heap_base < 0x80000:
                offset = actual_addr - allocs[0]
                chunk = (0, offset)
                for idx, alloc in enumerate(allocs):
                    offset = actual_addr - alloc
                    if 0 <= offset < chunk[1]:
                        chunk = (idx, offset)
                if shift > 0:
                    expr = ('((uint64_t) (((char *) ctrl_data_{}.global_var)'
                            ' + {}) << {})'
                            ' | {} | {}').format(chunk[0], hex(chunk[1]), shift * 8,
                                                 hex((addr & masks_prev[prev_part[0]]) &
                                                     masks[
                                                         shift]),
                                                 prev_part[1])
                    next_part = (shift, next_part & masks[shift])
                else:
                    expr = '((char *) ctrl_data_{}.global_var) + {}'.format(chunk[0], hex(chunk[1]))
                    next_part = (0, 0x0)
                return expr, next_part
        elif 'bss' in section.name:
            wtarget = main_bin.get_symbol('write_target')
            offset = actual_addr - wtarget.rebased_addr
            if shift > 0:
                expr = '((uint64_t) (((char *) &write_target) + {}) << {}) | {} | {}'.format(hex(offset), shift * 8,
                                                                                             hex((addr & masks[
                                                                                                 prev_part[0]]) &
                                                                                                 masks_prev[shift]),
                                                                                             prev_part[1])
                next_part = (shift, next_part & masks[shift])
            else:
                expr = '((char *) &write_target) + {}'.format(hex(offset))
                next_part = (0, 0x0)
            return expr, next_part
        shift += 1

    return check_offset(sym, sym_off, addr, main_bin, allocs)


def check_offset(sym, sym_off, addr, main_bin, allocs):
    if addr < 0x40:
        return hex(addr), (0, 0x0)
    #if addr > 0x100000000000000:  # Just in case it can't hurt to point back to us, pointer is arbitrary anyways
    #    return '(uint64_t) &write_target', (0, 0x0)

    if not sym:
        return hex(addr), (0, 0x0)

    if 'ctrl_data' in sym:
        alloc_index = int(re.findall('ctrl_data_(\d+)', sym)[0])
        base = allocs[alloc_index] + sym_off
        sym_prefix = ''
    else:
        symbol = main_bin.get_symbol(sym)
        if not symbol:
            return hex(addr), (0, 0x0)
        base = symbol.rebased_addr + sym_off
        sym_prefix = '&'

    addr_clean = addr & ~0x7
    for s in main_bin.symbols:

        if sym == s.name:
            continue
        if base + addr_clean >= s.rebased_addr and base + addr_clean < s.rebased_addr + s.size:
            if s.name != 'write_target':
                for i in range(0, 0x40, 8):
                    found_sym = main_bin.loader.find_symbol(s.rebased_addr + i)
                    if found_sym and found_sym.name == 'write_target':
                        break

            if not found_sym:
                found_sym = s
            off = base + addr_clean - found_sym.rebased_addr
            expr = '(uint64_t) ((((char *) &{}) - (char *) {}{}) - {}) + {}'.format(found_sym.name, sym_prefix, sym, sym_off, off)
            return expr, (0, 0x0)
        elif base - addr_clean >= s.rebased_addr and base - addr_clean < s.rebased_addr + s.size:
            if s.name != 'write_traget':
                for i in range(0, 0x40, 8):
                    found_sym = main_bin.loader.find_symbol(s.rebased_addr + i)
                    if found_sym and found_sym.name == 'write_target':
                        break

            if not found_sym:
                found_sym = s
            off = base - addr_clean - found_sym.rebased_addr
            expr = '(uint64_t) ((((char *) {}{}) - (char *) &{}) + {}) - {}'.format(sym_prefix, sym, found_sym.name, sym_off, off)
            return expr, (0, 0x0)

    for idx, alloc in enumerate(allocs):
        if base + addr_clean >= alloc and idx < len(allocs) - 1 and base + addr_clean < allocs[idx + 1]:
            off = base + addr_clean - alloc
            expr = '(uint64_t) ((((char *) ctrl_data_{}.global_var) - (char *) {}) - {}) + {}'.format(idx, sym, sym_off,
                                                                                                      off)
            return expr, (0, 0x0)
        elif base - addr_clean >= alloc and idx < len(allocs) - 1 and base - addr_clean < allocs[idx + 1]:
            off = base - addr_clean - alloc
            expr = '(uint64_t) ((((char *) {}) - (char *) ctrl_data_{}.global_var) + {}) - {}'.format(sym, idx, sym_off,
                                                                                                      off)
            return expr, (0, 0x0)

    if 'write_target' in sym:
        if 0x200 < addr < 0x2000:
            addr = addr & 1

    return hex(addr), (0, 0x0)


def get_last_line(last_line, src_file):
    with open(src_file, 'r') as sf:
        content = sf.read().split('\n')[last_line - 1]
        return content


def gen_poc(result, src_file, bin_file, last_line):
    global last_action_size, space
    with open('{}'.format(src_file), 'r') as f:
        lines = f.read().split('\n')

    main_bin = angr.Project(bin_file, auto_load_libs=False).loader.main_object
    heap_base = result['heap_base']
    mem2chunk = result['mem2chunk_offset']
    init_dict = dict()
    pocs = []
    poc_descs = []
    for input_opt, stdin_opt, svars, header, msizes, fsizes, osizes, wtargets, allocs, arw_offsets, bf_offsets in zip(
            result['input_opts'],
            result['stdin_opts'],
            result['symbolic_data'],
            result['header_sizes'],
            result['malloc_sizes'],
            result['fill_sizes'],
            result['overflow_sizes'],
            result['write_targets'],
            result['allocs'],
            result['arb_write_offsets'],
            result['bf_offsets']):

        if type(input_opt) == str:
            input_opt = bytes(input_opt, 'utf-8')

        poc = []
        poc_desc = dict(allocs=0, frees=0, overflows=0, fake_frees=0, double_frees=0, arb_relative_writes=0,
                        single_bitflips=0, uafs=0, constrained_target=False)
        free_list = []
        iter_lines = iter(lines[:last_line])
        for line in iter_lines:
            last_action_size = 0
            space = ''.join(takewhile(str.isspace, line))
            if 'free(dummy_chunk)' in line:
                poc.append(line)
                poc.append('\t# if print\n\t\tprintf("Init printf: %p\\n", dummy_chunk);\n\t# endif\n')
                last_action_size += 2
            elif 'free(ctrl_data' in line:
                poc.append(line)
                dst = list(map(int, re.findall('ctrl_data_(\d+).global_var', line)))[0]
                if dst in free_list:
                    poc_desc['double_frees'] += 1
                else:
                    free_list.append(dst)
                    poc_desc['frees'] += 1
                poc.append(
                    '{}#if print\n{}\tprintf("Free: %p\\n", ctrl_data_{}.global_var);\n{}#endif\n'.format(space,
                                                                                                          space,
                                                                                                          dst,
                                                                                                          space))
                last_action_size += 2
            elif line.strip().startswith('//'):  # comment
                poc.append(line)
                last_action_size += 1
            elif ' = malloc(malloc_sizes' in line:  # allocation
                last_action_size += 2
                poc_desc['allocs'] += 1
                dst, msize_index = list(map(int, re.findall('ctrl_data_(\d+).global_var = malloc\(malloc_sizes\[(\d+)\]\);',
                                                       line)[0]))
                poc.append(line)
                poc.append(
                    ('{}#if print\n{}\tprintf("Allocation: %p\\nSize: 0x%lx\\n",'
                     'ctrl_data_{}.global_var, malloc_sizes[{}]);\n{}#endif\n').format(
                        space,
                        space,
                        dst,
                        msize_index,
                        space))
                try:
                    for_line = next(iter_lines)  # get for
                    next(iter_lines)  # get read
                    next(iter_lines)  # get curly brace
                except StopIteration:
                    continue
                if not len(stdin_opt):
                    continue
                fsize_index = int(re.findall('fill_sizes\[(\d+)\]', for_line)[0])
                prev_part = (0, 0x0)
                for i in range(0, fsizes[fsize_index], 8):
                    val = b'0x' + binascii.hexlify(stdin_opt[:8][::-1])
                    stdin_opt = stdin_opt[8:]
                    if len(stdin_opt) >= 8:
                        next_part = int(b'0x' + binascii.hexlify(stdin_opt[:8][::-1]), 16)
                    else:
                        next_part = 0x0
                    sym_offset, prev_part = check_addr(int(val, 16), next_part, prev_part, main_bin, heap_base, allocs,
                                                       'ctrl_data_{}.global_var'.format(dst), i)
                    curr_dst = 'ctrl_data_{}.global_var[{}]'.format(dst, (i // 8))
                    instr = '{}{} = (uint64_t) {};'.format(space, curr_dst, sym_offset)
                    if 'ctrl_data' in sym_offset:
                        idx = int(re.findall(r'ctrl_data_(\d+)', sym_offset)[0])
                        if idx > dst:
                            key = 'ctrl_data_{}'.format(idx)
                            if key not in init_dict:
                                init_dict[key] = []
                            init_dict[key].append(instr)
                            continue

                    poc.append(instr)
                    last_action_size += 1
                key = 'ctrl_data_{}'.format(dst)
                if key in init_dict:
                    poc.append('\n')
                    last_action_size += 1
                    for instr in init_dict[key]:
                        poc.append(instr)
                        last_action_size += 1
            elif 'read' in line and 'header_size);' in line:
                # UAF
                poc_desc['uafs'] += 1
                dst = re.findall(r'read\(.*, (ctrl_data_\d+.global_var),', line)[0]
                dst_idx = re.findall(r'ctrl_data_(\d+).global_var', dst)[0]
                for i in range(0, header, 8):
                    val = b'0x' + binascii.hexlify(input_opt[:8][::-1])
                    input_opt = input_opt[8:]
                    sym_offset, prev_part = check_addr(int(val, 16), 0x0, (0, 0x0), main_bin, heap_base, allocs,
                                                       'ctrl_data_{}.global_var'.format(dst_idx), i)
                    poc.append('{}{}[{}] = {};'.format(space, dst, i // 8, sym_offset))
                    last_action_size += 1
            elif 'read(0, &arw_offsets' in line:
                # arbitrary relative write
                poc_desc['arb_relative_writes'] += 1
                offset_dst = re.findall(r'read\(0, &(arw_offsets\[\d+\]),', line)[0]
                val = b'0x' + binascii.hexlify(stdin_opt[:8][::-1])
                stdin_opt = stdin_opt[8:]
                sym_offset, prev_part = check_addr(int(val, 16), 0x0, (0, 0x0), main_bin, heap_base, allocs,
                                                   'arw_offsets', (poc_desc['arb_relative_writes'] - 1) * 8)
                poc.append('{}{} = {};'.format(space, offset_dst, sym_offset))
                last_action_size += 1

                line = next(iter_lines)  # get second read
                read_dst = re.findall(r'read\(.*, (.*), .*\)', line)[0]
                read_base, read_offset = read_dst.split('+')
                val = b'0x' + binascii.hexlify(input_opt[:8][::-1])
                input_opt = input_opt[8:]
                sym_offset, prev_part = check_addr(int(val, 16), 0x0, (0, 0x0), main_bin, heap_base, allocs, None, 0)
                poc.append('{}{}[{}] = (uint64_t) {};'.format(space, read_base, read_offset, sym_offset))
                last_action_size += 1
            elif 'read(0, &bf_offsets' in line:
                # single bitflip
                poc_desc['single_bitflips'] += 1
                offset_dst = re.findall(r'read\(0, &(bf_offsets\[\d+\]),', line)[0]
                val = b'0x' + binascii.hexlify(stdin_opt[:8][::-1])
                stdin_opt = stdin_opt[8:]
                sym_offset, prev_part = check_addr(int(val, 16), 0x0, (0, 0x0), main_bin, heap_base, allocs,
                                                   'bf_offsets', (poc_desc['single_bitflips'] - 1) * 8)
                poc.append('{}{} = {};'.format(space, offset_dst, sym_offset))
                last_action_size += 1

                line = next(iter_lines)  # get second read
                bit_dst = re.findall(r'read\(0, (bit_\d+), .*\)', line)[0]
                val = b'0x' + binascii.hexlify(stdin_opt[:1])
                stdin_opt = stdin_opt[1:]
                sym_offset, prev_part = check_addr(int(val, 16), 0x0, (0, 0x0), main_bin, heap_base, allocs, None, 0)
                poc.append('{}{} = {};'.format(space, bit_dst, sym_offset))
                last_action_size += 1
            elif 'read(' in line:
                # Overflow
                if not len(input_opt):
                    continue
                poc_desc['overflows'] += 1
                dst, size = re.findall(r'read\(.*, (.*), ([A-Za-z0-9\[\]_\-]*)\)', line)[0]
                ctrl_data_index = re.findall(r'ctrl_data_(\d+)', dst)[0]
                index = int(re.findall(r'\[(\d*)\]', size)[0], 10)

                new_size = osizes[index]
                prev_part = (0, 0x0)
                for i in range(0, new_size, 8):
                    if new_size - i < 8:
                        break
                    val = b'0x' + binascii.hexlify(input_opt[:8][::-1])
                    input_opt = input_opt[8:]
                    if len(input_opt) >= 8:
                        next_part = int(b'0x' + binascii.hexlify(input_opt[:8][::-1]), 16)
                    else:
                        next_part = 0x0
                    sym_offset, prev_part = check_addr(int(val, 16), next_part, prev_part, main_bin, heap_base, allocs,
                                                       'ctrl_data_{}.global_var'.format(ctrl_data_index), -mem2chunk)
                    curr_dst = '((uint64_t*) ({}))[{}]'.format(dst, (i // 8))
                    poc.append('{}{} = (uint64_t) {};'.format(space, curr_dst, sym_offset))
                    last_action_size += 1

                    # remainder
                    if new_size - (i + 8) < 8 and new_size - (i + 8) > 0:
                        val = b'0x' + binascii.hexlify(input_opt[:new_size - (i + 8)][::-1])
                        bits = 2 ** int(ceil(log((len(val) - 2) * 4, 2)))
                        input_opt = input_opt[new_size - (i + 8):]
                        sym_offset, prev_part = check_addr(int(val, 16), 0x0, prev_part, main_bin, heap_base, allocs,
                                                           'ctrl_data_{}.global_var'.format(ctrl_data_index), i + 8)
                        curr_dst = '((uint{}_t*) ({}+{}))[0]'.format(bits, dst, hex(i + 8))
                        poc.append('{}{} = (uint{}_t) {};'.format(space, curr_dst, bits, sym_offset))
                        last_action_size += 1


            elif line.startswith('controlled_data '):
                # we need go get rid of the trailing L
                poc.append(line)
                last_action_size += 1

            elif 'size_t malloc_sizes' in line:
                vals = []
                prev_part = (0, 0x0)
                for idx, var in enumerate(msizes):
                    if idx < len(msizes) - 1:
                        next_part = msizes[idx + 1]
                    else:
                        next_part = 0x0
                    sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs, None, 0)
                    # Get rit of the trailing Ls
                    if sym_offset[:-1] == 'L':
                        sym_offset = sym_offset[:-1]
                    vals.append(sym_offset)
                init = ' = {{ {} }};'.format(', '.join(vals))
                poc.append(line[:-1] + init)
                last_action_size += 1
            elif 'size_t fill_sizes' in line:
                vals = []
                prev_part = (0, 0x0)
                for idx, var in enumerate(fsizes):
                    if idx < len(fsizes) - 1:
                        next_part = fsizes[idx + 1]
                    else:
                        next_part = 0x0
                    sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs, None, 0)
                    # Get rit of the trailing Ls
                    if sym_offset[:-1] == 'L':
                        sym_offset = sym_offset[:-1]
                    vals.append(sym_offset)
                init = ' = {{ {} }};'.format(', '.join(vals))
                poc.append(line[:-1] + init)
                last_action_size += 1
            elif 'size_t overflow_sizes' in line:
                vals = []
                prev_part = (0, 0x0)
                for idx, var in enumerate(osizes):
                    if idx < len(osizes) - 1:
                        next_part = osizes[idx + 1]
                    else:
                        next_part = 0x0
                    sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs, None, 0)
                    # Get rit of the trailing Ls
                    if sym_offset[:-1] == 'L':
                        sym_offset = sym_offset[:-1]
                    vals.append(sym_offset)
                init = ' = {{ {} }};'.format(', '.join(vals))
                poc.append(line[:-1] + init)
                last_action_size += 1
            elif 'size_t header_size' in line:
                init = ' = 0x{:x};'.format(header)
                poc.append(line[:-1] + init)
                last_action_size += 1
            elif 'size_t mem2chunk_offset' in line:
                if result['mem2chunk_offset']:
                    init = ' = 0x{:x};'.format(result['mem2chunk_offset'])
                    poc.append(line[:-1] + init)
                else:
                    poc.append(line)
                last_action_size += 1
            elif 'size_t arw_offsets' in line:
                if not arw_offsets:
                    poc.append(line)
                else:
                    vals = []
                    prev_part = (0, 0x0)
                    for idx, var in enumerate(arw_offsets):
                        if idx < len(arw_offsets) - 1:
                            next_part = arw_offsets[idx + 1]
                        else:
                            next_part = 0x0
                        sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs,
                                                           'arw_offsets', idx * 8)
                        # Get rit of the trailing Ls
                        if sym_offset[:-1] == 'L':
                            sym_offset = sym_offset[:-1]
                        vals.append(sym_offset)
                    init = ' = {{ {} }};'.format(', '.join(vals))
                    poc.append(line[:-1] + init)
                last_action_size += 1
            elif 'size_t bf_offsets' in line:
                if not bf_offsets:
                    poc.append(line)
                else:
                    vals = []
                    prev_part = (0, 0x0)
                    for idx, var in enumerate(bf_offsets):
                        if idx < len(bf_offsets) - 1:
                            next_part = bf_offsets[idx + 1]
                        else:
                            next_part = 0x0
                        sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs,
                                                           'bf_offsets', idx * 8)
                        # Get rit of the trailing Ls
                        if sym_offset[:-1] == 'L':
                            sym_offset = sym_offset[:-1]
                        vals.append(sym_offset)
                    init = ' = {{ {} }};'.format(', '.join(vals))
                    poc.append(line[:-1] + init)
                last_action_size += 1
            elif 'free(((uint8_t *) &sym_data.data) + mem2chunk_offset);' in line:  # fake free
                # fake_free
                poc_desc['fake_frees'] += 1
                prev_part = (0, 0x0)
                for idx, var in enumerate(svars):
                    if idx < len(svars) - 1:
                        next_part = svars[idx + 1]
                    else:
                        next_part = 0x0
                    sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs,
                                                       'sym_data',
                                                       idx * 8)
                    # Get rit of the trailing Ls
                    if sym_offset[-1] == 'L':
                        sym_offset = sym_offset[:-1]
                    poc.append('\t((uint64_t *) sym_data.data)[{}] = (uint64_t) {};'.format(idx, sym_offset))
                    last_action_size += 1
                poc.append(line)
                last_action_size += 1
            else:
                poc.append(line)
                last_action_size += 1

        # setup write_target
        vals = []
        prev_part = (0, 0x0)
        for idx, var in enumerate(wtargets):
            if idx < len(wtargets) - 1:
                next_part = wtargets[idx + 1]
            else:
                next_part = 0x0
            sym_offset, prev_part = check_addr(var, next_part, prev_part, main_bin, heap_base, allocs, 'write_target',
                                               idx * 8)
            # Get rit of the trailing Ls
            if sym_offset[-1] == 'L':
                sym_offset = sym_offset[:-1]

            if not sym_offset == '0x0':
                poc_desc['constrained_target'] = True
            vals.append(sym_offset)
        content = []
        for idx, val in enumerate(vals):
            content.append('\twrite_target[{}] = (uint64_t) {};'.format(idx, val))

        if 0 == last_action_size:
            last_action_size = 1
        poc.insert(-last_action_size, '\n'.join(content))
        poc.insert(-last_action_size, '{}#if print\n{}\tfor (int i = 0; i < 4; i++) {{'.format(space, space))
        poc.insert(-last_action_size,
                   '{}\t\tprintf("write_target[%d]: %p\\n", i, (void *) write_target[i]);'.format(space))
        poc.insert(-last_action_size, '{}\t}}\n{}#endif\n'.format(space, space))
        poc.append('{}#if print\n{}\tfor (int i = 0; i < 4; i++) {{'.format(space, space))
        poc.append('{}\t\tprintf("write_target[%d]: %p\\n", i, (void *) write_target[i]);'.format(space))
        poc.append('{}\t}}\n{}#endif\n'.format(space, space))

        if result['vuln_type'].startswith('bad_allocation'):
            ptr = poc[-2].split(' ')[0].strip()
            poc.append('\t#if print\n\t\tprintf("Overlapping Allocation: %p\\n", {});\n\t#endif\n'.format(ptr))

        # end main
        poc.append('}')
        pocs.append('\n'.join(poc))
        poc_descs.append(poc_desc)

    # poc_desc are equal just return the first one
    return pocs, poc_descs[0]


def create_makefile(poc_dir, fnames, allocator, libc):
    alloc_name = re.search('lib([\w]+).so', basename(allocator)).group(1)
    libc_name = re.search('lib([\w]+).so', basename(libc)).group(1)
    alloc_path = abspath(allocator)
    libc_path = abspath(libc)

    with open('{}/Makefile'.format(poc_dir), 'w') as f:
        f.write('CC = gcc\n')
        f.write('CFLAGS += -std=c99 -g -O0 -w\n')
        f.write('LDFLAGS += -no-pie\n')
        f.write('SOURCES = $(wildcard *.c)\n')
        f.write('OBJECTS = $(SOURCES:.c=.o)\n')
        f.write('BINARIES = {}\n'.format(' '.join(fnames)))
        f.write('DIRNAME = bin\n\n')
        f.write('PRINT = 0\n')
        f.write('.PHONY: all clean distclean gendir\n\n')
        f.write('all: pocs\n\n')
        f.write('clean:\n\trm $(OBJECTS)\n\n')
        f.write('distclean: clean\n\trm -r $(DIRNAME)\n\n')
        f.write('gendir:\n\tmkdir -p $(DIRNAME)\n\n')
        f.write('pocs: gendir $(BINARIES)\n')
        f.write('pocs-print: PRINT = 1\n')
        f.write('pocs-print: gendir $(BINARIES)\n\n')
        for file in fnames:
            f.write(
                '{}: {}.c\n\t$(CC) $(CFLAGS) -Dprint=$(PRINT) -o "$(DIRNAME)/$@.bin" -L{} -L{} $^ $(LDFLAGS) -l{} -l{}\n\n'.format(
                    file, file, dirname(alloc_path), dirname(libc_path), alloc_name, libc_name))


def gen_pocs(config_file, bin_file, res_file, desc_file, src_file):
    config = parse_config(config_file)
    desc_dict = load_yaml(desc_file)
    results = load_yaml(res_file)

    last_lines = []
    for result in results:
        last_lines.append((result['last_line'], get_last_line(result['last_line'], src_file)))

    poc_path = os.path.abspath(os.path.join(os.path.dirname(config_file.name), config['pocs_path']))
    dir_path = gen_dir(poc_path, bin_file, results[0]['vuln_type'], results[0]['stack_trace'])

    logger.info('Found {} vulnerable paths'.format(len(results)))
    poc_descs = []
    fnames = []
    for i, result in enumerate(results):
        pocs, poc_desc = gen_poc(result, src_file, bin_file, last_lines[i][0])
        poc_descs.append(poc_desc)
        logger.info('Generated {} poc(s) out of path {}'.format(len(pocs), i))
        for i, poc in enumerate(pocs):
            fname = 'poc_{}_{}'.format(result['path_id'], i)
            with open('{}/{}.c'.format(dir_path, fname), 'w') as f:
                f.write(poc)
            fnames.append(fname)

    create_makefile(dir_path, fnames, config['allocator'], config['libc'])

    for i, desc in enumerate(desc_dict['text']):
        desc += '\n\t- Line {}: {}'.format(last_lines[i][0], last_lines[i][1].strip(' \t'))
        with open('{}/poc_{}.desc'.format(dir_path, i), 'w') as f:
            f.write(desc)

    for i, poc_desc in enumerate(poc_descs):
        with open('{}/poc_{}.yaml'.format(dir_path, i), 'w') as f:
            yaml.dump(poc_desc, f)
