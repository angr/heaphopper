from os import path, mkdir
from math import ceil, log
from copy import deepcopy
from json import dump

import sys

import re

from os.path import basename, dirname, abspath

from ..utils.parse_config import parse_config


def includes():
    return '\n'.join([
        '#include <malloc.h>',
        '#include <stdint.h>',
        '#include <stdio.h>',
        '#include <stdlib.h>',
        '#include <string.h>',
        '#include <unistd.h>\n'
        '#include <mcheck.h>'
    ])


def ctrled_struct():
    return '\n'.join([
        'typedef struct __attribute__((__packed__)) {',
        '\tuint64_t * global_var;',
        '} controlled_data;\n'
    ])


def sym_struct(size):
    return '\n'.join([
        'typedef struct __attribute__((__packed__)) {',
        '\tuint8_t data[{}];'.format(size),
        '} symbolic_data;\n'
    ])


def winning():
    return '\n'.join([
        'void winning(void) {',
        '\tputs("You win!");',
        '}\n'
    ])


def header_size():
    return '\n'.join([
        'size_t header_size;'
    ])


def mem2chunk_offset():
    return '\n'.join([
        'size_t mem2chunk_offset;'
    ])


def write_target(wtarget_size):
    return '\n'.join([
        'size_t write_target[{}];'.format(wtarget_size)
    ])


def offset():
    return '\n'.join([
        'size_t offset;'
    ])


def malloc_sizes(count):
    return '\n'.join([
        'size_t malloc_sizes[{}];'.format(count)
    ])


def fill_sizes(count):
    return '\n'.join([
        'size_t fill_sizes[{}];'.format(count)
    ])


def overflow_sizes(count):
    return '\n'.join([
        'size_t overflow_sizes[{}];'.format(count)
    ])


def bitflip_offsets(count):
    return '\n'.join([
        'size_t bf_offsets[{}];'.format(count)
    ])


def arb_write_offsets(count):
    return '\n'.join([
        'size_t arw_offsets[{}];'.format(count)
    ])


def ctrled_data(count):
    cdata = []
    for i in range(count):
        cdata.append('controlled_data __attribute__((aligned(16))) ctrl_data_{};'.format(i))

    return '\n'.join(cdata)


def symbolic_data(has_fake_free):
    data = ''
    if has_fake_free:
        data = '\n'.join([
            'symbolic_data __attribute__((aligned(16))) sym_data;'
        ])
    return data


# bin_info['allocs'] -> list of (dst_symbol, size_symbol)
def malloc(num):
    fill_code, fill_desc = fill_chunk(num)
    code = '\n'.join([
        '\t// Allocation',
        '\tctrl_data_{}.global_var = malloc(malloc_sizes[{}]);'.format(num, num),
        fill_code
    ])
    desc = {'allocs': [('ctrl_data_{}.global_var'.format(num), 'malloc_sizes[{}]'.format(num))]}
    desc.update(fill_desc)
    return code, desc


# bin_info['reads'] -> list of (dst_symbol, size_symbol)
def fill_chunk(num):
    code = '\n'.join([
        '\tfor (int i=0; i < fill_sizes[{}]; i+=8) {{'.format(num),
        '\t\tread(0, ((uint8_t *)ctrl_data_{}.global_var)+i, 8);'.format(num),
        '\t}\n'
    ])
    desc = {'reads': [('ctrl_data_{}.global_var'.format(num), 'fill_sizes[{}]'.format(num))]}
    return code, desc


# bin_info['frees'] -> list of (dst_symbol)
def free(num):
    code = '\n'.join([
        '\t// Free',
        '\tfree(ctrl_data_{}.global_var);\n'.format(num)
    ])
    desc = {'frees': ['ctrl_data_{}.global_var'.format(num)]}
    return code, desc


# bin_info['overflows'] -> list of (src_symbol, dst_symbol, size_symbol)
def overflow(num, overflow_num):
    code = '\n'.join([
        '\t// VULN: Overflow',
        # '\toffset = malloc_usable_size(ctrl_data_{}.global_var)-0x8;'.format(num),
        '\toffset = mem2chunk_offset;',
        '\tread({}, ((char *) ctrl_data_{}.global_var)-offset, overflow_sizes[{}]);\n'.format(FD, num + 1, overflow_num)
    ])
    desc = {'overflows': [('ctrl_data_{}.global_var'.format(num),
                           'ctrl_data_{}.global_var'.format(num + 1),
                           'overflow_sizes[{}]'.format(overflow_num))]}
    return code, desc


# bin_info['uafs'] -> list of (src_symbol, size_symbol)
def uaf(num):
    code = '\n'.join([
        '\t// VULN: UAF',
        '\tread({}, ctrl_data_{}.global_var, header_size);\n'.format(FD, num, num)
    ])
    desc = {'uaf': [('ctrl_data_{}.global_var'.format(num), 'header_size')]}
    return code, desc


# bin_info['fake_free'] -> list of fake_chunk_ptrs
def fake_free():
    code = '\n'.join([
        '\t// VULN: Free fake chunk',
        '\tfree(((uint8_t *) &sym_data.data) + mem2chunk_offset);\n'
    ])
    desc = {'fake_frees': ['sym_data.data']}
    return code, desc


def arb_relative_write(num, count):
    code = '\n'.join([
        '\t// VULN: Arbitrary relative write',
        '\tarw_offsets[{}] = 0;'.format(count),
        '\tread(0, &arw_offsets[{}], sizeof(arw_offsets[{}]));'.format(count, count),
        '\tarw_offsets[{}] = arw_offsets[{}] % malloc_sizes[{}];'.format(count, count, num),
        '\tread({}, ctrl_data_{}.global_var+arw_offsets[{}],'
        ' sizeof(arw_offsets[{}]));\n'.format(FD, num, count, count)
    ])
    desc = {'arb_relative_write': [('ctrl_data_{}.global_var'.format(num), 'arw_offsets[{}]'.format(count))]}
    return code, desc


def single_bitflip(num, count):
    code = '\n'.join([
        '\t// VULN: Single bitflip',
        '\tbf_offsets[{}] = 0;'.format(count),
        '\tread(0, &bf_offsets[{}], sizeof(bf_offsets[{}]));'.format(count, count),
        '\tuint8_t bit_{};'.format(count),
        '\tread(0, &bit_{}, sizeof(bit_{}));'.format(count, count),
        '\tbit_{} = bit_{} % 64;'.format(count, count),
        '\t*(ctrl_data_{}.global_var+bf_offsets[{}]) ='
        ' *(ctrl_data_{}.global_var+bf_offsets[{}]) ^ (1 << bit_{});'.format(num, count, num, count, count)
    ])
    desc = {'single_bitflip': [('ctrl_data_{}.global_var'.format(num), 'bf_offsets[{}]'.format(count),
                                'bit_{}'.format(count))]}
    return code, desc


def double_free(num):
    code = '\n'.join([
        '\t// VULN: Double free',
        '\tfree(ctrl_data_{}.global_var);'.format(num)
    ])
    desc = {'double_free': [('ctrl_data_{}.global_var'.format(num),)]}
    return code, desc


def main_start():
    return '\n'.join([
        '\nint main(void) {\n',
    ])


def main_end():
    return '\n'.join([
        '\twinning();',
        '\treturn 0;',
        '}'
    ])


def heap_setup():
    return '\n'.join([
        '\tvoid *dummy_chunk = malloc(0x200);',
        '\tfree(dummy_chunk);'
    ])


def mcheck():
    return '\n'.join([
        '\tmcheck(NULL);'  # call mcheck for malloc hardening
    ])


def mcheck_pedantic():
    return '\n'.join([
        '\tmcheck_pedantic(NULL);'  # call mcheck for malloc hardening
    ])


# Zoo generation
ACTIONS = [('malloc', malloc), ('free', free), ('overflow', overflow), ('fake_free', fake_free),
           ('arb_relative_write', arb_relative_write), ('single_bitflip', single_bitflip), ('double_free', double_free),
           ('uaf', uaf)]

FD = None


# oh boy this is dirty
def build_actions(zoo_actions, depth):
    global ACTIONS
    ACTIONS = [a for a in ACTIONS if a[0] in list(zoo_actions.keys())]
    action_counts = {}
    final_actions = []
    for action in ACTIONS:
        action_counts[action[0]] = 0
        count = zoo_actions[action[0]]
        if count == -1:
            action += (depth,)
        else:
            action += (count,)
        final_actions.append(action)
    ACTIONS = final_actions
    return action_counts


def gen_variants(config, action_counts):
    global FD
    FD = config['mem_corruption_fd']
    variants = []
    descs = []
    v = []
    d = {'allocs': [], 'frees': [], 'reads': [], 'overflows': [], 'uafs': [], 'fake_frees': [],
         'arb_relative_writes': [],
         'single_bitflips': [], 'double_frees': []}
    vuln_states = {'overflow_cnt': 0, 'pend_overf': [], 'uaf': [], 'freed_fake': [], 'arb_write_cnt': 0,
                   'bitflip_cnt': 0}
    total_count = add_variants(v, d, variants, descs, config['zoo_depth'], [], [], vuln_states,
                               action_counts)  # depth is 0-based
    print("Depth: {}".format(config['zoo_depth']))
    print("Total number of permutations: {}".format(total_count))
    return variants, descs


variant = 0


def add_variants(v, d, variants, descs, depth, chunks, frees, vuln_states, action_counts):
    global variant
    total_count = 0
    if depth == 1:
        for name, action, count in ACTIONS:
            if name == 'malloc':
                if vuln_states['overflow_cnt'] == 0 and vuln_states['arb_write_cnt'] == 0 \
                        and vuln_states['bitflip_cnt'] == 0 and not vuln_states['freed_fake'] \
                        and len(frees) == len(set(frees)) and len(vuln_states['uaf']) == 0:  # no need to trace benign
                    continue
                code, desc = action(len(d['allocs']))
                new_d = deepcopy(d)
                new_d['allocs'].extend(desc['allocs'])
                new_d['reads'].extend(desc['reads'])
                new_v = list(v)
                new_v.append(code)
                new_chunks = list(chunks)
                new_chunks.append(len(chunks))
                variants.append((new_v, len(new_chunks), vuln_states))
                descs.append(new_d)
                variant += 1
                total_count += 1
            elif name == 'free':
                for chunk in chunks:
                    code, desc = action(chunk)
                    new_d = deepcopy(d)
                    new_d['frees'].extend(desc['frees'])
                    new_v = list(v)
                    new_v.append(code)
                    if vuln_states['overflow_cnt'] == 0 and vuln_states['arb_write_cnt'] == 0 \
                            and vuln_states['bitflip_cnt'] == 0 and not vuln_states['freed_fake'] \
                            and len(frees) == len(set(frees)):  # no need to trace benign
                        continue
                    variants.append((new_v, len(chunks), vuln_states))
                    descs.append(new_d)
                    variant += 1
                    total_count += 1
            elif name == 'overflow':
                continue
            elif name == 'uaf':
                continue
            elif name == 'fake_free':
                continue
            elif name == 'arb_relative_write':
                continue
            elif name == 'single_bitflip':
                continue
            elif name == 'double_free':
                continue
        return total_count

    for name, action, count in ACTIONS:
        if name == 'malloc':
            if action_counts[name] >= count:
                continue
            code, desc = action(len(d['allocs']))
            new_d = deepcopy(d)
            new_d['allocs'].extend(desc['allocs'])
            new_d['reads'].extend(desc['reads'])
            new_v = list(v)
            new_v.append(code)
            new_chunks = list(chunks)
            new_chunks.append(len(chunks))
            new_vuln_states = deepcopy(vuln_states)
            new_vuln_states['pend_overf'] = []
            new_action_counts = dict(action_counts)
            new_action_counts[name] += 1
            total_count += add_variants(new_v, new_d, variants, descs, depth - 1, new_chunks, frees,
                                        new_vuln_states, new_action_counts)
        elif name == 'free':
            if action_counts[name] >= count:
                continue
            for chunk in chunks:
                if chunk in frees:
                    continue
                code, desc = action(chunk)
                new_d = deepcopy(d)
                new_d['frees'].extend(desc['frees'])
                new_v = list(v)
                new_v.append(code)
                new_frees = list(frees)
                new_frees.append(chunk)
                new_vuln_states = deepcopy(vuln_states)
                new_vuln_states['pend_overf'] = []
                new_action_counts = dict(action_counts)
                new_action_counts[name] += 1
                total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, new_frees,
                                            new_vuln_states, new_action_counts)
        elif name == 'overflow':
            if action_counts[name] >= count:
                continue
            for chunk in chunks[:-1]:  # don't overflow from last
                if chunk in vuln_states['pend_overf']:  # don't overflow a chunk twice without actions in between
                    continue
                code, desc = action(chunk, vuln_states['overflow_cnt'])
                vuln_states['overflow_cnt'] += 1
                new_d = deepcopy(d)
                new_d['overflows'].extend(desc['overflows'])
                new_v = list(v)
                new_v.append(code)
                new_vuln_states = deepcopy(vuln_states)
                new_vuln_states['pend_overf'].append(chunk)
                new_action_counts = dict(action_counts)
                new_action_counts[name] += 1
                total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, frees,
                                            new_vuln_states, new_action_counts)
        elif name == 'uaf':
            if action_counts[name] >= count:
                continue
            for chunk in frees:
                if chunk in vuln_states['uaf']:  # don't uaf a chunk twice without actions in between
                    continue
                code, desc = action(chunk)
                new_d = deepcopy(d)
                new_d['uafs'].extend(desc['uaf'])
                new_v = list(v)
                new_v.append(code)
                new_vuln_states = deepcopy(vuln_states)
                new_vuln_states['uaf'].append(chunk)
                new_action_counts = dict(action_counts)
                new_action_counts[name] += 1
                total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, frees,
                                            new_vuln_states, new_action_counts)
        elif name == 'fake_free':
            if action_counts[name] >= count:
                continue
            if vuln_states['freed_fake']:  # only free one fake chunk
                continue
            code, desc = action()
            new_d = deepcopy(d)
            new_d['fake_frees'].extend(desc['fake_frees'])
            new_v = list(v)
            new_v.append(code)
            new_vuln_states = deepcopy(vuln_states)
            new_vuln_states['freed_fake'] = True
            new_action_counts = dict(action_counts)
            new_action_counts[name] += 1
            total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, frees,
                                        new_vuln_states, new_action_counts)
        elif name == 'arb_relative_write':
            if action_counts[name] >= count:
                continue
            for chunk in chunks[:-1]:  # don't write into the last
                code, desc = action(chunk, vuln_states['arb_write_cnt'])
                new_d = deepcopy(d)
                new_d['arb_relative_writes'].extend(desc['arb_relative_write'])
                new_v = list(v)
                new_v.append(code)
                new_vuln_states = deepcopy(vuln_states)
                new_vuln_states['arb_write_cnt'] += 1
                new_action_counts = dict(action_counts)
                new_action_counts[name] += 1
                total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, frees,
                                            new_vuln_states, new_action_counts)

        elif name == 'single_bitflip':
            if action_counts[name] >= count:
                continue
            for chunk in chunks[:-1]:  # don't write into the last
                code, desc = action(chunk, vuln_states['bitflip_cnt'])
                new_d = deepcopy(d)
                new_d['single_bitflips'].extend(desc['single_bitflip'])
                new_v = list(v)
                new_v.append(code)
                new_vuln_states = deepcopy(vuln_states)
                new_vuln_states['bitflip_cnt'] += 1
                new_action_counts = dict(action_counts)
                new_action_counts[name] += 1
                total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, frees,
                                            new_vuln_states, new_action_counts)

        elif name == 'double_free':
            if action_counts[name] >= count:
                continue
            for chunk in frees:
                code, desc = action(chunk)
                new_d = deepcopy(d)
                new_d['double_frees'].extend(desc['double_free'])
                new_v = list(v)
                new_v.append(code)
                new_frees = list(frees)
                new_frees.append(chunk)
                new_action_counts = dict(action_counts)
                new_action_counts[name] += 1
                total_count += add_variants(new_v, new_d, variants, descs, depth - 1, chunks, new_frees,
                                            vuln_states, new_action_counts)

    return total_count


def write_files(config, variants):
    fnames = []

    if not len(variants):
        return fnames

    id_len = int(ceil(log(len(variants), 10)))

    if not path.isdir(config['zoo_dir']):
        mkdir(config['zoo_dir'])

    for i, v in enumerate(variants):
        file_name = "{}".format(str(i).rjust(id_len, '0'))
        with open('{}/{}.c'.format(config['zoo_dir'], file_name), 'w') as f:
            content = '\n'.join([
                includes(),
                ctrled_struct(),
                sym_struct(config['sym_data_size']),
                winning(),
                write_target(config['wtarget_size']),
                offset(),
                header_size(),
                mem2chunk_offset(),
                malloc_sizes(v[1]),
                fill_sizes(v[1]),
                overflow_sizes(v[2]['overflow_cnt']),
                arb_write_offsets(v[2]['arb_write_cnt']),
                bitflip_offsets(v[2]['bitflip_cnt']),
                ctrled_data(v[1]),
                symbolic_data(v[2]['freed_fake']),
                main_start(),
            ])

            if config['mcheck'] == 'enable':
                content += '\n'.join([mcheck()])
            elif config['mcheck'] == 'pedantic':
                content += '\n'.join([mcheck_pedantic()])

            content += '\n'.join([
                heap_setup(),
                '\n'.join(v[0]),
                main_end()
            ])
            f.write(content)
        fnames.append(file_name)
    return fnames


def create_makefile(zoo_dir, fnames, allocator, libc):
    alloc_name = re.search('lib([\w]+).so', basename(allocator)).group(1)
    libc_name = re.search('lib([\w]+).so', basename(libc)).group(1)
    alloc_path = abspath(allocator)
    libc_path = abspath(libc)

    with open('{}/Makefile'.format(zoo_dir), 'w') as f:
        f.write('CC = gcc\n')
        f.write('CFLAGS += -std=c99 -g -O0\n')
        f.write('LDFLAGS += -no-pie\n')
        f.write('SOURCES = $(wildcard *.c)\n')
        f.write('OBJECTS = $(SOURCES:.c=.o)\n')
        f.write('BINARIES = {}\n'.format(' '.join(fnames)))
        f.write('DIRNAME = bin\n\n')
        f.write('.PHONY: all clean distclean gendir cpy_file\n\n')
        f.write('all: gendir $(BINARIES) cpy_file\n\n')
        f.write('clean:\n\trm $(OBJECTS)\n\n')
        f.write('distclean: clean\n\trm -r $(DIRNAME)\n\n')
        f.write('gendir:\n\tmkdir -p $(DIRNAME)\n\n')
        f.write('cpy_file:\n\tfor desc in *.desc; do cp $$desc bin/; done\n\n')
        f.write('%.o: %.c\n\t$(CC) $(CFLAGS) -c -o $@ $^\n\n')
        for file_name in fnames:
            f.write('{}: {}.o\n\t$(CC) -L{} -L{} -o "$(DIRNAME)/$@.bin" $^ $(LDFLAGS) -l{} -l{}\n\n'.format(file_name,
                                                                                                            file_name,
                                                                                                            dirname(
                                                                                                                alloc_path),
                                                                                                            dirname(
                                                                                                                libc_path),
                                                                                                            alloc_name,
                                                                                                            libc_name))


def create_descriptions(zoo_dir, descs, fnames):
    for desc, fname in zip(descs, fnames):
        with open('{}/{}.desc'.format(zoo_dir, fname), 'w') as f:
            dump(desc, f)


def usage(argv):
    print('Usage: {} <zoo_dir> <depth>'.format(argv[0]))


def gen_zoo(config_file):
    global ACTIONS
    config = parse_config(config_file)
    action_count = build_actions(config['zoo_actions'], config['zoo_depth'])
    variants, descs = gen_variants(config, action_count)
    print('Variants: {}'.format(len(variants)))
    if not config['create_files'] or not len(variants):
        return -1
    fnames = write_files(config, variants)
    create_makefile(config['zoo_dir'], fnames, config['allocator'], config['libc'])
    create_descriptions(config['zoo_dir'], descs, fnames)
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 1:
        usage(sys.argv)
        sys.exit(1)
    gen_zoo(sys.argv[1])
