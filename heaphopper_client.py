#!/usr/bin/env python

import sys
import argparse
from heaphopper.analysis.tracer.tracer import trace
from heaphopper.analysis.identify_bins.identifier import identify
from heaphopper.gen.gen_zoo import gen_zoo
from heaphopper.gen.gen_pocs import gen_pocs


def run_identifier(config):
    ret = identify(config)
    sys.exit(ret)


def run_tracer(config, binary):
    ret = trace(config, binary)
    sys.exit(ret)


def run_zoo_gen(config):
    ret = gen_zoo(config)
    sys.exit(ret)

def run_poc_gen(config, binary, result, desc, source):
    gen_pocs(config, binary, result, desc, source)
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find heap corruptions')
    parser.add_argument('action', metavar='<identify|gen|trace|poc>', type=str,
                        choices=['identify', 'trace', 'gen', 'poc'],
                        help='Identify bins or trace for vulns')
    parser.add_argument('-c', '--config', metavar='analysis.yaml', type=open,
                        help='Path to config file in yaml-format')
    parser.add_argument('-b', '--binary', metavar='binary_path', type=str,
                        help='Path to the binary to be traced')
    parser.add_argument('-r', '--result', metavar='result.yaml', type=str,
                        help='Path to the result.yaml file for poc gen')
    parser.add_argument('-d', '--desc', metavar='desc.yaml', type=str,
                        help='Path to the desc.yaml file for poc gen')
    parser.add_argument('-s', '--source', metavar='source.c', type=str,
                        help='Path to the source file for poc gen')

    args = parser.parse_args()

    if args.action == 'trace':
        if args.config is None or args.binary is None:
            parser.error('trace requires --config and --binary')
        run_tracer(args.config, args.binary)
    elif args.action == 'gen':
        if args.config is None :
            parser.error('gen requires --config')
        run_zoo_gen(args.config)
    elif args.action == 'poc':
        if args.config is None or args.binary is None or args.result is None or args.desc is None or args.source is None:
            parser.error('poc requires --config, --binary, --result, --desc and --source')
        run_poc_gen(args.config, args.binary, args.result, args.desc, args.source)
    else:
        if args.config is None:
            parser.error('identify requires --config')
        run_identifier(args.config)
