import argparse
import sys

from src.helpers import certscan_direct, get_args, print_args_help

VERSION="v0.5.0"

if __name__ == '__main__':
    # Setup argument parser
    parser = argparse.ArgumentParser()
    args = get_args(parser)

    # Check if no args, print help
    if len(sys.argv) == 1:
        print_args_help(parser)

    if args.version:
        print(VERSION)
    elif args.scan:
        # Use scanner requested from arguments, output to stdout and/or csv
        certscan_direct(args)
    else:
        # If reached here, something went wrong, print help
        print_args_help(parser)
