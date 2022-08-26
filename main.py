import argparse
import csv
import os
import sys
from os.path import dirname

from src.helpers import write_list_of_certs_to_file, DEFAULT_FILE_OUT, \
    certscan_direct, certscan_config, certscan_database, get_args
from src.scanner import Scanner
from src import options

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    args = get_args(parser)

    # Check if no args, print help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.database:
        # Use scanners configured in database configured in database.ini file
        certscan_database(args)
    elif args.ini:
        # Use scanners configured in config.ini file
        certscan_config(args)
    else:
        # Use scanner requested from arguments, output to stdout or csv
        certscan_direct(args)



