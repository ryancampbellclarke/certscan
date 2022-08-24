# from pyopenssl
import sys
import getopt
from cloudUpload import CloudUpload


class Options:
    local_export: bool = False
    cloud_upload: bool = False


def process_options(args):
    options = Options()
    print(args)
# https://docs.python.org/3/library/getopt.html


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    process_options(sys.argv)
    # TODO: Read flags:
    #   -local:
    CloudUpload.cloud_license_key_valid()
