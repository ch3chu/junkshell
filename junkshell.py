import base64
import random
import string
import argparse
import sys

from builder import *
from utils import randomStr

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='junkshell - A shellcode loader for Powershell')
    parser.add_argument('-s', '--shellcode', help='Shellcode file to load', required=True)
    # parser.add_argument('-e', '--encoded', help='Encoded powershell command [only using -s]')
    parser.add_argument('-o', '--output', help='Output file', required=True)
    args = parser.parse_args()

    if args.shellcode:
        builder = ShellcodeBuilder(args.shellcode, args.output)
        builder.build()
    else:
        print("[!] You need to specify a shellcode or a pe file")
        sys.exit(0)