from binaryninja import *
from .basecc import *

def start_basecc(bv: BinaryView):
    be = BaseccEnumerate(bv)
    be.start()

def start_libc_basecc(bv: BinaryView):
    le = LibcEnumerate(bv)
    le.start()


PluginCommand.register(
    "basecc \\ Enumerate syscalls",
    "Enumerate syscalls for use with basecc tool",
    start_basecc
)

PluginCommand.register(
    "basecc \\ Analyze libc",
    "Enumerate syscalls used in each libc function",
    start_libc_basecc
)
