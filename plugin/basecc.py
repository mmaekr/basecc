from binaryninja import *
from shutil import which
import json
import os
import tempfile

class BaseccEnumerate(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Enumerating syscalls...", True)
        self.bv = bv
        self.syscalls = []
        self.path = user_directory() + os.sep + 'basecc'
        self.libc_cache = self._load_libc_cache()

    def run(self):
        for func in self.bv.functions:
            # If the function is imported, check if we have the library analyzed
            if func.symbol.type == SymbolType.ImportedFunctionSymbol:
                if func.name in self.libc_cache:
                    self.syscalls.extend(self.libc_cache[func.name])

            for i in func.mlil.instructions:
                if i.operation == MediumLevelILOperation.MLIL_SYSCALL:
                    sc_param = i.params[0]

                    # The syscall number is defined as a constant
                    if isinstance(sc_param, MediumLevelILConst):
                        sc_num = sc_param.constant
                        if sc_num is not None:
                            self.syscalls.append(sc_num)

                    # The syscall number is defined as a MLIL var
                    # this is likely from an argument being treated as the number
                    # just ignore these for now
                    elif isinstance(sc_param, MediumLevelILVar):
                        print(hex(i.address))

        if self._check_compile_support():
            default_so_name = f"basecc-\
{os.path.basename(os.path.normpath(self.bv.file.original_filename))}.so"
            so_path = get_save_filename_input("Save shared object", "so", default_so_name)
            if so_path:
                self.gen_seccomp_so(so_path)
                print(f"[+] Wrote {so_path}")
                print(self.syscalls)

        else:
            # Cannot compile shared object, just give system calls
            print(self.syscalls)


    def _check_compile_support(self):
        self.gcc = which("gcc")
        if not self.gcc:
            return False
        return True


    def gen_seccomp_so(self, so_path):
        rules = ""
        for sc in self.syscalls:
            rules += f"\tret |= seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, {str(sc)}, 0);\n"
        so_code = f"""
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

void __attribute__((constructor)) basecc_initialize() {{
\tint ret = 0;
    fputs("Sandboxed by basecc\\n", stderr);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);

{rules}
    ret |= seccomp_load(ctx);

    if (ret != 0) {{
        fprintf(stderr, "error: %d\\n", ret);
    }}

    seccomp_release(ctx);
}}
"""
        fd, sourcename = tempfile.mkstemp(suffix=".c", dir="/tmp")
        with os.fdopen(fd, 'w') as f:
            f.write(so_code)

        os.system(f"gcc -lseccomp -fPIC -shared {sourcename} -o {so_path}")
        os.system(f"rm {sourcename}")


    def _get_mlil_var_value(self, func_ssa, param):
        ssa_def = func_ssa.get_ssa_var_definition(param.src)


    def _load_libc_cache(self):
        cache_file = self.path + os.sep + "libc.so.6.json"
        f = open(cache_file)
        return json.load(f)



class LibcEnumerate(BackgroundTaskThread):
    # objdump -T /usr/lib/libc.so.6
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Enumerating library syscalls...", True)
        self.bv = bv
        self.objdump = None
        self.path = user_directory() + os.sep + 'basecc'
        self.func_syscalls = {}

    def run(self):
        if not self.check_symbol_support():
            print("Error, cannot find exported functions")
            return

        self._check_basecc_exists()

        e_funcs, e_aliases = self._get_lib_exported_symbols()

        # this is DFS; we can shorten some trees
        for func in self.bv.functions:
            if func.name in e_funcs:
                self.func_syscalls[func.name] = self._rec_find_syscalls(func, [])

        cache_file = os.path.basename(os.path.normpath(self.bv.file.original_filename)) + ".json"

        out = {}
        # TODO figure out aliases, we are getting keyerrors
        for ef in e_funcs:
            if ef in self.func_syscalls:
                # write to alias too if it exists
                if ef in e_aliases:
                    out[ef] = list(self.func_syscalls[e_aliases[ef]])

                out[ef] = list(self.func_syscalls[ef])

        with open(self.path + os.sep + cache_file, 'w') as f:
            f.write(json.dumps(out, indent=2))


    def _rec_find_syscalls(self, func: Function, prev: list):
        found_syscalls = set()

        for callee in func.callees:
            last = found_syscalls.copy()
            # Ignore cycles
            if callee in prev:
                continue

            # Already found syscalls for this function, ignore
            if callee.name in self.func_syscalls:
                found_syscalls.update(self.func_syscalls[callee.name])
            # New function that hasn't been processed yet
            else:
                print(f"searching in {callee.name} @ {hex(callee.start)}")
                self.func_syscalls[callee.name] = self._rec_find_syscalls(callee, prev + [func])
                found_syscalls.update(self.func_syscalls[callee.name])
                if len(found_syscalls) > len(last):
                    print("\t new syscall" + str(found_syscalls.difference(last)))

        found_syscalls.update(self._find_syscalls_in_func(func))
        return found_syscalls


    def _check_basecc_exists(self):
        if not os.path.exists(self.path):
            os.mkdir(self.path)


    def _find_syscalls_in_func(self, func: Function):
        syscalls = set()
        for i in func.mlil.instructions:
            if i.operation == MediumLevelILOperation.MLIL_SYSCALL:
                sc_param = i.params[0]

                # The syscall number is defined as a constant
                if isinstance(sc_param, MediumLevelILConst):
                    sc_num = sc_param.constant
                    if sc_num is not None:
                        syscalls.add(sc_num)
        return syscalls


    def check_symbol_support(self):
        self.objdump = which("objdump")
        if not self.objdump:
            return False
        return True


    def _get_lib_exported_symbols(self):
        fns = set()
        aliases = {}

        # Save the binary to a tempory file
        _, binname = tempfile.mkstemp(dir="/tmp")
        _, outname = tempfile.mkstemp(dir="/tmp")

        # this makes binja flip out
        #self.bv.save(binname)
        binname = "/usr/lib/libc.so.6"

        os.system(f"{self.objdump} -T {binname} > {outname}")

        seen_addr = {}

        with open(outname, 'r') as f:
            lines = f.readlines()[4:]
            for line in lines:
                sline = line.split(" ")
                if ".text" not in line:
                    continue
                fname = sline[-1].strip()
                addr = int(sline[0], 16)

                if addr not in seen_addr:
                    seen_addr[addr] = fname
                else:
                    aliases[fname] = seen_addr[addr]

                fns.add(fname)

        return (fns, aliases)
