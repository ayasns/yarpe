from ropchain import Executable
from constants import SELECTED_EXEC, SELECTED_LIBC, SYSCALL
from utils.etc import alloc
from utils.ref import get_ref_addr, refbytearray
from utils.conversion import get_cstring


class Function(Executable):
    def __init__(self, sc, func_addr):
        super(Function, self).__init__(sc)
        self.func_addr = func_addr

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        self.chain.reset()
        self.setup_front_chain()
        self.setup_call_chain(
            self.func_addr, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )
        self.setup_padding_chain()
        self.setup_post_chain()
        self.setup_back_chain()
        return self.execute()


class Syscall(Executable):
    def __init__(self, sc, syscall_number):
        super(Syscall, self).__init__(sc)
        self.syscall_number = syscall_number
        if self.sc.platform == "ps4" and syscall_number not in self.sc.syscall_table:
            raise Exception("Syscall number %d not found" % syscall_number)

    def __call__(self, rdi=0, rsi=0, rdx=0, rcx=0, r8=0, r9=0):
        pipe_on_ps5 = (
            self.syscall_number == SYSCALL["pipe"] and self.sc.platform == "ps5"
        )

        self.chain.reset()
        self.setup_front_chain()
        self.setup_syscall_chain(
            self.syscall_number, rdi=rdi, rsi=rsi, rdx=rdx, rcx=rcx, r8=r8, r9=r9
        )
        self.setup_padding_chain()
        if pipe_on_ps5:
            rdi_addr = get_ref_addr(rdi)
            self.chain.push_store_rax_into_memory(rdi_addr)
            self.chain.push_store_rdx_into_memory(rdi_addr + 4)

        self.setup_post_chain()
        self.setup_back_chain()
        ret = self.execute()

        return ret

    def get_error_string(self):
        errstr_addr = self.sc.functions.strerror(self.errno)
        errstr = get_cstring(self.sc.mem, errstr_addr - 0x1000)
        return errstr


class FunctionContainer(object):
    def __init__(self, sc):
        self.sc = sc
        self.functions = {}

    def __setattr__(self, name, value):
        if name in ("sc", "functions"):
            object.__setattr__(self, name, value)
        else:
            self.functions[name] = value

    def __getattr__(self, name):
        func_name = name
        if func_name not in self.functions:
            if func_name in SELECTED_LIBC:
                func_addr = self.sc.libc_addr + SELECTED_LIBC[func_name]
            elif func_name in SELECTED_EXEC:
                func_addr = self.sc.exec_addr + SELECTED_EXEC[func_name]
            else:
                raise Exception("Function %s not found" % func_name)
            func = Function(self.sc, func_addr)
            self.functions[func_name] = func
        return self.functions[func_name]


class SyscallContainer(object):
    def __init__(self, sc):
        self.sc = sc
        self.syscalls = {}

    def __setattr__(self, name, value):
        if name in ("sc", "syscalls"):
            object.__setattr__(self, name, value)
        else:
            self.syscalls[name] = value

    def __getattr__(self, name):
        syscall_name = name
        if syscall_name not in self.syscalls:
            if syscall_name not in SYSCALL:
                raise Exception("Syscall %s not found" % syscall_name)
            syscall_number = SYSCALL[syscall_name]
            syscall = Syscall(self.sc, syscall_number)
            self.syscalls[syscall_name] = syscall
        return self.syscalls[syscall_name]
