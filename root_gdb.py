# Import {{{
import gdb
import gdb.printing
from elftools.elf.elffile import ELFFile
import struct
import re
# }}}
# Global variable {{{
task_struct = {}
arch = gdb.selected_inferior().architecture()
# }}}
# Read from memory {{{
def read_pointer(address):
    void_t = gdb.lookup_type('void').pointer().pointer()
    return address.cast(void_t).dereference()
def read_c_string(address, max_len = 16):
    string = gdb.lookup_type('char').pointer()
    ss = address.cast(string).string('ascii', errors='backslashreplace', length=max_len)
    ss = ss.split('\x00')
    return ss[0]
def read_uint32_t(address):
    uint32_t = gdb.lookup_type('unsigned int').pointer()
    return address.cast(uint32_t).dereference()
def read_uint64_t(address):
    uint64_t = gdb.lookup_type("unsigned long long").pointer()
    return address.cast(uint64_t).dereference()
# }}}
# struct task_struct {{{
read_function = {}
read_function['pointer'] = read_pointer
read_function['long'] = read_uint64_t
read_function['c_string'] = read_c_string
read_function['int'] = read_uint32_t
def build_taskstruct():
    global task_struct
    init_task = gdb.parse_and_eval("$init_task")
    if init_task.type.code == gdb.TYPE_CODE_VOID:
        ad.invoke('init_task',None)        
        init_task = gdb.parse_and_eval("$init_task")
        if init_task.type.code == gdb.TYPE_CODE_VOID:
            print("$init_task symbol not found")
            return gdb.Error     
        if len(task_struct) != 0:
            # Is already built
            return
    # 8K is enough
    mem = gdb.selected_inferior().read_memory(init_task, 8192)
    ## Now, there is a comm field with ASCII. Moreover, the first process is hardcoded as SWAPPER
    for match in re.finditer(b"swapper",mem):
        task_struct['comm'] = [match.start(), "c_string"]
        break
    # The cred fields are before comm
    if arch.name() == 'i386:x86-64':
        ps = 8
    task_struct['cred'] = [task_struct['comm'][0] - ps, "pointer"] #dimension of pointer to that architecture
    task_struct['real_cred'] = [task_struct['cred'][0] - ps, "pointer"] #dimension of pointer to that architecture
    task_struct['ptrace_cred'] = [task_struct['real_cred'][0] - ps, "pointer"] #dimension of pointer to that architecture
    inx = 0
    dd  = ['real_parent' , 'parent', 'group_leader']
    for match in re.finditer(int(init_task).to_bytes(ps, "little"), mem):
        task_struct[dd[inx]] = [match.start(), "pointer"]
        inx+=1
    # Now, that we have parent and real_parent fields we can obtain PID and TID datas 
    task_struct['stack_canary'] = [task_struct['real_parent'][0] - ps, "long"]  
    task_struct['tgid'] = [task_struct['stack_canary'][0] - 4, "int"]  
    task_struct['pid'] = [task_struct['tgid'][0] - 4, "int"]  
    ## Now, search for tasks field. We use the previous obtained offset
    task_struct['tasks'] = {}
    index = 0;
    while index < 8192:
        test_addr = int.from_bytes(bytes(mem[index : index+ps]), 'little')
        index+=ps
        # we can skip if it is not a pointer to a memory area. Also, this can't be found it he kernel segment
        if test_addr < 0xffff000000000000 or test_addr > 0xffffffff00000000:
            continue
        try:
            # Like container_of macro
            next_task = gdb.selected_inferior().read_memory(test_addr - (index-ps), 8192)
            comm = bytes(next_task[task_struct['comm'][0] : task_struct['comm'][0] + 16])
            if comm[0] == 0x00:
                continue
            if comm.isascii():
                print("Found at "+hex(test_addr))
                print(comm)
                task_struct['tasks']['next'] = [index-ps, "pointer"]
                task_struct['tasks']['prev'] = [index, "pointer"]
        except gdb.MemoryError:
            pass
    ## TODO missing a LOT of fields
class PrintTaskStruct(gdb.Command):
    def __init__(self):
        super().__init__("ptask", gdb.COMMAND_USER)
    def invoke(self, args, tty):
        if len(args) < 2:
            print("[-] Error. Usage: ptask <address>/<comm>")
            return
        global task_struct
        if len(task_struct) == 0:
            build_taskstruct()
        args = args.split(' ')
        for i in args:
            try:
                address = int(i, 0)
            except ValueError:
                r = SP.invoke(i, None)
                if len(r) == 0:
                    print(i+" not found")
                    continue
                address = r[0]
            self.print_voc(task_struct, address)
    def print_voc(self, vocabulary,base):
        print(vocabulary)
        for key in vocabulary:
            k = vocabulary[key]
            if type(k) == type([]):
                mm = read_function[k[1]](gdb.Value(base + k[0]))
                print(key+'\t: '+str(mm))
            elif type(k) == type({}):
                self.print_voc(k, base)
PrintTaskStruct()
# }}}
# Process functions {{{
def processes():
    global task_struct
    if len(task_struct['tasks']) == 0:
        return
    init_task = gdb.parse_and_eval("$init_task")
    c_task = init_task
    while True: 
        address = read_pointer(c_task + task_struct['tasks']['next'][0])
        c_task = address - task_struct['tasks']['next'][0]
        if c_task == init_task:
            break
        yield c_task

class SearchProcess(gdb.Command):
    def __init__(self):
        super(SearchProcess, self).__init__("f_task", gdb.COMMAND_USER)
    def invoke(self, comm, tty):
        if len(task_struct) == 0:
            build_taskstruct()
        args = comm.split(' ')
        returned = []
        for x in args:
            try:
                value = int(x,0)
            except ValueError:
                value = x
            for t in processes():
                if type(value) == type(1):
                    c = read_uint32_t(t+task_struct['pid'][0])
                else:
                    c = read_c_string(t+task_struct['comm'][0], 16)
                if c == value:
                    print(t)
                    returned.append(t)
                    break
        return returned

SP = SearchProcess()

class Ls_Ps(gdb.Command):
    def __init__(self):
        super().__init__("ls-ps", gdb.COMMAND_USER)
    def invoke(self, args, tty):
        global task_struct
        if len(task_struct) == 0:
            build_taskstruct()
        p = processes()
        for t in p:
            c = str(read_c_string(t+task_struct['comm'][0], 16)).replace('\x00','')
            pid = int(read_uint32_t(t+task_struct['pid'][0]))
            gdb.write("0x{address:016x} {PID} {comm}\n".format(address=int(t), PID=pid, comm=c))
Ls_Ps()

class Current_Process(gdb.Function):
    def __init__(self):
        super(Current_Process, self).__init__("current")
    def invoke(self):
        # Find offset for current_task from exported symbols
        for s in ["$current_task", "$__per_cpu_offset"]:
            c_t = gdb.parse_and_eval(s)
            if c_t.type.code == gdb.TYPE_CODE_VOID:
                ad.invoke(s[1:],None)        
                c_t = gdb.parse_and_eval(s)
            if c_t.type.code == gdb.TYPE_CODE_VOID:
                print("ERROR BAD!")
                return gdb.error     
        # TODO Fix this with read_memory functions
        void_t = gdb.lookup_type('unsigned long long').pointer()
        cpu = gdb.selected_thread().num - 1
        c_t = gdb.parse_and_eval("$current_task")
        off = gdb.parse_and_eval("$__per_cpu_offset") + (8*cpu)
        per_cpu_data = off.cast(void_t).dereference() + (c_t)
        return per_cpu_data.cast(void_t).dereference()
Current_Process()
# }}}
# This is the main part where we build the exported symbols {{{
class AddSymb(gdb.Command):
    def __init__(self):
        super().__init__("symbs", gdb.COMMAND_USER)
    def invoke(self, args, tty):
        if args != "":
            args = args.split(' ')
        if not hasattr(self, 'symbs'):
            self.ksym_tab = None
            self.ksym_tab_gpl = None
            self.ksym_string = None
            self.filename = gdb.progspaces()[0].filename
            self.symbs = {}
            print("Parsing "+self.filename)
            self.open_file()
            self.sym_tab(self.ksym_tab)
            self.sym_tab(self.ksym_tab_gpl)
        for i in args:
            if i in self.symbs:
                print("[+] Exact match with "+i+" at "+hex(self.symbs[i]))
                gdb.execute("set $"+i+"="+hex(self.symbs[i]))
                continue
            for j in self.symbs:
                if i in j:
                    print("[?] Partial match with "+j+" at "+hex(self.symbs[j]))
    def open_file(self):
        f = open(self.filename, 'rb')
        e = ELFFile(f)
        for section in e.iter_sections():
            if section.name == '__ksymtab':
                self.ksym_tab = section
            elif section.name == '__ksymtab_gpl':
                self.ksym_tab_gpl = section
            elif section.name == '__ksymtab_strings':
                self.ksym_string = section
    def sym_tab(self, section):
        dd = section.data()
        strings = self.ksym_string.data()
        size = section.data_size
        num_symb = size / 16
        print("\'"+section.name+"\' has size "+hex(size)+" so we have "+str(num_symb)+" symbs")
        i = 0

        while i < num_symb:
            sy = struct.unpack('<QQ', dd[(i*16):(i*16)+16])
            offset = sy[1] - self.ksym_string['sh_addr']
            name = strings[offset:].decode('ascii').split('\x00')[0]
            self.symbs[name] = sy[0]
            i+=1
ad = AddSymb()
# }}}
# Usefull definition used for kcalling functions with #define {{{
DEFINE = {}
DEFINE['___GFP_DMA'] = 0x01
DEFINE['___GFP_HIGHMEM'] = 0x02
DEFINE['___GFP_DMA32'] =	0x04
DEFINE['___GFP_MOVABLE']	=	0x08
DEFINE['___GFP_RECLAIMABLE']	=0x10
DEFINE['___GFP_HIGH']	=0x20
DEFINE['___GFP_IO']		=0x40
DEFINE['___GFP_FS']		=0x80
DEFINE['___GFP_COLD']		=0x100
DEFINE['___GFP_NOWARN']		=0x200
DEFINE['___GFP_RETRY_MAYFAIL']	=0x400
DEFINE['___GFP_NOFAIL']		=0x800
DEFINE['___GFP_NORETRY']		=0x1000
DEFINE['___GFP_MEMALLOC']		=0x2000
DEFINE['___GFP_COMP']		=0x4000
DEFINE['___GFP_ZERO']		=0x8000
DEFINE['___GFP_NOMEMALLOC']	=0x10000
DEFINE['___GFP_HARDWALL']		=0x20000
DEFINE['___GFP_THISNODE']		=0x40000
DEFINE['___GFP_ATOMIC']		=0x80000
DEFINE['___GFP_ACCOUNT']		=0x100000
DEFINE['___GFP_DIRECT_RECLAIM']	=0x400000
DEFINE['___GFP_WRITE']		=0x800000
DEFINE['___GFP_KSWAPD_RECLAIM']	=0x1000000
DEFINE['__GFP_RECLAIM'] = ((DEFINE['___GFP_DIRECT_RECLAIM']|DEFINE['___GFP_KSWAPD_RECLAIM']))
DEFINE['GFP_KERNEL'] = (DEFINE['__GFP_RECLAIM'] | DEFINE['___GFP_IO'] | DEFINE['___GFP_FS'])
# }}}
# Calling function in current {{{
class Exec_Function(gdb.Command):
    def __init__(self):
        super().__init__("kcall", gdb.COMMAND_USER)
    def invoke(self, args, tty):
        ss = args.split('(')
        function = ss[0]
        try:
            function = int(function,0)
        except ValueError:
            ad.invoke(function, None)
            function = gdb.parse_and_eval("$"+function)
            if function.type.code == gdb.TYPE_CODE_VOID:
                print("Function not found")
                return gdb.error
        # Now, I need to save all the status
        rr = {}
        regs = gdb.execute("info register", to_string= True).split('\n')
        for i in regs:
            sx = i.split(' ')
            reg = sx[0]
            for j in sx[1:]:
                if j!= "":
                    break
            if reg == " ":
                continue
            rr[reg] = j
        current = gdb.parse_and_eval("$current()")
        params = ss[1].split(')')
        p_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        ix = 0
        if len(params[0]) != 0:
            params = params[0].split(',')
            for j in params:
                j = j.strip()
                if j in DEFINE:
                    j = hex(DEFINE[j])
                print("set $"+p_regs[ix]+"="+j)
                gdb.execute("set $"+p_regs[ix] + "="+j)
                ix+=1
                if ix > 5:
                    ## TODO
                    print("More than 5 arguments is to be implemented")
                    return gdb.error
        # Call the function. We create a new stack frame
        gdb.execute("set $rsp-=8")
        gdb.execute("set {unsigned long}$rsp=$pc")
        gdb.execute("set $pc="+str(function))
        # In order to catch the termination of that function
        bb = kCallFinishBreakpoint(gdb.newest_frame(), rr, current)
        # Let's GO!
        gdb.execute("continue")
class kCallFinishBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, frame, regs, current):
        super(kCallFinishBreakpoint,self).__init__(frame, True)
        self.frame = frame
        self.regs = regs
        self.current = current
    def stop(self):
        returned = gdb.parse_and_eval("$current()")
        if returned != self.current:
            return False
        # So we can see the current status
        gdb.execute("info register")
        # Store the returned value
        gdb.execute("set $ret=$rax")
        ## Restore register
        for j in self.regs:
            gdb.execute("set $"+j+"="+self.regs[j])
        # Stop the execution
        return True
Exec_Function()
# }}}
# Escalate to root. Like a script {{{
class escalateToRoot(gdb.Command):
    def __init__(self):
        super(escalateToRoot, self).__init__("escalate", gdb.COMMAND_USER)
    def invoke(self, args, tty):
        if len(task_struct) == 0:
            build_taskstruct()
        # I noticied that this works very well ONLY in swapper thread. I don't fully understand why
        current = gdb.parse_and_eval("$current()")
        comm = read_c_string(current + task_struct['comm'][0])
        if comm != "swapper/0":
            print("This command should be executed in swapper context but now we are in "+comm)
            return gdb.error
        try:
            c_address = int(args, 0)
            if c_address < 0xffff:
                raise ValueError
        except ValueError:
            r = SP.invoke(args, None)
            if len(r) == 0:
                print("Process "+args+" not found")
                return gdb.error
            c_address = r[0] 
        # Start with creating a memory pointer
        gdb.execute("kcall __kmalloc(256, GFP_KERNEL)")
        gdb.execute("set $mm=$ret")
        # Finding the symbols
        # Disable SELINUX
        gdb.execute("set {char[18]}$mm=\"selinux_enforcing\"")
        gdb.execute("kcall kallsyms_lookup_name("+str(gdb.parse_and_eval("$mm"))+")")
        gdb.execute("set $selinux_enforcing=$ret")
        gdb.execute("set {unsigned int}$ret=0x0")
        # SeLinux disabled
        # Creating a new credentials struct
        gdb.execute("set {char[14]}$mm=\"prepare_creds\"")
        gdb.execute("kcall kallsyms_lookup_name("+str(gdb.parse_and_eval("$mm"))+")")
        gdb.execute("kcall "+str(gdb.parse_and_eval("$ret"))+"()")
        # Set usage field in order to avoid crashing the system with __put_cred
        gdb.execute("set {unsigned int}$ret=0x2")
        # Now we have a root credentials inside $ret
        gdb.execute("set {unsigned long}("+hex(c_address + task_struct['cred'][0])+")=$ret")
        gdb.execute("set {unsigned long}("+hex(c_address + task_struct['real_cred'][0])+")=$ret")
        # and WIN
escalateToRoot()
# }}}
