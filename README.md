# gdb_2_root
This python script adds some usefull command to stripped `vmlinux` image.

## What is this and why
This script adds some usefull command for debugging kernel without symbols.

The main goal is to obtain a root shell with `Android Emulator` using common _Google Play Images_ with the built-in kernel.

I started this little script because I needed a way to easily obtain a root shell in emulated _AVD_ with Google Play (and Services) installed.

## Installation
The installation is quite straightforward:
1. Clone this repo
2. Source inside __GDB__ the script (`source <path_to_repo>/root_gdb.py`)

There is only one requirements: [ELFFile](https://pypi.org/project/elffile/)
```
  pip install elffile
```

## Usage
The script adds some usefull command to __GDB__.

If you only want to root a process, you can use: 
```
  escalate <comm>/<pid>/<task_struct address>
```
and the script will disable `selinux` and change the process credentials.

_Just a note_: `comm` is intended as the field in `task_struct` kernel structure (`char comm[16]`) so it can be different from the real name (you can check the running process with `ls-ps`).

### List of commands:
- `ptask <struct task_struct address>`: Print some fields of `task_struct` structure. 
- `f_task <comm/pid>`: Search the process (by PID or COMM) and it returns the address of `task_struct`
- `ls-ps`: List all process
- `current`: __GDB__ function. This is the address of the `task_struct` for the _current_ running process
- `symbs <symbol name>`: Try to find symbols using _ksymtab_ section
- `kcall name_or_address(parameter, parameter, ...)`: Create a new stack frame and execute a kernel function. More of this later 
- `escalate`: This command works like a script. It use `kcall` in order to disable __SELinux__ and change the credentials of one process.

## Android rooting AVD
The main objective of this script is to obtain a root shell in a any AVD without actually rooting the emulator. The steps are simple:
1. `emulator -avd <YourAVD> -ranchu -verbose | grep kernel.path`: with this command you can see where the __vmlinux__ image is located
2. That image should be a `bzImage` so you should extract it. I use [extract-vmlinux](https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux).
3. You can now restart your emulator with: `emulator -avd <YourAVD> -show-kernel -no-snapshot-load -ranchu -qemu -s -append "nokaslr"`. After the boot, open a shell with `adb shell`.
4. Open __GDB__ with `gdb <path/to/extracted/vmlinux> -ex "target remote :1234"`
5. Source the script `source <path/to/repo/root_gdb.py>`
7. `escalate sh`, wait for the completation and `continue`. This command refuses to execute if it is not in the context of `swapper` process so you should `continue` and break few times before catching the right process.
9. Enjoy your rooted Google Image emulator (or the panic :D)

The `escalate` commands can __panic__ your kernel. You can retry.

![Escalation example](https://github.com/c3r34lk1ll3r/gdb_2_root/blob/master/escalate.gif?raw=true)
## Limitations
At this moment, this script works only with x86_64 image. In particular, I tested only with __Android 10__. Feedbacks are really appreciated. 

There is an medium change to __panic__ your kernel. Just reboot and retry.

## Kcall
The main command is `kcall` because it allows to modify the running kernel and inject the execution of kernel function. The main idea is to create a new _stack frame_ and jump to the new address. The parameters are handled just copying the value to registers one by one. 

If you need to pass some pointers, you can use __kmalloc__, set the value to that memory location and use that pointer as argument.

If you need others memory locations, you can call __kallsyms\_lookup\_name(pointer_to_char*)__.

The return value is stored in `$ret` variable (so `x/x $ret`).
## How this works
This script uses the ___ksymtab__ in order to find __init_task__ address. Then, we can search some fields like __comm__ and the tasks list.

The escalation is made calling some kernel function. In particular, we can disable __SELinux__ searching, thanks to __kallsyms_lookup_name__, the `selinux_enforcing` symbol. Then, we can create a new credential with _prepare_cred_ and change the pointer in the _task_struct_ structure.

