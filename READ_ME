-The submission consists of ROPcompiler.py, vuln1 and READ_ME
READ_ME 

documentation about project

vuln1

example vulnerable ELF file that is to be exploit

ROPcompiler.py

usage: ROPcompiler.py [-h] [-binaries BINARIES] [-bufferLength BUFFERLENGTH]
                      [-mode MODE]

ROPcompiler takes BINARIES BUFFERLENGTH MODE as arguments.
BINARIES : vulnerable ELF file that is to be exploited.
BUFFERLENGTH : length of buffer where argument to program is to be strcpy.
MODE : test or payload. test - test the payload with subprocess. payload - prints out the payload.

ROPcompiler collects gadgets from libc. Any gadgets that is not found but essential is to be collected from user input.
ROPcompiler assumes that the vulnerable program uses "/usr/lib/i386-linux-gnu/libc-2.28.so".
ROPcompiler also assumes that ASLR is disabled before running.
ROPcompiler uses some gdb command shell. If some other gdb options are set in ~/.gdbinit, ROPcompiler will fail.

Frameworks that are used : capstone, pyelftools
Both framesworks were used to binary instructions from ELF file.

Strategy
mprotect syscall was used to set execute permissions on stack and then jmpcall to $esp which contains fixed shellcode.
mprotect syscall : eax = \x7b; ebx = address of stack; ecx = length of memory address in which permission will be changed;
edx = protect flag (\x07 for read write execute);
After setting all the arguments, syscall is called and then jmpcall to $esp. Shellcode is injected after all the ROP payload so that jmpcall to $esp can execute shellcode.

Some Tricks...
Stack address and libc base address is found using gdb shell command.
All the instructions before gs:[0x10] were skipped to withstand mangled registers in syscall.

