import os
from pwn import *

class tools():
    def __init__(self, binary, crash):
        self.binary = binary
        self.crash = crash
        self.core_list = filter(lambda x:"core" in x, os.listdir('.'))
        self.core = self.core_list[0]

    def gdb(self, command):
        popen=os.popen('gdb '+self.binary+' '+self.core+' --batch -ex "'+command+'"')
        return popen.read()

    def ROPsearch(self, register):
        popen = os.popen('ROPgadget --binary '+self.binary+' |grep ": call '+register+'"|cut -d \' \' -f1')
        s = popen.read()
        if (s != ''):
            rop = p32(int(s,16))
        else:
            popen = os.popen('ROPgadget --binary '+self.binary+' |grep ": jmp '+register+'"|cut -d \' \' -f1')
            s = popen.read()
            if (s != ''):
                rop = p32(int(s,16))
            else:
                log.info('Can\'t find jmp|call '+register+'')
                rop = -1
        return rop

    def get_data(self, size, addr):
        data = str()
        s = self.gdb('x /'+str(size)+'gx '+hex(addr))
        i = size
        j = 1
        while(i):
            aline = s.split(':\t')[j].split('\n')[0]
            if aline == '':
                break
            if(i>1):
                data += p64(int(aline.split('\t')[0],16))
                data += p64(int(aline.split('\t')[1],16))
                i -= 2
                if(j <= size/2):
                    j += 1
            else:
                data += p64(int(aline,16))
                i -= 1
        return data
