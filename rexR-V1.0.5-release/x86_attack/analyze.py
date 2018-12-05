from pwn import *
import sys
import os
from tools import *

class analyze():
    def __init__(self, info, binary, crash):
        self.info = info
        self.lcs = {}
        self.binary = binary
        self.crash = crash
        global t
        t = tools(binary, crash)


    def find_lcs(self):
        data = str()
        for key,data in self.info.items():
            m=[[0 for i in range(len(data)+1)]  for j in range(len(self.crash)+1)]
            mmax=0
            p=0
            for i in range(len(self.crash)):
                for j in range(len(data)):
                    if self.crash[i]==data[j]:
                        m[i+1][j+1]=m[i][j]+1
                        if m[i+1][j+1]>mmax:
                            mmax=m[i+1][j+1]
                            p=i+1
            lcsubstr = str(self.crash[p-mmax:p])
            if mmax > 0:
                self.lcs[key] = lcsubstr
                self.lcs[key] += ',.,'
                self.lcs[key] += str(p-mmax)
        if 'eip' not in self.lcs.keys():
            if 'data_in_eip' not in self.lcs.keys():
                log.info('Crash can\'t be used!')
                return -1
        #if len(self.lcs['eip'].split(',.,')[0]) is not 4:
        #    log.info('Crash can\'t be used!')
        #    return -1
        return self.lcs

    def calc_index(self):
        rop_and_index = {}
        for key,value in self.lcs.items():
            lcsubstr = value.split(',.,')[0]
            index = value.split(',.,')[1]
            if '\r' in lcsubstr:
                lcsubstr = lcsubstr.split('\r')[0]
            if '\n' in lcsubstr:
                lcsubstr = lcsubstr.split('\n')[0]
            if len(lcsubstr) > 22:
                if key is not 'bss_data':
                    if key is 'data_in_eip':
                        #print 'direct_call analyze data_in_eip'
                        if self.info['data_in_eip'].find(lcsubstr,0) == 0 or 1:
                            rop_and_index['direct_call' + str(index)] = index

                    else:
                        reg = key.split('_in_')[1]
                        log.info('Finding ROP: call|jmp '+reg+'')
                        rop = t.ROPsearch(reg)
                        if rop is not -1:
                            log.info('ROP: ' + str(hex(u32(rop))))
                            rop = rop + ',' + reg
                            rop_and_index[rop] = index
                else:
                    i = 0
                    log.info('Sending shellcode to bss!')
                    while(1):
                        i = self.info['bss_data'].find(lcsubstr, i)
                        if i > 0:
                            rop_and_index[p32(int(self.info['bss_addr'])+i)+',bss'] = index
                            i += 1
                        else:
                            break
        return rop_and_index




