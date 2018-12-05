from tools import *
from pwn import *

class state():
    def __init__(self, binary, crash):
        self.binary = binary
        self.crash = crash
        self.info = {}
        self.tools = tools(binary, crash)

    def get_register_info(self):
        self.register_string = self.tools.gdb('info register')
        self.info['esp'] = p32(int(self.register_string.split('esp')[1].lstrip().split('\t')[0],16))
        self.info['eip'] = p32(int(self.register_string.split('eip')[1].lstrip().split('\t')[0],16))
        self.info['ebp'] = p32(int(self.register_string.split('ebp')[1].lstrip().split('\t')[0],16))
        self.info['eax'] = p32(int(self.register_string.split('eax')[1].lstrip().split('\t')[0],16))
        self.info['ebx'] = p32(int(self.register_string.split('ebx')[1].lstrip().split('\t')[0],16))
        self.info['ecx'] = p32(int(self.register_string.split('ecx')[1].lstrip().split('\t')[0],16))
        self.info['edx'] = p32(int(self.register_string.split('edx')[1].lstrip().split('\t')[0],16))
        self.info['data_in_esp'] = self.tools.get_data(0x100, u32(self.info['esp']))
        self.info['data_in_ebp'] = self.tools.get_data(0x20, u32(self.info['ebp']))
        self.info['data_in_eip'] = self.tools.get_data(0x20, u32(self.info['eip']))
        self.info['data_in_eax'] = self.tools.get_data(0x20, u32(self.info['eax']))
        self.info['data_in_ebx'] = self.tools.get_data(0x20, u32(self.info['ebx']))
        self.info['data_in_ecx'] = self.tools.get_data(0x20, u32(self.info['ecx']))
        self.info['data_in_edx'] = self.tools.get_data(0x20, u32(self.info['edx']))

    def get_segment_data(self):
        elf = ELF(self.binary)
        self.info['bss_addr'] = str(elf.bss(0))
        self.info['bss_data'] = self.tools.get_data(0x1000, int(self.info['bss_addr']))
        return self.info
