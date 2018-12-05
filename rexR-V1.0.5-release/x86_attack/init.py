import sys
from state import *
from roputils import *

class init():
    def __init__(self, binary, crash):
        self.binary = binary
        self.crash = crash
        self.info = set()
        self.core_list = []
        #self.import_crash()
        self.core_dump()


    def import_crash(self):
        #self.crash_file = input('Input crash_file name: ')
        f = open(self.crash_file, 'r')
        self.crash = f.read()
        f.close()
        #self.optimize_crash()

    #def optimize_crash(self):
        #p = process(self.binary)
        #p.sendline(self.crash)
        #print p.recv(1024)
        #if 'Segmentation fault' in p.recv(1024):
         #   log.info('Crash imported!')
        #else:
         #   log.info('Crash can\'t be used!')
        #p.close()

    def core_dump(self):
        self.core_list = filter(lambda x:"core" in x, os.listdir('.'))
        if self.core_list is not None:
            os.popen('ulimit -c unlimited')
            for core in self.core_list:
                os.unlink(core)
        p = process(self.binary)
        p.sendline(self.crash)
        sleep(0.5)
        p.close()

    def get_state(self):
        self.core_list = filter(lambda x:"core" in x, os.listdir('.'))
       # print self.core_list
        if len(self.core_list) == 0:
            if self.crash is '':
                log.info('No Crash')
            else:
                log.info('Crash can\'t be used!')
            return None
        s = state(self.binary, self.crash)
        s.get_register_info()
        self.info = s.get_segment_data()
        return self.info
