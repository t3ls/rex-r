from pwn import *
import roputils
import os
import sys

class cfl():
    @classmethod
    def run(self, binary):
        def check_seed(seed):
        #sleep(0.5)
        #p.close()
            print '\n',seed,'\n'
            core_list = filter(lambda x:"core" in x, os.listdir('.'))
            if len(core_list) > 0:
                cfl_crash_list.append(seed)
                print cfl_crash_list
                #print core_list
                #print len(cfl_crash_list)
                for core in core_list:
                    os.unlink(core)

        global cfl_crash_list
        cfl_crash_list = []
        seed_list = ['0','1','2','3','4','5','y','n',roputils.Pattern.create(1000)]
        #afl can't solve
        core_list = filter(lambda x:"core" in x, os.listdir('.'))
        os.popen('ulimit -c unlimited')
        if len(core_list) > 0:
            for core in core_list:
                os.unlink(core)
        p = process(binary)
        #fuzz circle
        for a in seed_list:
            try:
                p.sendline(a)
            except:
                p.close()
                check_seed(a)
                #check_seed('1')
            for b in seed_list:
                try:
                    p.sendline(b)
                except:
                    p.close()
                    check_seed(a+'\n'+b)
                    #check_seed('1\n0')
                for c in seed_list:
                    try:
                        p.sendline(c)
                    except:
                        p.close()
                        check_seed(a+'\n'+b+'\n'+c)
                        #check_seed('1\n0\n'+roputils.Pattern.create(1000))
                    for d in seed_list:
                        try:
                            p.sendline(d)
                        except:
                            p.close()
                            check_seed(a+'\n'+b+'\n'+c+'\n'+d)
                            #check_seed('1\n0\n'+roputils.Pattern.create(1000)+'\n'+d)
                        for e in seed_list:
                            try:
                                p.sendline(e)
                                #if a == '1' and b == '0' and c == roputils.Pattern.create(1000) and d == '3' and e == '0':
                                #    print 'crash seed find'
                            except:
                                p.close()
                                check_seed(a+'\n'+b+'\n'+c+'\n'+d+'\n'+e)
                                #check_seed('1\n0\n'+roputils.Pattern.create(1000)+'\n'+d+'\n'+e)
                            for f in seed_list:
                                try:
                                    p.sendline(f)
                                except:
                                    p.close()
                                    check_seed(a+'\n'+b+'\n'+c+'\n'+d+'\n'+e+'\n'+f)
                                    #check_seed('1\n0\n'+roputils.Pattern.create(1000)+'\n'+d+'\n'+e+'\n'+f)
                                for g in seed_list:
                                    try:
                                        p.sendline(g)
                                    except:
                                        p.close()
                                        check_seed(a+'\n'+b+'\n'+c+'\n'+d+'\n'+e+'\n'+f+'\n'+g)
                                        #check_seed('1\n0\n'+roputils.Pattern.create(1000)+'\n'+d+'\n'+e+'\n'+f+'\n'+g)
        return cfl_crash_list



