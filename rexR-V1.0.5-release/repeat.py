#-*- coding:utf8 -*-
import os
import time


if __name__ == '__main__':
    for job_id in range(8,43):
        print job_id
        os.system("python main_type1.py %s" % (job_id))
        time.sleep(2)
