#!/usr/bin/env python3
"""
Author:[huan666]
Date:[2024/02/07]
"""
from config import history_switch
import subprocess
from scan_lib import scandomain

def ergodic_target():
    if int(history_switch) == 0:
        file = "./url.txt"
        print("正在通过RAD扫描用户输入URL......")
    elif int(history_switch) ==1:
        print("正在调用OTX查询历史URL......")
        scandomain()
        file = "./result.txt"
        print("正在通过RAD扫描历史URL......")
    else:
        print("配置文件history_switch字段只允许0/1")
    for line in open(file):
        line = line.replace("\n","")
        command = ["./start.sh", "startrad", line]
        #启动子进程  
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

        #实时读取子进程输出  
        for output_line in iter(process.stdout.readline, ''):
            print(output_line, end='')  # 实时打印输出  
  
        #等待子进程结束  
        process.stdout.close()  
        returncode = process.wait()  
        if returncode != 0:  
            print(f"Error: Command returned non-zero exit status {returncode}")  
        



if __name__ == "__main__":
    ergodic_target()