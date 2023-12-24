'''
Description:[调用nuclei启动文件]
Author:[huan666]
Date:[2023/12/24]
'''
import os

def nucle_scan(nucleilist):
    f = open(file='./result/domainstatuscode.txt', mode='w')
    for k in nucleilist:
        f.write(str(k)+"\n")
    f.close()
    if len(nucleilist) == 0:
        print("列表为空")
    else:
        print("正在进行nuclei漏洞扫描.....")
        os.popen('bash ./finger.sh startnuclei')