#!/usr/bin/env python3
"""
Author:[huan666]
Date:[2024/01/12]
"""
import re
from url_lib import urlinfo


def scandomain():
    domain_file = open('/TIP/batch_scan_domain/url.txt',encoding='utf-8')
    url_list = []
    try:
        for line in domain_file.readlines():
            #从https://www.xxx.com/1.html中匹配出www.xxx.com
            pattern = r"https?://([^/]+)"
            urls_re = re.search(pattern,line)
            urls_pattern = urls_re.group(1)
            url_list.append(urls_pattern)
        
        #列表去重
        url_list_uniq = list(set(url_list))
        urlinfo(url_list_uniq)
    except Exception as e:
        print("发生异常:", e)




if __name__ == "__main__":
    scandomain()