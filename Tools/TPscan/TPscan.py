#!/usr/bin/env python
# coding=utf-8
from gevent import monkey;

monkey.patch_all()
from gevent.pool import Pool
from termcolor import colored
from plugins.thinkphp_checkcode_time_sqli import thinkphp_checkcode_time_sqli_verify
from plugins.thinkphp_construct_code_exec import thinkphp_construct_code_exec_verify
from plugins.thinkphp_construct_debug_rce import thinkphp_construct_debug_rce_verify
from plugins.thinkphp_debug_index_ids_sqli import thinkphp_debug_index_ids_sqli_verify
from plugins.thinkphp_driver_display_rce import thinkphp_driver_display_rce_verify
from plugins.thinkphp_index_construct_rce import thinkphp_index_construct_rce_verify
from plugins.thinkphp_index_showid_rce import thinkphp_index_showid_rce_verify
from plugins.thinkphp_invoke_func_code_exec import thinkphp_invoke_func_code_exec_verify
from plugins.thinkphp_lite_code_exec import thinkphp_lite_code_exec_verify
from plugins.thinkphp_method_filter_code_exec import thinkphp_method_filter_code_exec_verify
from plugins.thinkphp_multi_sql_leak import thinkphp_multi_sql_leak_verify
from plugins.thinkphp_pay_orderid_sqli import thinkphp_pay_orderid_sqli_verify
from plugins.thinkphp_request_input_rce import thinkphp_request_input_rce_verify
from plugins.thinkphp_view_recent_xff_sqli import thinkphp_view_recent_xff_sqli_verify

import sys
import gevent
import argparse




# TPscan原来功能已注释
# print('''
#  ___________                    
# |_   _| ___ \                   
#   | | | |_/ /__  ___ __ _ _ __  
#   | | |  __/ __|/ __/ _` | '_ \ 
#   | | | |  \__ \ (_| (_| | | | |
#   \_/ \_|  |___/\___\__,_|_| |_|          
#                 code by Lucifer
# ''')
# targeturl = input("[*]Give me a target: ")
# if targeturl.find('http') == -1 and targeturl.find('https') == -1:
#     print(colored("\n[*]Please input a valid url!", "red"))
#     exit(1)




##########################################################################################
# 为了适配info_scan,修改为 python3 TPscan.py -u url 传参
# 创建 ArgumentParser 对象
parser = argparse.ArgumentParser(description='处理命令行参数')

# 添加 -u 参数
parser.add_argument('-u', '--url', dest='url', type=str, help='指定一个URL')

# 解析命令行参数
args = parser.parse_args()

# 检查 -u 参数是否被提供,不输入-u参数直接退出
if args.url:
    # print(f"提供的URL是: {args.url}")
    targeturl = f"{args.url}"
else:
    print("没有提供URL参数。")
    sys.exit()

print("当前URL："+targeturl)
##########################################################################################



poclist = [
    'thinkphp_checkcode_time_sqli_verify("{0}")'.format(targeturl),
    'thinkphp_construct_code_exec_verify("{0}")'.format(targeturl),
    'thinkphp_construct_debug_rce_verify("{0}")'.format(targeturl),
    'thinkphp_debug_index_ids_sqli_verify("{0}")'.format(targeturl),
    'thinkphp_driver_display_rce_verify("{0}")'.format(targeturl),
    'thinkphp_index_construct_rce_verify("{0}")'.format(targeturl),
    'thinkphp_index_showid_rce_verify("{0}")'.format(targeturl),
    'thinkphp_invoke_func_code_exec_verify("{0}")'.format(targeturl),
    'thinkphp_lite_code_exec_verify("{0}")'.format(targeturl),
    'thinkphp_method_filter_code_exec_verify("{0}")'.format(targeturl),
    'thinkphp_multi_sql_leak_verify("{0}")'.format(targeturl),
    'thinkphp_pay_orderid_sqli_verify("{0}")'.format(targeturl),
    'thinkphp_request_input_rce_verify("{0}")'.format(targeturl),
    'thinkphp_view_recent_xff_sqli_verify("{0}")'.format(targeturl),
]


def pocexec(pocstr):
    exec(pocstr)
    gevent.sleep(0)


pool = Pool(1)
threads = [pool.spawn(pocexec, item) for item in poclist]
gevent.joinall(threads)
