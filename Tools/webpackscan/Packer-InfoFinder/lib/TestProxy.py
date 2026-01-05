# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import requests
import sys
import time
import re

import urllib3
from lib.common.utils import Utils

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def testProxy(options, show):
    """
    优化后的网络连通性测试函数
    - 支持多个测试节点自动切换
    - 增加重试机制
    - 延长超时时间
    - 批量扫描时降低频率
    """
    # 多个测试节点，提高可用性
    # 仅使用国内网络更友好的节点
    test_urls = [
        "http://ip.3322.net",
        "https://myip.ipip.net",
    ]

    proxy_data = Utils().build_proxies(options.proxy)

    ipAddr = ""
    max_retries = 3  # 最大重试次数
    timeout_settings = (8, 15)  # (连接超时, 读取超时) - 增加到8/15秒

    # 尝试每个测试节点
    for url in test_urls:
        retry_count = 0
        while retry_count < max_retries:
            try:
                # 每次重试前增加延迟，避免频繁请求
                if retry_count > 0:
                    time.sleep(1 * retry_count)  # 递增延迟：1秒、2秒、3秒

                kwargs = {
                    'timeout': timeout_settings,
                    'verify': False,
                    'allow_redirects': True,
                }
                if proxy_data:
                    kwargs['proxies'] = proxy_data
                response = requests.get(url, **kwargs)

                if response.status_code == 200:
                    text = response.text.strip()
                    ip = ""
                    # 尝试从返回内容中提取 IPv4 或 IPv6
                    m4 = re.search(r"\b(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}\b", text)
                    if m4:
                        ip = m4.group(0)
                    else:
                        m6 = re.search(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", text)
                        if m6:
                            ip = m6.group(0)
                        else:
                            ip = text  # 兜底：直接使用原始文本
                    if ip:
                        if show == 1 and options.silent is None:
                            print(f"[+] 网络连通性检测通过，当前出口IP：{ip}")
                        return ip

            except requests.exceptions.Timeout:
                retry_count += 1
                if show == 1 and options.silent is None and retry_count < max_retries:
                    print(f"[!] 网络测试超时，正在重试 ({retry_count}/{max_retries})...")
                continue

            except requests.exceptions.ProxyError:
                if show == 1 and options.silent is None:
                    print(f"[!] 代理连接失败，请检查代理配置: {options.proxy}")
                return ipAddr

            except requests.exceptions.ConnectionError:
                retry_count += 1
                if show == 1 and options.silent is None and retry_count < max_retries:
                    print(f"[!] 网络连接失败，正在重试 ({retry_count}/{max_retries})...")
                continue

            except Exception:
                retry_count += 1
                if retry_count >= max_retries:
                    # 尝试下一个测试节点
                    break
                continue

        # 如果当前节点获取到了IP，直接返回
        if ipAddr:
            return ipAddr

    # 所有节点都失败
    if show == 1 and options.silent is None:
        print("[!] 连接失败，请检查当前网络状况或者代理情况")
        print("[提示] 已尝试多个测试节点，建议：")
        print("       1. 检查网络连接是否正常")
        print("       2. 如使用代理，请确认代理配置正确")
        print("       3. 检查防火墙设置")

    return ipAddr
