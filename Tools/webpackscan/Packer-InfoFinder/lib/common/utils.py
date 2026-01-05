# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os,random,locale,time,shutil
from urllib.parse import urljoin, urlparse
# from lib.common.cmdline import CommandLines


def resolve_js_url(path: str, base_url: str) -> str:
    """
    Resolve a JS path to an absolute URL.
    
    Args:
        path: The JS path (can be absolute, protocol-relative, or relative)
        base_url: The base URL for resolving relative paths
    
    Returns:
        The resolved absolute URL
    
    URL Types:
        - Absolute URL (http:// or https://): returned unchanged
        - Protocol-relative (//): prepend protocol from base_url
        - Relative path: join with base_url using urljoin
    """
    # Handle empty path
    if not path or not path.strip():
        return ""
    
    path = path.strip()
    
    # Skip special protocols
    special_protocols = ('javascript:', 'data:', 'about:', 'blob:', 'mailto:')
    if path.lower().startswith(special_protocols):
        return ""
    
    # Absolute URL - return unchanged
    if path.startswith('http://') or path.startswith('https://'):
        return path
    
    # Protocol-relative URL - prepend protocol from base_url
    if path.startswith('//'):
        parsed_base = urlparse(base_url)
        protocol = parsed_base.scheme if parsed_base.scheme else 'http'
        return f"{protocol}:{path}"
    
    # Relative path - use urljoin
    return urljoin(base_url, path)


class Utils():

    def creatTag(self, num):  # 生成随机tag
        H = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        salt = ''
        for i in range(num):
            salt += random.choice(H)
        return salt

    def getFilename(self, url):
        filename = url.split('/')[-1]
        filename = filename.split('?')[0]
        return filename

    def creatSometing(self, choice, path):  # choice1文件夹，2文件
        # 返回0已经存在，返回1创建文件夹成功，返回2创建文件夹失败
        if choice == 1:
            path = path.split('/')  # 输入统一用 /
            path = os.sep.join(path)
            path = os.getcwd() + os.sep + path
            try:
                if not os.path.exists(path):
                    os.makedirs(path)
                    return 1
            except Exception as e:
                print(f"[Err] 创建目录失败: {e}")
                return 2
            return 0
        if choice == 2:
            try:
                # 处理路径
                path_parts = path.split('/')
                file_name = path_parts[-1]
                dir_path = os.sep.join(path_parts[:-1])
                full_dir_path = os.getcwd() + os.sep + dir_path
                
                # 确保目录存在
                if not os.path.exists(full_dir_path):
                    os.makedirs(full_dir_path)
                
                # 返回成功
                return 1
            except Exception as e:
                print(f"[Err] 创建文件路径失败: {e}")
                return 2
            return 0

    def getMiddleStr(self, content, startStr, endStr):  # 获取中间字符串通用函数
        startIndex = content.index(startStr)
        if startIndex >= 0:
            startIndex += len(startStr)
        endIndex = content.index(endStr)
        return content[startIndex:endIndex]


    def tellTime(self): #时间输出
        localtime = "[" + str(time.strftime('%H:%M:%S',time.localtime(time.time()))) + "] "
        return localtime

    def getMD5(self,file_path):
        files_md5 = os.popen('md5 %s' % file_path).read().strip()
        file_md5 = files_md5.replace('MD5 (%s) = ' % file_path, '')
        return file_md5

    def copyPath(self,path,out):
        out = out + os.sep + path.split(os.sep)[-1]
        os.mkdir(out)
        for files in os.listdir(path):
            name = os.path.join(path, files)
            back_name = os.path.join(out, files)
            if os.path.isfile(name):
                if os.path.isfile(back_name):
                    if self.getMD5(name) != self.getMD5(back_name):
                        shutil.copy(name,back_name)
                else:
                    shutil.copy(name, back_name)
            else:
                if not os.path.isdir(back_name):
                    os.makedirs(back_name)
                self.main(name, back_name)

    def build_proxies(self, proxy_str):
        try:
            if proxy_str is None:
                return None
            proxy_str = str(proxy_str).strip()
            if proxy_str == "":
                return None
            return {'http': proxy_str, 'https': proxy_str}
        except Exception:
            return None
