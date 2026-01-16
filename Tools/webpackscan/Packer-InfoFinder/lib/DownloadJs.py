# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import requests
import base64
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import sqlite3
import warnings
import random
import re
import logging
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from lib.common import readConfig
from lib.common.utils import Utils
from lib.common.CreatLog import creatLog
from lib.common.models import DiscoverySource


class DownloadJs():

    def __init__(self, jsRealPaths, options, discovery_source: Optional[DiscoverySource] = None):
        """
        Initialize DownloadJs with JS paths and options.
        
        Args:
            jsRealPaths: List of JS file URLs to download
            options: Command line options
            discovery_source: The method by which these JS files were discovered
                             (Requirements 4.1)
        """
        warnings.filterwarnings('ignore')
        self.jsRealPaths = jsRealPaths
        self.blacklist_domains = readConfig.ReadConfig().getValue('blacklist', 'domain')[0]
        self.blacklistFilenames = readConfig.ReadConfig().getValue('blacklist', 'filename')[0]
        self.options = options
        self.discovery_source = discovery_source or DiscoverySource.STATIC_HTML
        self.proxy_data = Utils().build_proxies(self.options.proxy)
        self.UserAgent = [
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 9.50",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.133 Safari/534.16",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.11 TaoBrowser/2.0 Safari/536.11",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.3.4000 Chrome/30.0.1599.101 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; SE 2.X MetaSr 1.0)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E; LBBROWSER)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0",
            "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)"
        ]
        self.log = creatLog().get_logger()
        self.successful_path_patterns = {}
        self.webpack_public_path = None

        # 降噪：收紧 urllib3 重试日志，只在严重错误时输出（避免长串 Retrying(...) 提示刷屏）
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
        
        # Discovery source prefix mapping for logging (Requirements 4.2)
        self._source_prefix_map = {
            DiscoverySource.STATIC_HTML: "[STATIC]",
            DiscoverySource.IFRAME: "[IFRAME]",
            DiscoverySource.INLINE_PATTERN: "[PATTERN]",
            DiscoverySource.BROWSER_INTERCEPT: "[BROWSER]",
        }

        # --- 优化：初始化一个具备重试功能的 session ---
        self.session = requests.Session()
        # 定义重试策略
        retry_strategy = Retry(
            total=3,  # 总重试次数
            status_forcelist=[429, 500, 502, 503, 504],  # 需要重试的状态码
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1  # 重试之间的延迟因子
        )
        # ######################## START: 代码修改区域 ########################
        # 创建一个带有重试策略的适配器，并增大连接池大小以匹配线程数
        adapter = HTTPAdapter(
            pool_connections=100,      # 总连接池数量，可以设置得大一些
            pool_maxsize=30,           # 关键：每个连接池的最大连接数，使其等于或大于 max_workers (30)
            max_retries=retry_strategy
        )
        # ######################## END: 代码修改区域 ##########################

        # 为 http 和 https 协议挂载此适配器
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        # ----------------------------------------------------------------

    def _get_source_prefix(self, source: Optional[DiscoverySource] = None) -> str:
        """
        Get the log prefix for a discovery source.
        
        Args:
            source: The discovery source, defaults to instance discovery_source
        
        Returns:
            Log prefix string like [STATIC], [IFRAME], [PATTERN], [BROWSER]
        
        Requirements: 4.2
        """
        src = source or self.discovery_source
        return self._source_prefix_map.get(src, "[STATIC]")

    def _append_sourcemap_report(self, project_root, message):
        try:
            sourcemap_dir = os.path.join(project_root, "sourcemaps")
            if not os.path.exists(sourcemap_dir):
                os.makedirs(sourcemap_dir)
            report_path = os.path.join(sourcemap_dir, "sourcemap_report.txt")
            with open(report_path, 'a', encoding='utf-8') as rf:
                rf.write(message.strip() + "\n")
        except Exception as e:
            # 静默失败，避免影响主流程
            self.log.debug(f"写入sourcemap报告失败: {e}")

    def _extract_sourcemap_reference(self, js_text):
        try:
            # 支持 //# 和 /*# 两种形式，允许在行中间出现（压缩后的JS）
            # 优先匹配行首的注释
            m1 = re.search(r"^[\t ]*\/\/#\s*sourceMappingURL\s*=\s*(.+)$", js_text, re.MULTILINE)
            if m1:
                return ('ref', m1.group(1).strip())
            # 匹配行中间的 //# 注释（压缩后的JS可能没有换行）
            m1b = re.search(r"\/\/#\s*sourceMappingURL\s*=\s*([^\s]+)", js_text)
            if m1b:
                return ('ref', m1b.group(1).strip())
            # 匹配 /*# ... */ 块注释形式
            m2 = re.search(r"\/\*#\s*sourceMappingURL\s*=\s*(.+?)\s*\*\/", js_text, re.DOTALL)
            if m2:
                return ('ref', m2.group(1).strip())
        except Exception:
            pass
        return None

    def _sanitize_source_path(self, relative_path):
        # 处理 webpack:// 前缀等 scheme
        try:
            path = relative_path.replace('\\', '/')
            if path.startswith('webpack://'):
                path = path[len('webpack://'):]
            path = path.lstrip('/')
            # 去掉奇怪的协议前缀，如 (webpack:///)
            if path.startswith('/'):
                path = path[1:]
            # 简单替换非法字符
            path = re.sub(r'[:*?"<>|]', '_', path)
            return path
        except Exception:
            return os.path.basename(relative_path)

    def _safe_join(self, base_dir, relative_path):
        target_path = os.path.abspath(os.path.join(base_dir, relative_path))
        base_dir_abs = os.path.abspath(base_dir)
        if not target_path.startswith(base_dir_abs):
            # 防目录穿越
            target_path = os.path.join(base_dir_abs, os.path.basename(relative_path))
        parent = os.path.dirname(target_path)
        if not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        return target_path

    def _save_map_file(self, project_root, js_local_tag, js_filename, map_bytes):
        sourcemap_dir = os.path.join(project_root, "sourcemaps")
        os.makedirs(sourcemap_dir, exist_ok=True)
        map_local_name = f"{js_local_tag}.{js_filename}.map"
        map_local_path = os.path.join(sourcemap_dir, map_local_name)
        with open(map_local_path, 'wb') as mf:
            mf.write(map_bytes)
        return map_local_path

    def _parse_and_save_sources(self, map_json, map_base_url, sources_root):
        saved = 0
        fetched = 0
        failed = 0
        try:
            sources = map_json.get('sources') or []
            sources_content = map_json.get('sourcesContent') or []
            source_root = map_json.get('sourceRoot') or ''

            # 计算基准URL - 正确处理 sourceRoot
            # sourceRoot 可能是:
            # 1. 空字符串 - 使用 map_base_url
            # 2. 相对路径 (如 "../src/") - 相对于 map_base_url
            # 3. 绝对路径 (如 "/src/") - 相对于域名根
            # 4. 完整URL (如 "webpack://app/") - 直接使用（但通常不可访问）
            effective_base_url = map_base_url
            if source_root:
                try:
                    # 如果 sourceRoot 是 webpack:// 等虚拟协议，忽略它
                    if not source_root.startswith(('webpack://', 'file://')):
                        # 确保 sourceRoot 以 / 结尾以正确拼接
                        if not source_root.endswith('/'):
                            source_root = source_root + '/'
                        effective_base_url = urljoin(map_base_url, source_root)
                except Exception:
                    pass

            for idx, src in enumerate(sources):
                safe_rel = self._sanitize_source_path(src if src else f"source_{idx}")
                out_path = self._safe_join(sources_root, safe_rel)

                try:
                    if idx < len(sources_content) and sources_content[idx] is not None:
                        # 直接使用嵌入内容
                        with open(out_path, 'w', encoding='utf-8', errors='ignore') as sf:
                            sf.write(sources_content[idx])
                        saved += 1
                        continue
                    
                    # 回源抓取 - 跳过 webpack:// 等虚拟协议的源文件
                    if src and src.startswith(('webpack://', 'file://')):
                        failed += 1
                        continue
                        
                    full_url = urljoin(effective_base_url, src)
                    resp = self.session.get(full_url, timeout=(10, 30))
                    resp.raise_for_status()
                    content_text = resp.text
                    with open(out_path, 'w', encoding='utf-8', errors='ignore') as sf:
                        sf.write(content_text)
                    fetched += 1
                except Exception:
                    failed += 1
                    continue
        except Exception:
            # 顶层错误不再抛出
            pass
        return saved, fetched, failed

    def _handle_sourcemap(self, js_text, js_url, project_root, js_local_tag, js_filename):
        ref = self._extract_sourcemap_reference(js_text)
        if not ref:
            return

        _, ref_value = ref
        try:
            if ref_value.startswith('data:'):
                # 处理内联 data: URL
                # 支持多种格式: data:application/json;base64,xxx 或 data:application/json;charset=utf-8;base64,xxx
                comma_idx = ref_value.find('base64,')
                if comma_idx != -1:
                    b64_data = ref_value[comma_idx + len('base64,'):]
                    try:
                        map_bytes = base64.b64decode(b64_data)
                    except Exception:
                        self._append_sourcemap_report(project_root, f"JS {js_filename}: data:URL base64 解码失败")
                        return
                else:
                    # 非base64的data URL，尝试直接截取逗号后文本（可能是URL编码的JSON）
                    comma = ref_value.find(',')
                    if comma != -1:
                        raw_data = ref_value[comma+1:]
                        # 尝试URL解码
                        try:
                            from urllib.parse import unquote
                            raw_data = unquote(raw_data)
                        except Exception:
                            pass
                        map_bytes = raw_data.encode('utf-8', errors='ignore')
                    else:
                        map_bytes = b''

                map_local_path = self._save_map_file(project_root, js_local_tag, js_filename, map_bytes)
                try:
                    map_json = json.loads(map_bytes.decode('utf-8', errors='ignore'))
                except Exception:
                    self._append_sourcemap_report(project_root, f"JS {js_filename}: data:URL 不是有效JSON，已保存 {os.path.basename(map_local_path)}")
                    return

                sources_root = os.path.join(project_root, 'sourcemaps', 'sources', f"{js_local_tag}.{js_filename}")
                os.makedirs(sources_root, exist_ok=True)
                saved, fetched, failed = self._parse_and_save_sources(map_json, js_url, sources_root)
                self._append_sourcemap_report(project_root, f"JS {js_filename}: 解析内联SourceMap，保存 {saved}，抓取 {fetched}，失败 {failed}")
                return

            # 远程 .map URL
            map_url = urljoin(js_url, ref_value)
            
            # 添加重试机制
            map_bytes = None
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    resp = self.session.get(map_url, timeout=(10, 30))
                    resp.raise_for_status()
                    map_bytes = resp.content
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        self.log.debug(f"[SourceMap] 下载重试 {attempt + 1}/{max_retries}: {map_url}")
                        continue
                    else:
                        self._append_sourcemap_report(project_root, f"JS {js_filename}: 下载 SourceMap 失败 {map_url}: {e}")
                        return
            
            if not map_bytes:
                return
                
            map_local_path = self._save_map_file(project_root, js_local_tag, js_filename, map_bytes)

            try:
                map_text = map_bytes.decode('utf-8', errors='ignore')
                map_json = json.loads(map_text)
            except Exception:
                self._append_sourcemap_report(project_root, f"JS {js_filename}: {map_url} 不是有效JSON，已保存 {os.path.basename(map_local_path)}")
                return

            sources_root = os.path.join(project_root, 'sourcemaps', 'sources', f"{js_local_tag}.{js_filename}")
            os.makedirs(sources_root, exist_ok=True)
            saved, fetched, failed = self._parse_and_save_sources(map_json, map_url, sources_root)
            self._append_sourcemap_report(project_root, f"JS {js_filename}: 下载并解析 SourceMap {map_url}，保存 {saved}，抓取 {fetched}，失败 {failed}")
        except Exception as e:
            self._append_sourcemap_report(project_root, f"JS {js_filename}: 处理 SourceMap 失败: {e}")

    def analyze_path_patterns(self, successful_path):
        try:
            parsed_url = urlparse(successful_path)
            path = parsed_url.path
            filename = path.split('/')[-1]
            if 'chunk' in filename:
                directory = '/'.join(path.split('/')[:-1]) + '/'
                if 'chunk' not in self.successful_path_patterns:
                    self.successful_path_patterns['chunk'] = []
                if directory not in self.successful_path_patterns['chunk']:
                    self.successful_path_patterns['chunk'].append(directory)
        except Exception as e:
            self.log.error(f"[Err] 分析路径模式时出错: {str(e)}")

    def extract_webpack_public_path(self, js_content):
        patterns = [
            r'__webpack_require__\.p\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'\.p\s*=\s*[\'"]([^\'"]+)[\'"]',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            if matches:
                return matches[0]
        return None

    def infer_path(self, original_path):
        try:
            parsed_url = urlparse(original_path)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            filename = os.path.basename(parsed_url.path)
            possible_paths = {original_path} # 使用集合自动去重

            if 'chunk' in self.successful_path_patterns:
                for directory in self.successful_path_patterns['chunk']:
                    possible_paths.add(urljoin(base_url, f"{directory}{filename}"))
            
            return list(possible_paths)
        except Exception as e:
            self.log.error(f"[Err] 推断路径时出错: {str(e)}")
            return [original_path]

    def jsBlacklist(self):
        newList = self.jsRealPaths[:]
        for jsRealPath in newList:
            res = urlparse(jsRealPath)
            domain = res.netloc.lower()
            filename = Utils().getFilename(jsRealPath).lower()
            for d in self.blacklist_domains.split(","):
                if d in domain:
                    self.jsRealPaths.remove(jsRealPath)
                    break
            for f in self.blacklistFilenames.split(","):
                if f in filename:
                    if jsRealPath in self.jsRealPaths:
                        self.jsRealPaths.remove(jsRealPath)
                    break
        return self.jsRealPaths

    def download_single_js(self, jsRealPath, tag, host, spiltId, discovery_source: Optional[DiscoverySource] = None):
        """
        优化后的单个JS下载方法
        - 增加数据库连接超时
        - 使用参数化查询防止SQL注入
        - 增强错误处理
        - 存储发现来源 (Requirements 4.1)
        
        Args:
            jsRealPath: JS file URL
            tag: Project tag
            host: Host domain
            spiltId: Split ID for chunked files
            discovery_source: The method by which this JS file was discovered
        """
        jsFilename = Utils().getFilename(jsRealPath)
        jsTag = Utils().creatTag(6)
        PATH = "tmp/" + tag + "_" + host + "/" + tag + ".db"
        db_path = os.sep.join(PATH.split('/'))
        
        # Use instance discovery_source if not provided
        source = discovery_source or self.discovery_source
        source_value = source.value if isinstance(source, DiscoverySource) else str(source)
        
        conn = None  # 确保 conn 被定义
        try:
            # 增加数据库连接超时到30秒
            conn = sqlite3.connect(db_path, timeout=30.0)
            cursor = conn.cursor()

            # 使用参数化查询检查文件是否存在
            checkSql = "SELECT * FROM js_file WHERE name=?"
            cursor.execute(checkSql, (jsFilename,))
            if cursor.fetchall():
                prefix = self._get_source_prefix(source)
                self.log.info(Utils().tellTime() + f"{prefix} 文件已存在，跳过: {jsFilename}")
                return

            # 使用参数化查询插入数据，包含discovery_source (Requirements 4.1)
            if spiltId == 0:
                sql = "INSERT INTO js_file(name,path,local,discovery_source) VALUES(?, ?, ?, ?)"
                cursor.execute(sql, (jsFilename, jsRealPath, f'{jsTag}.{jsFilename}', source_value))
            else:
                sql = "INSERT INTO js_file(name,path,local,spilt,discovery_source) VALUES(?, ?, ?, ?, ?)"
                cursor.execute(sql, (jsFilename, jsRealPath, f'{jsTag}.{jsFilename}', spiltId, source_value))
            conn.commit()

            sslFlag = int(self.options.ssl_flag)
            header = {
                'User-Agent': random.choice(self.UserAgent),
                'Accept': 'application/javascript, text/javascript, */*; q=0.01',
                self.options.head.split(':')[0]: self.options.head.split(':')[1],
            }
            # 如果用户没有通过 -d 显式指定 Referer，则默认使用原始 URL 作为 Referer，避免为空
            if 'Referer' not in header and getattr(self.options, 'url', None):
                header['Referer'] = self.options.url

            if self.options.cookie:
                header['Cookie'] = self.options.cookie

            # 更新 session 的请求细节
            self.session.headers.update(header)
            if self.proxy_data:
                self.session.proxies.update(self.proxy_data)
            self.session.verify = not sslFlag

            # --- 优化：使用 session 并配合健壮的超时和错误处理 ---
            # 超时：10秒连接，30秒读取响应。
            response = self.session.get(jsRealPath, stream=True, timeout=(10, 30))
            
            # 如果 HTTP 请求返回不成功的状态码，这将引发 HTTPError，并由重试机制处理。
            response.raise_for_status()

            self.analyze_path_patterns(jsRealPath)
            
            jsFileData = response.content
            if jsFileData.strip().lower().startswith((b'<!doctype html>', b'<html')):
                prefix = self._get_source_prefix(source)
                self.log.error(f"{prefix} [Err] 下载内容为HTML，非JS: {jsFilename}")
                return

            if not self.webpack_public_path:
                self.webpack_public_path = self.extract_webpack_public_path(jsFileData.decode('utf-8', errors='ignore'))

            file_path = f"tmp{os.sep}{tag}_{host}{os.sep}{jsTag}.{jsFilename}"
            with open(file_path, "wb") as js_file:
                js_file.write(jsFileData)
            
            # 使用参数化查询更新状态
            cursor.execute("UPDATE js_file SET success=1 WHERE local=?", (f'{jsTag}.{jsFilename}',))
            conn.commit()
            prefix = self._get_source_prefix(source)
            self.log.info(Utils().tellTime() + f"{prefix} 下载成功: {jsFilename}")

            # 尝试下载并解析 SourceMap（非阻塞关键路径）
            try:
                project_root = f"tmp{os.sep}{tag}_{host}"
                js_text = jsFileData.decode('utf-8', errors='ignore')
                self._handle_sourcemap(js_text, jsRealPath, project_root, jsTag, jsFilename)
            except Exception as e:
                self.log.debug(f"SourceMap 处理跳过: {e}")

        except requests.exceptions.RequestException as e:
            # 这将捕获所有重试失败后的错误。
            msg = str(e)
            # 去掉冗长的 URL，保留紧凑原因（例如 "404 Client Error: Not Found"）
            short = msg.split(" for url: ")[0] if " for url: " in msg else msg
            # 尝试从错误消息中提取状态码
            code_match = re.search(r"\b(\d{3})\b", short)
            if code_match:
                code = code_match.group(1)
                if code == "404":
                    human = "资源不存在(404)"
                elif code == "403":
                    human = "访问被禁止(403)"
                elif code == "500":
                    human = "服务器内部错误(500)"
                else:
                    human = f"请求失败({code})"
            else:
                human = short
            prefix = self._get_source_prefix(source)
            self.log.error(f"{prefix} [Err] 重试多次仍失败: {jsFilename} ({human})")
            if " for url: " in msg:
                self.log.debug(f"[Debug] 失败请求URL: {msg.split(' for url: ', 1)[1]}")
        except sqlite3.OperationalError as e:
            # 数据库锁定或其他操作错误
            prefix = self._get_source_prefix(source)
            if "database is locked" in str(e).lower():
                self.log.error(f"{prefix} [Err] 数据库被锁定: {jsFilename} - 建议减少并发线程数")
            else:
                self.log.error(f"{prefix} [Err] 数据库操作错误: {jsFilename}, 错误: {str(e)}")
        except Exception as e:
            prefix = self._get_source_prefix(source)
            self.log.error(f"{prefix} [Err] 下载或处理过程中发生未知错误: {jsFilename}, 错误: {str(e)}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass  # 忽略关闭时的错误

    def downloadJs(self, tag, host, spiltId):
        self.jsRealPaths = list(set(self.jsRealPaths))
        try:
            self.jsRealPaths = self.jsBlacklist()
        except Exception as e:
            self.log.error("[Err] %s" % e)

        filtered_urls = []
        for jsUrl in self.jsRealPaths:
            try:
                parsed_url = urlparse(jsUrl)
                if all([parsed_url.scheme, parsed_url.netloc]):
                    filtered_urls.append(jsUrl)
                else:
                    self.log.error(f"格式无效的URL，已忽略: {jsUrl}")
            except Exception as e:
                self.log.error(f"URL解析错误: {jsUrl}, {str(e)}")

        # --- 优化：增加并发工作线程数 ---
        # 对于像下载这样的I/O密集型任务，更多的线程可以显著提高速度。
        # 这个值可以根据网络状况和目标服务器的性能进行调整。
        max_workers = 30
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.download_single_js, jsRealPath, tag, host, spiltId, self.discovery_source) for jsRealPath in filtered_urls]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log.error(f"[Err] 一个下载任务线程出现异常: {e}")

    def creatInsideJs(self, tag, host, scriptInside, url, discovery_source: Optional[DiscoverySource] = None):
        """
        优化后的内联JS创建方法 - 增加超时和参数化查询
        
        Args:
            tag: Project tag
            host: Host domain
            scriptInside: Inline JS content
            url: Source URL
            discovery_source: The method by which this JS was discovered (Requirements 4.1)
        """
        try:
            jsRealPath = url
            jsFilename = "7777777.script.inside.html.js"
            jsTag = Utils().creatTag(6)
            PATH = "tmp/" + tag + "_" + host + "/" + tag + ".db"
            
            # Use instance discovery_source if not provided
            source = discovery_source or self.discovery_source
            source_value = source.value if isinstance(source, DiscoverySource) else str(source)
            
            # 增加超时时间
            conn = sqlite3.connect(os.sep.join(PATH.split('/')), timeout=30.0)
            cursor = conn.cursor()
            
            # 使用参数化查询，包含discovery_source (Requirements 4.1)
            sql = "INSERT INTO js_file(name,path,local,discovery_source) VALUES(?, ?, ?, ?)"
            cursor.execute(sql, (jsFilename, jsRealPath, f'{jsTag}.{jsFilename}', source_value))
            conn.commit()
            
            prefix = self._get_source_prefix(source)
            self.log.info(Utils().tellTime() + f"{prefix} 正在下载：" + jsFilename)
            file_path = f"tmp{os.sep}{tag}_{host}{os.sep}{jsTag}.{jsFilename}"
            with open(file_path, "wb") as js_file:
                js_file.write(str.encode(scriptInside))
            
            # 使用参数化查询更新状态
            cursor.execute("UPDATE js_file SET success=1 WHERE local=?", (f'{jsTag}.{jsFilename}',))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                self.log.error(f"[Err] 数据库被锁定 - {e}")
            else:
                self.log.error(f"[Err] 数据库操作错误 - {e}")
        except Exception as e:
            self.log.error("[Err] %s" % e)