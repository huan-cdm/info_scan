#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import re
import requests
import warnings
import sqlite3
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from lib.common.utils import Utils, resolve_js_url
from lib.Database import DatabaseType
from lib.DownloadJs import DownloadJs
from lib.common.CreatLog import creatLog
from lib.common.cmdline import CommandLines
from lib.IframeParser import IframeParser
from lib.InlinePatternParser import InlinePatternParser
from lib.common.models import DiscoverySource


class ParseJs():
    def __init__(self, projectTag, url, options):
        warnings.filterwarnings('ignore')
        self.url = self._normalize_url(url)
        self.jsPaths = []
        self.jsRealPaths = []
        self.jsPathList = []
        self.projectTag = projectTag
        self.options = options
        self.proxy_data = Utils().build_proxies(self.options.proxy)
        self.base_url = self.url  # 新增基路径变量
        self._init_headers()
        DatabaseType(self.projectTag).createProjectDatabase(self.url, 1, "0")
        self.log = creatLog().get_logger()
        
        # Track JS paths by discovery source (Requirements 4.1)
        self.js_by_source = {
            DiscoverySource.STATIC_HTML: [],
            DiscoverySource.IFRAME: [],
            DiscoverySource.INLINE_PATTERN: [],
        }
        
        # Initialize IframeParser (Requirements 1.1)
        # Get max_iframe_depth from command line options, default to 3
        max_iframe_depth = getattr(options, 'max_iframe_depth', 3)
        self.iframe_parser = IframeParser(
            base_url=self.url,
            options=options,
            max_depth=max_iframe_depth
        )
        
        # Initialize InlinePatternParser (Requirements 3.1)
        self.inline_pattern_parser = InlinePatternParser(base_url=self.url)

    def _normalize_url(self, url):
        """规范化入口 URL，修复终端中使用 \\# 逃逸导致路径被解析为 /%5C 的问题。
        例如: https://host/\\#/login -> https://host/#/login
        """
        try:
            if not url:
                return url
            # 处理终端传入的 \\# 形式（用于避免 shell 将 # 解析为注释）
            url = url.replace('\\#', '#')
            return url
        except Exception:
            return url

    def _init_headers(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0",
            self.options.head.split(':')[0]: self.options.head.split(':')[1]
        }
        if self.options.cookie:
            headers["Cookie"] = self.options.cookie
        self.header = headers

    def _extract_base_url(self, html_content):
        """从HTML中提取<base>标签修正基路径"""
        soup = BeautifulSoup(html_content, "html.parser")
        base_tag = soup.find("base")
        if base_tag and base_tag.get("href"):
            return urljoin(self.url, base_tag.get("href"))
        return self.url

    def _process_script_tags(self, soup):
        """处理script标签的通用逻辑"""
        for item in soup.find_all("script"):
            # 处理外部JS
            if js_path := item.get("src"):
                self.jsPaths.append(js_path)
            
            # 处理内联JS
            if js_code := item.text.encode():
                self._save_inline_js(js_code)

    def _save_inline_js(self, js_code):
        """保存内联JS到数据库，并提取Webpack chunk映射"""
        js_tag = Utils().creatTag(6)
        res = urlparse(self.url)
        domain = res.netloc.replace(":", "_")
        db_path = os.path.join("tmp", f"{self.projectTag}_{domain}", f"{self.projectTag}.db")
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO js_file(name, path, local) VALUES(?, ?, ?)",
                (f"{js_tag}.js", self.url, f"{js_tag}.js")
            )
            file_path = os.path.join("tmp", f"{self.projectTag}_{domain}", f"{js_tag}.js")
            with open(file_path, "wb") as f:
                f.write(js_code)
            cursor.execute("UPDATE js_file SET success = 1 WHERE local=?", (f"{js_tag}.js",))
            conn.commit()
        
        # === 新增：从内联JS中提取Webpack chunk映射 ===
        try:
            js_text = js_code.decode('utf-8', errors='ignore')
            self._extract_webpack_chunks_from_inline(js_text, domain)
        except Exception as e:
            self.log.debug(f"提取内联JS中的chunk映射时出错: {e}")

    def requestUrl(self):
        """
        优化后的URL请求方法
        - 增加重试机制
        - 详细的错误分类处理
        - 更好的用户提示
        - 集成iframe递归解析和内联模式检测 (Requirements 1.1, 3.1)
        """
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                response = self._fetch_url()
                self.base_url = self._extract_base_url(response.text)  # 更新基路径
                soup = BeautifulSoup(response.text.replace("", ""), "html.parser")
                
                # Process static script tags - these go to STATIC_HTML source
                self._process_script_tags(soup)
                self._process_link_tags(soup)
                self._process_dynamic_js(soup, response.text)
                
                # Track static HTML JS paths (Requirements 4.1)
                self.js_by_source[DiscoverySource.STATIC_HTML].extend(self.jsPaths)
                self.jsPaths = []  # Clear for next source
                
                # Process iframes recursively (Requirements 1.1, 1.2)
                self._process_iframes(soup)
                
                # Process inline JS patterns (Requirements 3.1, 3.4)
                self._process_inline_patterns(soup)
                
                # Download JS files by discovery source (Requirements 4.1)
                self._download_js_by_source()
                return  # 成功则返回
                
            except requests.exceptions.Timeout as e:
                retry_count += 1
                if retry_count < max_retries:
                    self.log.warning(f"[警告] 请求超时，正在重试 ({retry_count}/{max_retries})...")
                    time.sleep(2 * retry_count)
                    continue
                else:
                    self.log.error(f"[Critical Error] 请求超时（已达最大重试次数）: {str(e)}")
                    raise
                    
            except requests.exceptions.ConnectionError as e:
                retry_count += 1
                if retry_count < max_retries:
                    self.log.warning(f"[警告] 连接失败，正在重试 ({retry_count}/{max_retries})...")
                    time.sleep(2 * retry_count)
                    continue
                else:
                    self.log.error(f"[Critical Error] 连接失败（已达最大重试次数）: {str(e)}")
                    self.log.error("[提示] 请检查：1) 目标URL是否可访问 2) 网络连接是否正常 3) 代理设置是否正确")
                    raise
                    
            except requests.exceptions.ProxyError as e:
                self.log.error(f"[Critical Error] 代理错误: {str(e)}")
                self.log.error("[提示] 请检查代理配置是否正确")
                raise
                
            except Exception as e:
                self.log.error(f"[Critical Error] 主解析流程失败: {str(e)}")
                raise

    def _fetch_url(self):
        """封装请求逻辑"""
        ssl_flag = int(self.options.ssl_flag)
        kwargs = {
            "url": self.url,
            "headers": self.header,
            "allow_redirects": True,
            # --- 优化：添加了健壮的超时设置 ---
            "timeout": (10, 30) # 10秒连接，30秒读取
        }
        if self.proxy_data:
            kwargs["proxies"] = self.proxy_data
        if ssl_flag:
            kwargs["verify"] = False
        response = requests.get(**kwargs)
        
        # 处理重定向
        if response.url != self.url:
            self.log.info(f"{Utils().tellTime()} 重定向: {self.url} -> {response.url}")
            self.url = response.url
        return response

    def _process_link_tags(self, soup):
        """处理link标签"""
        for item in soup.find_all("link"):
            if (href := item.get("href")) and href.endswith(".js"):
                self.jsPaths.append(href)

    def _process_iframes(self, soup):
        """
        Process iframe/frame tags and recursively discover JS files.
        
        Calls IframeParser.extract_iframe_urls to find all iframes,
        then calls IframeParser.parse_iframe_recursive for each URL
        to discover JS files within iframes.
        
        Requirements: 1.1, 1.2, 4.1
        
        Args:
            soup: BeautifulSoup parsed HTML content
        """
        # Check if iframe parsing is disabled
        if getattr(self.options, 'no_iframe', False):
            self.log.debug("[ParseJs] Iframe parsing disabled via --no-iframe flag")
            return
        
        try:
            # Update iframe parser's base URL to current page
            self.iframe_parser.base_url = self.base_url
            
            # Extract iframe URLs from the HTML
            iframe_urls = self.iframe_parser.extract_iframe_urls(soup)
            
            if iframe_urls:
                self.log.info(f"{Utils().tellTime()} [IFRAME] 发现 {len(iframe_urls)} 个iframe/frame")
            
            # Process each iframe recursively
            for iframe_url in iframe_urls:
                try:
                    # Parse iframe and get discovered JS URLs
                    discovered_js = self.iframe_parser.parse_iframe_recursive(
                        url=iframe_url,
                        depth=0,
                        parent_url=self.base_url
                    )
                    
                    # Track iframe-discovered JS separately (Requirements 4.1)
                    if discovered_js:
                        self.log.debug(f"  → iframe中发现 {len(discovered_js)} 个JS")
                        self.js_by_source[DiscoverySource.IFRAME].extend(discovered_js)
                        
                except Exception as e:
                    self.log.warning(f"[ParseJs] Error processing iframe {iframe_url}: {str(e)}")
                    continue
                    
        except Exception as e:
            self.log.error(f"[ParseJs] Error in _process_iframes: {str(e)}")

    def _process_dynamic_js(self, soup, html_content):
        """处理动态生成的JS路径"""
        try:
            js_in_script = self.scriptCrawling(html_content)
            self.jsPaths.extend(js_in_script)
        except Exception as e:
            self.log.error(f"[Error] scriptCrawling失败: {str(e)}")

    def _process_inline_patterns(self, soup):
        """
        Process inline JavaScript to detect dynamic script loading patterns.
        
        Calls InlinePatternParser.extract_dynamic_urls on inline JS content
        to find dynamically loaded scripts. Adds discovered URLs to:
        - iframe queue if iframe.src pattern detected
        - JS list if script.src pattern detected
        
        Requirements: 3.1, 3.4, 4.1
        
        Args:
            soup: BeautifulSoup parsed HTML content
        """
        try:
            # Update inline pattern parser's base URL
            self.inline_pattern_parser.base_url = self.base_url
            
            # Collect all inline JS content
            inline_js_content = []
            for script in soup.find_all("script"):
                # Only process scripts without src (inline scripts)
                if not script.get("src") and script.string:
                    inline_js_content.append(script.string)
            
            if not inline_js_content:
                return
            
            # Combine all inline JS for analysis
            combined_js = "\n".join(inline_js_content)
            
            # Process inline JS and get discovered URLs
            js_urls, iframe_urls = self.inline_pattern_parser.process_inline_js(
                js_content=combined_js,
                parent_url=self.base_url
            )
            
            # Track inline-pattern-discovered JS separately (Requirements 4.1)
            if js_urls:
                self.log.info(f"{Utils().tellTime()} [PATTERN] 发现 {len(js_urls)} 个动态加载JS")
                self.js_by_source[DiscoverySource.INLINE_PATTERN].extend(js_urls)
            
            # Process discovered iframe URLs through iframe parser
            if iframe_urls and not getattr(self.options, 'no_iframe', False):
                self.log.debug(f"  → 发现 {len(iframe_urls)} 个动态iframe")
                for iframe_url in iframe_urls:
                    try:
                        discovered_js = self.iframe_parser.parse_iframe_recursive(
                            url=iframe_url,
                            depth=0,
                            parent_url=self.base_url
                        )
                        if discovered_js:
                            # Track as iframe-discovered since they come from iframes
                            self.js_by_source[DiscoverySource.IFRAME].extend(discovered_js)
                    except Exception as e:
                        self.log.warning(f"[ParseJs] Error processing dynamic iframe {iframe_url}: {str(e)}")
                        
        except Exception as e:
            self.log.error(f"[ParseJs] Error in _process_inline_patterns: {str(e)}")

    def dealJs(self, js_paths, discovery_source: DiscoverySource = DiscoverySource.STATIC_HTML):
        """
        生成JS绝对路径并下载
        
        Uses resolve_js_url to properly handle:
        - Absolute URLs (returned unchanged)
        - Protocol-relative URLs (prepend protocol from base_url)
        - Relative paths (join with base_url)
        
        Args:
            js_paths: List of JS paths to process
            discovery_source: The method by which these JS files were discovered
                             (Requirements 2.1, 4.1)
        """
        parsed = urlparse(self.base_url)
        
        for path in js_paths:
            resolved_url = resolve_js_url(path, self.base_url)
            if resolved_url:  # Skip empty results (special protocols, empty paths)
                self.jsRealPaths.append(resolved_url)
        
        self.log.info(f"{Utils().tellTime()} [HTML] 发现 {len(self.jsRealPaths)} 个JS文件")
        domain = parsed.netloc.replace(":", "_")
        DownloadJs(self.jsRealPaths, self.options, discovery_source).downloadJs(self.projectTag, domain, 0)
        self._process_external_js(domain)

    def _process_external_js(self, domain):
        """处理外部输入的JS"""
        if hasattr(self.options, 'js') and self.options.js:
            ext_js = self.options.js
            DownloadJs(ext_js.split(','), self.options).downloadJs(self.projectTag, domain, 0)

    def _download_js_by_source(self):
        """
        Download JS files grouped by discovery source.
        
        Downloads JS files from each discovery source with the appropriate
        source tracking for logging and database storage.
        
        Uses resolve_js_url to properly handle:
        - Absolute URLs (returned unchanged, preserving iframe-discovered URLs)
        - Protocol-relative URLs (prepend protocol from base_url)
        - Relative paths (join with base_url)
        
        Requirements: 1.1, 2.1, 4.1
        """
        parsed = urlparse(self.base_url)
        domain = parsed.netloc.replace(":", "_")
        
        total_count = 0
        all_downloads = []  # 收集所有待下载的JS
        
        # Process each discovery source - first collect all URLs
        for source, js_paths in self.js_by_source.items():
            if not js_paths:
                continue
            
            # Convert paths to absolute URLs using unified resolve_js_url function
            # This preserves absolute URLs (e.g., from iframes) unchanged
            real_paths = []
            for path in js_paths:
                resolved_url = resolve_js_url(path, self.base_url)
                if resolved_url:  # Skip empty results (special protocols, empty paths)
                    real_paths.append(resolved_url)
            
            if real_paths:
                all_downloads.append((source, real_paths))
                total_count += len(real_paths)
        
        # Output summary first, then download
        self.log.info(f"{Utils().tellTime()} [静态解析] 共发现 {total_count} 个JS文件")
        
        # Now download all collected JS files
        for source, real_paths in all_downloads:
            DownloadJs(real_paths, self.options, source).downloadJs(self.projectTag, domain, 0)
        
        # Process external JS if provided
        self._process_external_js(domain)

    def _extract_webpack_chunks_from_inline(self, js_text, domain):
        """从内联JS中提取Webpack chunk映射并添加到下载队列"""
        # 兼容任意变量名的 u 属性：l.u / t.u / i.u ...，并允许命名型 chunkId
        # 形态：return "js/" + e + "." + { nameOrId: hash, ... }[e] + ".js"
        chunk_map_pattern = r'[A-Za-z_$][\w$]*\.u\s*=\s*function\([^)]+\)\s*\{[\s\S]*?return\s*["\']([^"\']+)["\'][\s\S]*?\{([^}]+)\}'
        chunk_map_matches = re.findall(chunk_map_pattern, js_text, flags=re.S)

        if chunk_map_matches:
            for base_path, chunk_ids in chunk_map_matches:
                self.log.info(f"[+] 发现Webpack chunk映射表")
                # 先尝试命名型键（支持 src_views_xxx 这类命名），再回退到纯数字键
                named_entries = re.findall(r'["\']?([A-Za-z0-9_\/\-]+)["\']?\s*:\s*["\']([a-f0-9]{8,16})["\']', chunk_ids, flags=re.I)
                num_entries = re.findall(r'(\d+)\s*:\s*["\']([a-f0-9]{8,16})["\']', chunk_ids, flags=re.I)
                chunk_entries = named_entries or num_entries

                self.log.info(f"  → 解析到 {len(chunk_entries)} 个异步chunk")

                for chunk_key, chunk_hash in chunk_entries:
                    # 构造完整的chunk路径: js/<nameOrId>.<hash>.js
                    chunk_filename = f"{base_path}{chunk_key}.{chunk_hash}.js"
                    self.jsPaths.append(chunk_filename)

    def scriptCrawling(self, demo):
        """从内联JS中提取路径"""
        soup = BeautifulSoup(demo, "html.parser")
        found_paths = []
        for script in soup.find_all("script"):
            if script_content := script.string:
                found_paths.extend(re.findall(r'src=["\'](.*?\.js)', str(script_content)))
        return list(set(found_paths))

    def parseJsStart(self):
        self.requestUrl()