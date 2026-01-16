# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import time
from urllib.parse import urlparse
from lib.ParseJs import ParseJs
from lib.common.utils import Utils
from lib.Database import DatabaseType
from lib.CheckPacker import CheckPacker
from lib.common.beautyJS import BeautyJs
from lib.Recoverspilt import RecoverSpilt
from lib.common.CreatLog import creatLog,log_name,logs
from lib.JsFinder.JsFinderModule import JsFinderModule  #引入js文件扫描模块
from lib.common.models import DiscoverySource, JsDiscoveryRecord
from lib.DownloadJs import DownloadJs


class Project():

    def __init__(self, url, options):
        self.url = url
        self.codes = {}
        self.options = options
        # 确保每个URL实例使用自己的projectTag
        from lib.common.CreatLog import logs
        self.projectTag = logs

    def parseStart(self):
        # --- 修复：移除所有关于finder_report_path的返回值逻辑 ---
        projectTag = self.projectTag
        log = creatLog().get_logger()
        if self.options.silent != None:
            print("[TAG]" + projectTag)
        DatabaseType(projectTag).createDatabase()
        
        # Check if browser mode is enabled (Requirements 2.1)
        browser_mode_enabled = getattr(self.options, 'browser', False)
        browser_discovered_urls = []
        
        if browser_mode_enabled:
            log.info("[+] 浏览器模式已启用，正在使用Playwright捕获动态JS...")
            browser_discovered_urls = self._run_browser_mode()
        
        # Run static parsing with ParseJs
        ParseJs(projectTag, self.url, self.options).parseJsStart()
        
        # Merge browser-discovered URLs with static-discovered URLs (Requirements 2.3, 4.1)
        if browser_discovered_urls:
            self._merge_browser_discovered_urls(browser_discovered_urls, projectTag)
        
        path_log = os.path.abspath(log_name)
        path_db = os.path.abspath(DatabaseType(projectTag).getPathfromDB() + projectTag + ".db")
        log.info("[+] " + "缓存文件路径：" + path_db)  #显示数据库文件路径
        log.info("[+] " + "日志文件路径：" + path_log) #显示log文件路径
        checkResult = CheckPacker(projectTag, self.url, self.options).checkStart()
        # 彻底放开方案：无论是否命中打包器指纹，都运行异步JS恢复引擎
        if checkResult == 1:
            creatLog().get_logger().info("[v] " + "恭喜，这个站点很可能是通过前端打包器构建的！")
        elif checkResult == 777:
            creatLog().get_logger().info("[!] " + "前端打包器检测模块执行出错，将仍然尝试异步JS分析...")
        else:
            creatLog().get_logger().info("[!] " + "未检测到前端打包器特征，将仍然尝试异步JS分析（可能是现有规则不足或未使用常见打包器）")

        # 无论检测结果如何，都运行 RecoverSpilt
        RecoverSpilt(projectTag, self.options).recoverStart()

        # 接口提取 + -b 组合 URL 逻辑（只使用手动指定的 baseurl）
        try:
            # 原先这里调用 Apicollect 使用 -b/baseurl 进行接口组合，现已移除该功能
            pass
        except Exception as e:
            creatLog().get_logger().error(f"[Err] 接口收集模块执行失败: {e}")


        # CI Packer-Fuzzer 353232 + -b 27 URL 73594278346236 baseurl4
        try:
            # 原先这里调用 Apicollect 使用 -b/baseurl 进行接口组合，现已移除该功能
            pass
        except Exception as e:
            creatLog().get_logger().error(f"[Err] 35382362392388613594: {e}")


        # 如果启用了finder参数，执行JavaScript敏感信息扫描
        if hasattr(self.options, 'finder') and self.options.finder:
            creatLog().get_logger().info("[+] " + "已启用JavaScript敏感信息扫描...")
            js_finder = JsFinderModule(projectTag, self.options)

            # --- 修复：恢复原始的调用方式，不再关心返回值 ---
            scan_result = js_finder.start_scan()

            if scan_result:
                creatLog().get_logger().info("[v] " + "JavaScript敏感信息扫描完成")
            else:
                creatLog().get_logger().info("[!] " + "JavaScript敏感信息扫描过程中出现问题或未发现")

        # Output discovery summary (Requirements 4.3)
        self._output_discovery_summary(projectTag)
        
        creatLog().get_logger().info("[v] " + "感谢您的使用！")

        # --- 修复：函数末尾不再返回任何值 ---

    def _run_browser_mode(self):
        """
        Run browser mode to capture dynamically loaded JS files.
        
        Uses BrowserMode with Playwright to intercept network requests
        and capture JS files that require JavaScript execution to discover.
        
        Returns:
            List of discovered JS file URLs from browser mode
        
        Requirements: 2.1
        """
        log = creatLog().get_logger()
        discovered_urls = []
        
        try:
            from lib.BrowserMode import BrowserMode, PlaywrightNotInstalledError
            
            try:
                browser_mode = BrowserMode(self.options)
                discovered_urls = browser_mode.scan(self.url)
                # 日志输出移至 _merge_browser_discovered_urls 统一处理
            except PlaywrightNotInstalledError as e:
                log.error(f"[BROWSER] Playwright未安装，回退到静态解析模式")
            except Exception as e:
                log.error(f"[BROWSER] 执行失败: {str(e)}")
                log.info("[BROWSER] 回退到静态解析模式")
                
        except ImportError as e:
            log.error(f"[BrowserMode] 无法导入BrowserMode模块: {str(e)}")
        
        return discovered_urls

    def _merge_browser_discovered_urls(self, browser_urls, projectTag):
        """
        Merge browser-discovered URLs with static-discovered URLs.
        
        Deduplicates URLs from both sources and tracks discovery source
        for each URL. Downloads any new JS files discovered by browser mode.
        
        Args:
            browser_urls: List of JS URLs discovered by browser mode
            projectTag: Project tag for database operations
        
        Requirements: 2.3, 4.1
        """
        log = creatLog().get_logger()
        
        if not browser_urls:
            log.info("[BROWSER] 扫描完成，未发现JS文件")
            return
        
        try:
            from lib.DownloadJs import DownloadJs
            
            # Get domain for file storage
            parsed = urlparse(self.url)
            domain = parsed.netloc.replace(":", "_")
            
            # Get existing URLs from database to deduplicate
            existing_urls = self._get_existing_js_urls(projectTag, domain)
            
            # Filter out already discovered URLs
            new_urls = []
            for url in browser_urls:
                if url not in existing_urls:
                    new_urls.append(url)
                    existing_urls.add(url)  # Add to set to prevent duplicates within browser_urls
            
            if new_urls:
                log.info(f"[BROWSER] 扫描完成，发现 {len(new_urls)} 个新JS文件")
                # Download new JS files with browser intercept source tracking (Requirements 4.1)
                DownloadJs(new_urls, self.options, DiscoverySource.BROWSER_INTERCEPT).downloadJs(projectTag, domain, 0)
            else:
                log.info(f"[BROWSER] 扫描完成，发现 {len(browser_urls)} 个JS文件（均已存在）")
                
        except Exception as e:
            log.error(f"[BROWSER] 合并URL出错: {str(e)}")

    def _get_existing_js_urls(self, projectTag, domain):
        """
        Get existing JS URLs from the database for deduplication.
        
        Args:
            projectTag: Project tag for database operations
            domain: Domain string for database path
        
        Returns:
            Set of existing JS URLs
        
        Requirements: 2.3, 4.1
        """
        import sqlite3
        
        existing_urls = set()
        
        try:
            db_path = os.path.join("tmp", f"{projectTag}_{domain}", f"{projectTag}.db")
            
            if os.path.exists(db_path):
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT path FROM js_file")
                    rows = cursor.fetchall()
                    for row in rows:
                        if row[0]:
                            existing_urls.add(row[0])
        except Exception as e:
            creatLog().get_logger().debug(f"[BrowserMode] 读取现有URL时出错: {str(e)}")
        
        return existing_urls

    def _output_discovery_summary(self, projectTag):
        """
        Output a summary of JS files discovered by each method.
        
        Counts JS files by discovery source and outputs a summary
        at the end of the scan.
        
        Args:
            projectTag: Project tag for database operations
        
        Requirements: 4.3
        """
        import sqlite3
        
        log = creatLog().get_logger()
        
        try:
            # Get domain from URL
            parsed = urlparse(self.url)
            domain = parsed.netloc.replace(":", "_")
            
            db_path = os.path.join("tmp", f"{projectTag}_{domain}", f"{projectTag}.db")
            
            if not os.path.exists(db_path):
                log.debug("[Summary] 数据库文件不存在，跳过摘要生成")
                return
            
            with sqlite3.connect(db_path, timeout=30.0) as conn:
                cursor = conn.cursor()
                
                # Check if discovery_source column exists
                cursor.execute("PRAGMA table_info(js_file)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'discovery_source' not in columns:
                    # Old database schema, skip summary
                    return
                
                # Count by discovery source (for internal tracking only)
                cursor.execute("""
                    SELECT discovery_source, COUNT(*) 
                    FROM js_file 
                    GROUP BY discovery_source
                """)
                counts = cursor.fetchall()
                
                # Get total count
                cursor.execute("SELECT COUNT(*) FROM js_file")
                total = cursor.fetchone()[0]
                
                # Build summary (stored for potential future use, not logged)
                source_counts = {}
                for source, count in counts:
                    source_counts[source or 'static_html'] = count
                
                # Summary output removed per user request
                
        except Exception as e:
            log.debug(f"[Summary] 生成摘要时出错: {str(e)}")