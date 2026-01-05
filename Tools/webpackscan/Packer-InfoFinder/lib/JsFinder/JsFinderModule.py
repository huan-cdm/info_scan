#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import re
import os
import json
import base64
import html # 修复: 导入 html 模块
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Set
from collections import Counter, defaultdict

from lib.common.CreatLog import creatLog
from lib.common.utils import Utils
from lib.Database import DatabaseType
import multiprocessing

class JsFinderModule:
    def __init__(self, projectTag, options):
        self.projectTag = projectTag
        self.options = options
        self.log = creatLog().get_logger()

        # --- 修复：确保每个项目的输出目录是唯一的 ---
        self.output_directory = os.path.join(DatabaseType(self.projectTag).getPathfromDB(), 'finder_results')

        self.regex_patterns = self.load_regex_patterns()

        self.compiled_regex_patterns = {name: re.compile(pattern, re.MULTILINE | re.DOTALL)
                                       for name, pattern in self.regex_patterns.items()}
        try:
            from urllib.parse import urlparse
            parsed = urlparse(getattr(self.options, 'url', '') or '')
            self.target_netloc = (parsed.netloc or '').lower()
            self.target_host_no_port = self.target_netloc.split(':')[0]
            labels = [p for p in self.target_host_no_port.split('.') if p]
            self.base_domain = '.'.join(labels[-2:]) if len(labels) >= 2 else self.target_host_no_port
        except Exception:
            self.target_netloc = ''
            self.target_host_no_port = ''
            self.base_domain = ''

        self.blacklist_domains = self.load_blacklist_domains()
        # 末段词表/资源聚合的配置
        self._verbs = {'add','create','new','update','edit','change','delete','remove','clear','reset','list','get','query','search','detail','info','show','save','export','import','upload','download'}
        self._suffix_detail_like = {'detail','info','list','page','pages','all'}
        self._stop_tokens = {'api','tmp','tmpl','tmple','template','v1','v2','v3'}
        self._synonyms = {'companty':'company','permissions':'permission','menus':'menu','roles':'role','users':'user','usernames':'username','pwd':'password'}


    def load_regex_patterns(self):
        """加载正则表达式模式"""
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config.json')
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                return config.get('regex_patterns', {})
        except Exception as e:
            self.log.error(f"加载配置文件失败: {e}")

        return {
            # === 云服务 AccessKey ===
            'Oss云存储桶': r"(?i)(?:access[-_]?key[-_]?(?:id|secret)?|secret[-_]?(?:access)?[-_]?key)\s*[:=]\s*['\"]?([0-9a-zA-Z\-_=]{6,128})['\"]?",
            "aliyun_oss_url": r"(?<![a-zA-Z0-9-])[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.oss[-\w]*\.aliyuncs\.com(?![a-zA-Z0-9-])",
            'Aliyun_AccessKeyId': r'LTAI[A-Za-z\d]{12,30}',
            'Tencent_SecretId': r'AKID[A-Za-z\d]{13,40}',
            'JDCloud_AccessKey': r'JDC_[0-9A-Z]{25,40}',
            'AWS_AccessKeyId': r'["\']?(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']?',
            'Aliyun_TemporaryKey_1': r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}',
            'Aliyun_TemporaryKey_2': r'AKLT[a-zA-Z0-9-_]{16,28}',
            'Google_API_Key': r'AIza[0-9A-Za-z_\-]{35}',

            # === Token/JWT ===
            'json_web_token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.?[A-Za-z0-9-_.+/=]*',
            'HTTP_Bearer_Token': r'[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}',
            'HTTP_Basic_Auth_Header': r'[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}',
            'HTTP_Authorization_Header': r'["\'\[]*[Aa]uthorization["\'\]]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?',

            # === Git/代码托管平台 ===
            'GitLab_PAT': r'glpat-[a-zA-Z0-9\-=_]{20,22}',
            'Github_PAT_New': r'(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}',
            "Github_Token": r"(?i)github[-_]?token\s*[:=]\s*['\"]?(gh[psuro]_[0-9a-zA-Z]{36,})['\"]?",

            # === 第三方服务 ===
            'Basic Auth Credentials': r'(?<=://)[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}',
            'Cloudinary Basic Auth': r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
            "LinkedIn Secret Key": r"(?i)linkedin[-_]?secret\s*[:=]\s*['\"][0-9a-zA-Z]{16}['\"]",
            'Mailchamp API Key': r'(?i)[0-9a-f]{32}-us\d{1,2}',
            'Mailgun API Key': r'(?i)key-[0-9a-zA-Z]{32}',
            'APID_Token': r'APID[a-zA-Z0-9]{32,42}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}',
            'Stripe API Key': r'(?i)[rs]k_(?:live|test)_[0-9a-zA-Z]{24,}',

            # === 国内平台 ===
            'WeChat_AppID': r'["\'](wx[a-z0-9]{15,18})["\']',
            'WeCom_CorpID': r'["\'](ww[a-z0-9]{15,18})["\']',
            'WeChat_gh_ID': r'["\'](gh_[a-z0-9]{11,13})["\']',
            'Webhook_QY_Weixin': r'https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}',
            'Webhook_DingTalk': r'https://oapi\.dingtalk\.com/robot/send\?access_token=[a-z0-9]{50,80}',
            'Webhook_Feishu': r'https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}',

            # === 个人敏感信息 ===
            "国内手机号码": r'(?<!\d)((?:(?:\+|00)?86[-\s]?)?1[3-9]\d{9})(?!\d)',
            "身份证号码": r'(?<!\d)(?!0{6,}|1{6,})([1-6]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)',

            # === 敏感配置/凭证 ===
            '敏感配置信息': r"(?i)(?:^|[^\w])(?:appkey|secret|token|auth|access|admin|VideoWebPlugin|playMode|snapDir|SnapDir|videoDir)[\w]{0,10}\s*[:=]\s*(?:[^,\}\s;]+|['\"].*?['\"])",
            "Password": r"(?i)[\w.'\"]*[Pp](?:ass|wd|asswd|assword)[\w'\"]*\s*[:=]\s*['\"](?!null|undefined|true|false|\s*['\"])([^'\"]+)['\"]",
            "Username/Account": r"(?i)['\"]?[\w.]*(?:user[-_]?(?:name|id)?|account[-_]?(?:name|id)?|login[-_]?(?:name|id)?|admin[-_]?(?:name|id)?|created?[-_]?(?:by|r|on|at)|updated?[-_]?(?:by|r|on|at)|creator|operator)[\w]*['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]",

            # === 数据库连接 ===
            'JDBC_Connection': r'jdbc:[a-z:]+://[a-zA-Z0-9.\-_:;=/@?,&]+',
            'MongoDB_URI': r'mongodb(?:\+srv)?://[a-zA-Z0-9.\-_:;=/@?,&%]+',
            'Redis_URI': r'redis://[a-zA-Z0-9.\-_:;=/@?,&%]+',

            # === 私钥/证书 ===
            'Private_Key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            'Certificate': r'-----BEGIN\s+CERTIFICATE-----'
        }

    def find_matches(self, content: str, filename: str) -> Dict[str, List[Tuple[str, str, str]]]:
        """在JavaScript内容中查找匹配的敏感信息"""
        matches = {}
        lines = content.splitlines()

        for pattern_name, compiled_pattern in self.compiled_regex_patterns.items():
            pattern_matches = set()
            try:
                for match in compiled_pattern.finditer(content):
                    matched_text = match.group(0)
                    start_pos = match.start()

                    line_num = content[:start_pos].count('\n') + 1

                    context_start = max(0, start_pos - 300)
                    context_end = min(len(content), start_pos + len(matched_text) + 300)
                    context = content[context_start:context_end].strip()

                    context = context.replace('\n', ' ').replace('\r', ' ')

                    pattern_matches.add((
                        matched_text,
                        f"{filename}:Line {line_num}",
                        context
                    ))
            except re.error as e:
                self.log.error(f"正则表达式 '{pattern_name}' 无效: {e}")
                continue

            if pattern_matches:
                matches[pattern_name] = list(pattern_matches)

        return matches

    def extract_paths(self, content: str, filename: str) -> Tuple[List[str], List[str]]:
        """从JavaScript内容中提取路径"""
        paths = set()
        path_to_file_mapping = []

        path_patterns = [
            # 匹配以/或http://开头的路径
            r'''['"](?:/|https?://)[^\s'"]+['"]''',
            # 匹配 src/href/url/api/endpoint/baseUrl 等字段
            r'''(?i)(?:src|href|url|api|endpoint|baseUrl|baseURL|apiUrl|apiURL|requestUrl|serverUrl)\s*[:=]\s*['"][^'"]+['"]''',
            # 匹配 path/route/uri 等字段
            r'''(?i)(?:path|route|uri|URI|pathname)\s*[:=]\s*['"][^'"]+['"]''',
            # 匹配 fetch/axios/ajax 调用中的URL
            r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax)\s*\(\s*['"]([^'"]+)['"]''',
            # 匹配 window.location 相关
            r'''window\.location\.(?:href|pathname)\s*=\s*['"]([^'"]+)['"]'''
        ]

        for pattern in path_patterns:
            for match in re.finditer(pattern, content):
                path = match.group(0).strip('\'"')
                if path.startswith(('/', 'http://', 'https://') ) and not path.endswith(('.js', '.css')):
                    is_acceptable = True
                    if path.startswith(('http://', 'https://')):
                        try:
                            from urllib.parse import urlparse
                            p = urlparse(path)
                            host = (p.netloc or '').lower()
                            host_no_port = host.split(':')[0]
                            if host_no_port in self.blacklist_domains:
                                is_acceptable = False
                            elif not self.is_first_party_host(host_no_port):
                                is_acceptable = False
                        except Exception:
                            is_acceptable = False
                    if is_acceptable:
                        paths.add(path)
                        path_to_file_mapping.append(f"{filename}----{path}")

        return sorted(paths), path_to_file_mapping

    def load_blacklist_domains(self) -> Set[str]:
        domains: Set[str] = set()
        try:
            from configparser import ConfigParser
            cfg = ConfigParser()
            cfg.read(os.path.join(os.getcwd(), 'config.ini'), encoding='utf-8')
            if cfg.has_section('blacklist') and cfg.has_option('blacklist', 'domain'):
                raw = cfg.get('blacklist', 'domain')
                for item in raw.split(','):
                    d = item.strip().lower()
                    if d:
                        domains.add(d)
        except Exception:
            pass
        return domains

    def is_first_party_host(self, host_no_port: str) -> bool:
        if not host_no_port:
            return False
        if self.target_host_no_port and host_no_port == self.target_host_no_port:
            return True
        if self.base_domain and (host_no_port == self.base_domain or host_no_port.endswith('.' + self.base_domain)):
            return True
        return False

    def process_js_file(self, file_path: str) -> Tuple[Dict, List, List]:
        """处理单个JavaScript文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
        except Exception as e:
            self.log.error(f"无法读取文件 {file_path}: {e}")
            return {}, [], []

        filename = os.path.basename(file_path)
        matches = self.find_matches(content, filename)
        unique_paths, path_mappings = self.extract_paths(content, filename)
        return matches, unique_paths, path_mappings

    def process_js_files(self, js_files_dir: str) -> None:
        """处理目录中的所有JavaScript文件与由SourceMap还原的源码"""
        if not os.path.exists(js_files_dir):
            self.log.error(f"目录不存在: {js_files_dir}")
            return False

        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        # 统计原始与 SourceMap 还原文件，避免重复计数
        source_exts = ('.js', '.jsx', '.ts', '.tsx', '.vue')
        sm_sources_root = os.path.join(js_files_dir, 'sourcemaps', 'sources')

        original_paths_set = set()
        sm_paths_set = set()

        for root, _, files in os.walk(js_files_dir):
            # 跳过 SourceMap 还原目录，避免与后续统计重复
            if os.path.exists(sm_sources_root) and root.startswith(sm_sources_root):
                continue
            for file in files:
                if file.endswith(source_exts):
                    original_paths_set.add(os.path.join(root, file))

        if os.path.exists(sm_sources_root):
            for root, _, files in os.walk(sm_sources_root):
                for file in files:
                    if file.endswith(source_exts):
                        sm_paths_set.add(os.path.join(root, file))

        # 合并去重
        total_paths_set = original_paths_set | sm_paths_set
        file_paths = list(total_paths_set)

        if not file_paths:
            self.log.info("未找到JavaScript文件")
            return False

        original_count = len(original_paths_set)
        sm_count = len(sm_paths_set)
        total_count = len(file_paths)

        if sm_count > 0:
            self.log.info(f"找到 {total_count} 个源文件（原始 {original_count} + SourceMap还原 {sm_count}），开始扫描敏感信息...")
        else:
            self.log.info(f"找到 {original_count} 个源文件（无SourceMap新增），开始扫描敏感信息...")

        all_matches = {}
        all_unique_paths = set()
        all_path_mappings = []

        max_threads = min(4, multiprocessing.cpu_count())
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(self.process_js_file, fp) for fp in file_paths]

            for future in futures:
                matches, unique_paths, path_mappings = future.result()
                for pattern_name, pattern_matches in matches.items():
                    if pattern_name not in all_matches:
                        all_matches[pattern_name] = []
                    all_matches[pattern_name].extend(pattern_matches)
                all_unique_paths.update(unique_paths)
                all_path_mappings.extend(path_mappings)

        self.save_results(all_matches, sorted(all_unique_paths), sorted(all_path_mappings))

        total_matches = sum(len(m) for m in all_matches.values())
        self.log.info(f"敏感信息扫描完成，共发现 {total_matches} 个匹配项")
        for pattern_name, pattern_matches in all_matches.items():
            if pattern_matches:
                self.log.info(f"- {pattern_name}: {len(pattern_matches)} 个匹配")

        return True

    def generate_html_output(self, matches: Dict[str, List[Tuple[str, str, str]]]) -> str:
        """生成与总览报告相同格式的交互式HTML输出"""
        html_path = os.path.join(self.output_directory, 'sensitive_info.html')

        scan_time = Utils().tellTime()
        total_matches = sum(len(pattern_matches) for pattern_matches in matches.values())
        sorted_patterns = sorted(matches.items(), key=lambda x: len(x[1]), reverse=True)

        # 将matches数据按分类组织
        findings_by_type = {}
        for pattern_name, pattern_matches in sorted_patterns:
            if not pattern_matches:
                continue
            findings_by_type[pattern_name] = [
                {
                    "match": match_text,
                    "source": source,
                    "context": context
                }
                for match_text, source, context in pattern_matches
            ]

        # 编码为Base64（与总览报告相同）
        try:
            json_string = json.dumps(findings_by_type, ensure_ascii=False)
            json_bytes = json_string.encode('utf-8')
            b64_bytes = base64.b64encode(json_bytes)
            b64_string = b64_bytes.decode('ascii')
        except Exception:
            b64_string = ""

        # 生成摘要文本
        if not findings_by_type:
            summary_text = "未发现敏感信息"
            summary_class = "summary-not-found"
        else:
            summary_parts = [f"{ftype}: {len(items)}" for ftype, items in findings_by_type.items()]
            summary_text = ", ".join(summary_parts)
            summary_class = "summary-found"

        # 使用与总览报告完全相同的样式和脚本
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>单目标敏感信息扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0 auto; max-width: 1600px; padding: 20px; background-color: #f8f9fa; color: #333; }}
        h1, h2 {{ text-align: center; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); background-color: #fff; }}
        th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; word-break: break-all; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .data-row:nth-child(even) {{ background-color: #f9f9f9; }}
        .data-row:hover {{ background-color: #e9ecef; cursor: pointer; }}
        .data-row.active {{ background-color: #d1e7fd; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .summary-found {{ color: #dc3545; font-weight: bold; }}
        .summary-not-found {{ color: #6c757d; }}
        .summary-error {{ color: #ffc107; }}
        .footer {{ text-align: center; margin-top: 30px; color: #888; font-size: 0.9em; }}
        .hidden {{ display: none; }}
        .detail-cell {{ padding: 0; }}
        .detail-container {{ padding: 20px; background-color: #fdfdfd; border-top: 2px solid #007bff; }}
        .tabs {{ display: flex; border-bottom: 1px solid #ccc; margin-bottom: 15px; flex-wrap: wrap; }}
        .tab-link {{ padding: 10px 15px; cursor: pointer; border: 1px solid transparent; border-bottom: none; margin-bottom: -1px; background: #f1f1f1; border-radius: 4px 4px 0 0; margin-right: 5px; }}
        .tab-link.active {{ background: #fff; border-color: #ccc #ccc #fff; }}
        .tab-content {{ padding: 10px; }}
        .match-list-item {{ list-style: none; padding: 10px; border: 1px solid #eee; margin-bottom: 8px; border-radius: 4px; background: #fff; }}
        .match-list-item:hover {{ background: #f7f7f7; }}
        .match-header {{ cursor: pointer; font-weight: bold; color: #c0392b; font-family: monospace; }}
        .match-source {{ font-size: 0.8em; color: #777; margin-left: 15px; }}
        .match-context {{ background-color: #f0f0f0; padding: 10px; border-radius: 4px; margin-top: 10px; font-family: monospace; white-space: pre-wrap; word-break: break-all; font-size: 0.9em; border-left: 3px solid #6c757d; }}
        .highlight {{ background-color: #ff9999; padding: 2px 0; border-radius: 2px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>单目标敏感信息扫描报告</h1>
    <h2>扫描时间: {scan_time}</h2>
    <table id="main-table">
        <thead>
            <tr>
                <th style="width:10%">类型统计</th>
                <th style="width:70%">扫描结果摘要 (点击展开查看详情)</th>
                <th style="width:20%">总匹配项数</th>
            </tr>
        </thead>
        <tbody>
            <tr class="data-row" data-id="1">
                <td>{len(findings_by_type)} 种类型</td>
                <td class="{summary_class}">{html.escape(summary_text)}</td>
                <td>{total_matches}</td>
            </tr>
        </tbody>
    </table>
    <div class="footer">
        <p>报告由 Packer-InfoFinder 工具生成</p>
    </div>

    <script type="application/json-base64" id="json-1" class="hidden">
    {b64_string}
    </script>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const mainTableBody = document.querySelector('#main-table tbody');

            // Unicode-safe Base64解码函数
            function b64DecodeUnicode(str) {{
                try {{
                    return decodeURIComponent(atob(str).split('').map(function(c) {{
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }}).join(''));
                }} catch (e) {{
                    console.error("Base64 decoding failed:", e);
                    return '';
                }}
            }}

            mainTableBody.addEventListener('click', function(e) {{
                const dataRow = e.target.closest('.data-row');
                if (!dataRow) return;

                const detailRowId = `detail-${{dataRow.dataset.id}}`;
                let detailRow = document.getElementById(detailRowId);

                if (detailRow) {{
                    dataRow.classList.toggle('active');
                    detailRow.classList.toggle('hidden');
                }} else {{
                    dataRow.classList.add('active');
                    detailRow = document.createElement('tr');
                    detailRow.id = detailRowId;
                    const detailCell = detailRow.insertCell(0);
                    detailCell.colSpan = 3;
                    detailCell.classList.add('detail-cell');
                    dataRow.insertAdjacentElement('afterend', detailRow);

                    const jsonDataScript = document.getElementById(`json-${{dataRow.dataset.id}}`);
                    try {{
                        const b64Data = jsonDataScript.textContent.trim();
                        if (!b64Data) throw new Error("No data found.");

                        const jsonText = b64DecodeUnicode(b64Data);
                        if (!jsonText) throw new Error("Decoded data is empty.");

                        const findings = JSON.parse(jsonText);
                        detailCell.innerHTML = createDetailView(findings, dataRow.dataset.id);
                        attachDetailEventListeners(detailRow);
                    }} catch (err) {{
                        detailCell.innerHTML = `<div class="detail-container">无法加载详细信息: ${{err.message}}</div>`;
                    }}
                }}
            }});

            function createDetailView(findings, id) {{
                if (Object.keys(findings).length === 0) {{
                    return `<div class="detail-container">无详细信息</div>`;
                }}
                let tabsHtml = '<div class="tabs">';
                let contentHtml = '';
                let isFirstTab = true;
                let tabIndex = 0;

                for (const type in findings) {{
                    const safeId = `tab-${{id}}-${{tabIndex}}`;
                    tabsHtml += `<div class="tab-link ${{isFirstTab ? 'active' : ''}}" data-tab="${{safeId}}">${{escapeHtml(type)}} (${{findings[type].length}})</div>`;

                    let matchesHtml = '<ul style="padding:0;">';
                    findings[type].forEach((item, index) => {{
                        const contextId = `context-${{id}}-${{tabIndex}}-${{index}}`;

                        const safeMatch = escapeHtml(item.match);
                        const safeContext = escapeHtml(item.context);
                        const highlightedContext = safeContext.split(safeMatch).join(`<span class="highlight">${{safeMatch}}</span>`);

                        matchesHtml += `
                            <li class="match-list-item">
                                <div class="match-header" data-target="${{contextId}}">
                                    ${{safeMatch}}
                                    <span class="match-source">${{escapeHtml(item.source)}}</span>
                                </div>
                                <div id="${{contextId}}" class="match-context hidden">
                                    ${{highlightedContext}}
                                </div>
                            </li>`;
                    }});
                    matchesHtml += '</ul>';

                    contentHtml += `<div id="${{safeId}}" class="tab-content ${{isFirstTab ? '' : 'hidden'}}">${{matchesHtml}}</div>`;
                    isFirstTab = false;
                    tabIndex++;
                }}
                tabsHtml += '</div>';

                return `<div class="detail-container">${{tabsHtml}}${{contentHtml}}</div>`;
            }}

            function attachDetailEventListeners(detailRow) {{
                detailRow.addEventListener('click', function(e) {{
                    if (e.target.classList.contains('tab-link')) {{
                        const tabId = e.target.dataset.tab;
                        detailRow.querySelectorAll('.tab-link').forEach(t => t.classList.remove('active'));
                        e.target.classList.add('active');
                        detailRow.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
                        detailRow.querySelector(`#${{tabId}}`).classList.remove('hidden');
                    }} else if (e.target.closest('.match-header')) {{
                        const header = e.target.closest('.match-header');
                        const contextDiv = document.getElementById(header.dataset.target);
                        if (contextDiv) {{
                            contextDiv.classList.toggle('hidden');
                        }}
                    }}
                }});
            }}

            function escapeHtml(str) {{
                if (typeof str !== 'string') return '';
                const p = document.createElement("p");
                p.textContent = str;
                return p.innerHTML;
            }}
        }});
    </script>
</body>
</html>
"""

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return html_path

    def save_results(self, matches: Dict, unique_paths: List, path_mappings: List) -> None:
        """保存扫描结果到文件"""
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        html_path = self.generate_html_output(matches)

        text_path = os.path.join(self.output_directory, 'sensitive_info.txt')
        with open(text_path, 'w', encoding='utf-8') as output_file:
            output_file.write(f"=== JavaScript敏感信息扫描结果 ===\n")
            output_file.write(f"扫描时间: {Utils().tellTime()}\n\n")

            for pattern_name, pattern_matches in matches.items():
                if pattern_matches:
                    output_file.write(f"\n=== {pattern_name.upper()} ===\n")
                    for match_text, source, _ in pattern_matches:
                        output_file.write(f"[+] {match_text}\n")
                        output_file.write(f"    来源: {source}\n")

        path_output_file = os.path.join(self.output_directory, 'paths.txt')
        with open(path_output_file, 'w', encoding='utf-8') as path_file:
            path_file.write("[--------------------独立路径列表-----------------------]\n")
            for path in unique_paths:
                path_file.write(f"{path}\n")
            path_file.write("\n[------------------文件路径对应关系-----------------------]\n")
            for mapping in path_mappings:
                path_file.write(f"{mapping}\n")

        self.log.info(f"HTML格式结果已保存到: {html_path}")
        self.log.info(f"文本格式结果已保存到: {text_path}")
        self.log.info(f"路径信息已保存到: {path_output_file}")

        # 在保存 paths.txt 之后：提取路径最后一段并叠加写入全局词表
        try:
            last_tokens = self.extract_last_segments(unique_paths)
            if last_tokens:
                global_list_path = self.append_to_global_fuzz_list(last_tokens)
                if global_list_path:
                    self.log.info(f"已将 {len(last_tokens)} 个候选路径末段去重后追加到: {global_list_path}")
        except Exception as e:
            self.log.error(f"提取/写入路径末段词表时出错: {e}")

        # 单文件智能收敛导出功能已取消，跳过 endpoints.jsonl 与 inventory.md 生成
        self.log.debug("已跳过 API Inventory 导出（功能已取消）")

    def start_scan(self) -> bool:
        """开始扫描JavaScript文件中的敏感信息"""
        self.log.info("开始JavaScript敏感信息扫描...")

        try:
            project_path = DatabaseType(self.projectTag).getPathfromDB()
            if not project_path:
                self.log.error("无法获取项目路径")
                return False

            result = self.process_js_files(project_path)

            if result:
                self.log.info(f"JavaScript敏感信息扫描完成，结果保存在: {self.output_directory}")
                return True
            else:
                self.log.error("JavaScript敏感信息扫描失败")
                return False

        except Exception as e:
            self.log.error(f"JavaScript敏感信息扫描过程中出错: {e}")
            return False

    def extract_last_segments(self, paths: List[str]) -> List[str]:
        """从路径列表中提取最后一个“看起来像API”的有效段并去重"""
        tokens = set()
        for original in paths:
            try:
                path = original
                # 支持完整URL：仅取其路径部分
                if '://' in path:
                    from urllib.parse import urlparse
                    path = urlparse(path).path or '/'
                # 去掉查询串和fragment
                path = path.split('?', 1)[0].split('#', 1)[0].strip()
                if not path:
                    continue
                # 规范化/分段
                segments = [s for s in path.strip('/').split('/') if s]
                if not segments:
                    continue
                candidate = segments[-1].strip()
                if not candidate:
                    continue
                if self.is_reasonable_api_segment(candidate):
                    tokens.add(candidate)
            except Exception:
                continue
        return sorted(tokens)

    def is_reasonable_api_segment(self, segment: str) -> bool:
        """基于启发式判断一个末段是否像“正常API接口名”"""
        seg = segment.strip()
        if not seg:
            return False
        low = seg.lower()
        # 排除静态资源及常见非接口后缀
        static_exts = (
            '.js', '.mjs', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.map',
            '.eot', '.ttf', '.woff', '.woff2', '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.vue'
        )
        if any(low.endswith(ext) for ext in static_exts):
            return False
        # 含点通常是文件，直接排除
        if '.' in seg:
            return False
        # 过长/过短或明显随机
        if len(seg) > 48:
            return False
        # 纯数字
        if re.fullmatch(r'\d+', seg):
            return False
        # UUID或长哈希
        if re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', seg, re.IGNORECASE):
            return False
        if re.fullmatch(r'[A-Fa-f0-9]{24,}', seg):
            return False
        # 合理的API命名：字母开头，允许数字/下划线/破折号，长度限制
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{1,47}', seg):
            return True
        return False

    def append_to_global_fuzz_list(self, tokens: List[str]) -> str:
        """将候选词追加到项目根目录的 fuzz_last_segments.txt（全局累积、去重）"""
        try:
            global_path = os.path.join(os.getcwd(), 'fuzz_last_segments.txt')
            existing = set()
            if os.path.exists(global_path):
                with open(global_path, 'r', encoding='utf-8', errors='ignore') as f:
                    existing = {line.strip() for line in f if line.strip()}
            new_tokens = [t for t in tokens if t not in existing]
            if not new_tokens:
                return global_path
            with open(global_path, 'a', encoding='utf-8') as f:
                for t in new_tokens:
                    f.write(f"{t}\n")
            return global_path
        except Exception as e:
            self.log.error(f"写入全局词表失败: {e}")
            return ""

    def _split_identifier(self, s: str) -> List[str]:
        s = re.sub(r'([a-z])([A-Z])', r'\1 \2', s or '')
        s = s.replace('-', ' ').replace('_', ' ')
        return [t for t in s.lower().split() if t]

    def _is_verb(self, tok: str) -> bool:
        return tok in self._verbs

    def _last_noun_from_tokens(self, toks: List[str]) -> str:
        for t in reversed(toks or []):
            if t not in self._stop_tokens and t not in self._verbs and t not in self._suffix_detail_like:
                return t
        return (toks or [''])[ -1 ] if toks else ''

    def _split_verb_noun(self, segment: str) -> Tuple[str, str]:
        toks = self._split_identifier(segment)
        if not toks:
            return None, None
        if self._is_verb(toks[0]) and len(toks) >= 2:
            return toks[0], self._last_noun_from_tokens(toks[1:])
        if toks[-1] in self._suffix_detail_like and len(toks) >= 2:
            suffix = toks[-1]
            verb = 'detail' if suffix in {'detail', 'info'} else 'list'
            return verb, self._last_noun_from_tokens(toks[:-1])
        # 既非动词开头也非后缀，返回最后一个“像名词”的token
        return None, self._last_noun_from_tokens(toks)

    def _normalize_noun(self, n: str) -> str:
        if not n:
            return ''
        n = self._synonyms.get(n, n)
        if n.endswith('ies') and len(n) > 3:
            n = n[:-3] + 'y'
        elif n.endswith('s') and len(n) > 3:
            n = n[:-1]
        return re.sub(r'[^a-z0-9]', '', n)

    def _classify_action(self, verb: str, segment: str) -> Tuple[str, str]:
        v = verb
        if not v:
            toks = self._split_identifier(segment)
            if toks and toks[0] in self._verbs:
                v = toks[0]
        verb2method = {
            'add': 'post','create': 'post','new': 'post','save': 'post','upload': 'post','import': 'post',
            'update': 'put','edit': 'put','change': 'put',
            'delete': 'delete','remove': 'delete','clear': 'delete','reset': 'delete',
            'list': 'get','get': 'get','detail': 'get','info': 'get','show': 'get','search': 'get','query': 'get','export': 'get','download': 'get'
        }
        method = verb2method.get(v or '', '')
        if not method and v in {'list','detail','info','get','show','search','query','export','download'}:
            method = 'get'
        return method, v or ''

    def build_endpoint_records(self, paths: List[str]) -> List[Dict[str, str]]:
        records = []
        for original in paths:
            try:
                path = original
                if '://' in path:
                    from urllib.parse import urlparse
                    path = urlparse(path).path or '/'
                path = path.split('?', 1)[0].split('#', 1)[0].strip()
                segs = [s for s in path.strip('/').split('/') if s]
                if not segs:
                    continue
                last = segs[-1].strip()
                if not self.is_reasonable_api_segment(last):
                    continue
                module = segs[0].lower()
                verb, noun = self._split_verb_noun(last)
                if noun:
                    resource = self._normalize_noun(noun)
                elif len(segs) > 1:
                    resource = self._normalize_noun(self._last_noun_from_tokens(self._split_identifier(segs[-2])))
                else:
                    resource = self._normalize_noun(self._last_noun_from_tokens(self._split_identifier(last)))
                action_method, action_verb = self._classify_action(verb, last)
                rec = {
                    'path': path,
                    'module': module,
                    'resource': resource or 'others',
                    'action': action_verb or '',
                    'method': action_method or '',
                    'token': last
                }
                records.append(rec)
            except Exception:
                continue
        return records

    def export_single_inventory(self, endpoints: List[Dict[str, str]], max_resources: int = 12, min_support: int = 2) -> Dict[str, str]:
        # 资源计数与裁剪
        res_counts = Counter([e.get('resource') for e in endpoints if e.get('resource')])
        sorted_resources = [r for r, _ in res_counts.most_common()]
        keep = set([r for r in sorted_resources if r and res_counts[r] >= min_support][:max_resources])

        by_res = defaultdict(list)
        for e in endpoints:
            r = e.get('resource') or 'others'
            by_res[r if r in keep else 'others'].append(e)

        # 写 endpoints.jsonl（全量，可编程）
        jsonl_path = os.path.join(self.output_directory, 'endpoints.jsonl')
        os.makedirs(self.output_directory, exist_ok=True)
        with open(jsonl_path, 'w', encoding='utf-8') as f:
            for e in endpoints:
                f.write(json.dumps(e, ensure_ascii=False) + '\n')

        # 写 inventory.md（收敛的人读报告）
        md_path = os.path.join(self.output_directory, 'inventory.md')
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write('# API Inventory (收敛视图)\n\n')
            f.write(f"- resources_kept: {len(keep)} (min_support={min_support}, max={max_resources})\n")
            f.write(f"- total_endpoints: {len(endpoints)}\n\n")
            for r, items in sorted(by_res.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                mods = Counter([e.get('module') for e in items])
                tokens = Counter([e.get('token') for e in items])
                actions = Counter([(e.get('action') or 'unknown') for e in items])
                f.write(f"## Resource: {r} (paths={len(items)})\n")
                if mods:
                    f.write(f"- modules: {', '.join([f'{m}:{c}' for m, c in mods.most_common()])}\n")
                if actions:
                    f.write(f"- actions: {', '.join([f'{a}:{c}' for a, c in actions.most_common()])}\n")
                danger = sum(c for a, c in actions.items() if a in {'delete','clear','reset','remove'})
                if danger:
                    f.write(f"- risks: delete/clear/reset={danger}\n")
                top_tokens = ', '.join([t for t, _ in tokens.most_common(10)])
                if top_tokens:
                    f.write(f"- tokens: {top_tokens}\n")
                # examples
                for e in items[:3]:
                    f.write(f"  - {e.get('path')}\n")
                # CRUD 补全建议
                have = set([e.get('action') for e in items if e.get('action')])
                missing = [a for a in ('add','update','delete','list','detail') if a not in have]
                if missing:
                    f.write(f"- suggest: {', '.join([f'{r}{a.capitalize()}' for a in missing])}\n")
                f.write('\n')

        return {'jsonl': jsonl_path, 'md': md_path, 'kept_resources': str(len(keep))}
