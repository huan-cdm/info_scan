# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import sys
import re
import json
import html
import base64
import datetime
import time
import requests
from urllib.parse import quote, urlparse
from collections import Counter, defaultdict
import sqlite3
import multiprocessing
from types import SimpleNamespace

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[错误] 缺少 'BeautifulSoup' 模块，请先安装: pip install beautifulsoup4")
    sys.exit(1)

from lib.Controller import Project
from lib.TestProxy import testProxy
from lib.common.banner import RandomBanner
from lib.common.cmdline import CommandLines
from lib.common.utils import Utils
from lib.common.CreatLog import logs, log_name



import importlib

# 每次执行前删除临时目录下的所有文件
os.popen('rm -rf /TIP/info_scan/Tools/webpackscan/Packer-InfoFinder/tmp/*')
os.popen('rm -rf /TIP/info_scan/Tools/webpackscan/Packer-InfoFinder/logs/*')

class Program():
    def __init__(self, options):
        self.options = options

    def check(self):
        url = self.options.url
        t = Project(url, self.options)
        t.parseStart()


def read_urls(file_path):
    """读取 URL 文件"""
    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"文件 {file_path} 不存在")

        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except (FileNotFoundError, IOError, PermissionError) as e:
        print(f"文件操作失败: {e}")
        exit(1)

def reset_project_tag():
    """重置全局projectTag变量，为每个URL创建唯一的projectTag"""
    import lib.common.CreatLog
    importlib.reload(lib.common.CreatLog)
    return lib.common.CreatLog.logs



def _scan_single_url_worker(options_dict, url):
    """子进程中执行单个URL的完整扫描，避免单个目标卡死影响整个批量任务。"""
    # 在子进程中重新构造一个简单的options对象，避免直接跨进程序列化optparse.Values
    opts = SimpleNamespace(**options_dict)
    opts.url = url
    info_finder = Program(opts)
    info_finder.check()


def run_single_url_with_timeout(options, url, timeout_seconds):
    """在子进程中执行单个URL扫描，并施加总超时时间。超时会抛出 TimeoutError。"""
    # 将optparse.Values转换为普通dict以便在子进程中重建
    options_dict = vars(options).copy()
    process = multiprocessing.Process(
        target=_scan_single_url_worker,
        args=(options_dict, url),
    )
    process.start()
    process.join(timeout_seconds)

    if process.is_alive():
        # 超时仍未结束，强制终止子进程
        process.terminate()
        process.join()
        raise TimeoutError(f"单个URL扫描超时（超过 {timeout_seconds} 秒）")

    # 非0退出码视为扫描失败
    if process.exitcode != 0:
        raise RuntimeError(f"子进程扫描失败，exitcode={process.exitcode}")


def get_latest_project_tag_for_host(host, batch_start_ts):
    """从 main.db 中获取本次批量任务中指定主机的最新 projectTag。"""
    main_db_path = os.path.abspath(os.path.join(os.getcwd(), "main.db"))
    if not os.path.exists(main_db_path):
        return None

    try:
        conn = sqlite3.connect(main_db_path, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tag, time FROM project WHERE host = ? AND time >= ? ORDER BY time DESC LIMIT 1",
            (host, batch_start_ts),
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None
    except Exception as e:
        print(f"[警告] 无法从 main.db 获取项目标签: {e}")
        return None



def scan_js_urls_only(options):
    """仅基于 -j 指定的 JS URL 进行分析，不访问入口 HTML。

    流程：
    - 解析 -j 中的 JS URL 列表；
    - 创建项目数据库记录；
    - 下载这些 JS 文件；
    - 复用 RecoverSpilt / JsFinder 进行分析。
    """
    js_value = getattr(options, "js", "") or ""
    js_value = js_value.strip()
    if not js_value:
        print("[!] -j 参数为空，未指定 JS URL")
        return

    js_urls = [u.strip() for u in js_value.split(",") if u.strip()]
    if not js_urls:
        print("[!] 未能从 -j 参数中解析出有效的 JS URL")
        return

    primary_js_url = js_urls[0]
    parsed = urlparse(primary_js_url)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] 无效的 JS URL：{primary_js_url}")
        return

    # 如果 options.url 为空，则默认填充为 primary_js_url，方便后续模块复用 host / referer 等逻辑
    if getattr(options, "url", None) is None:
        options.url = primary_js_url

    # 网络连通性检测
    testProxy(options, 1)

    # 使用全局 logs 作为本次任务的 projectTag
    projectTag = logs

    from lib.Database import DatabaseType
    from lib.DownloadJs import DownloadJs
    from lib.Recoverspilt import RecoverSpilt
    from lib.JsFinder.JsFinderModule import JsFinderModule
    from lib.common.CreatLog import creatLog, log_name as global_log_name

    db = DatabaseType(projectTag)
    db.createDatabase()
    # 为 JS-only 模式创建一个项目记录，type 固定为 1，cloneTag 为 "0"
    db.createProjectDatabase(primary_js_url, 1, "0")

    logger = creatLog().get_logger()

    # 计算缓存数据库路径
    project_path = db.getPathfromDB()
    if project_path:
        db_path = os.path.abspath(os.path.join(project_path, f"{projectTag}.db"))
        logger.info("[+] 缓存文件路径：" + db_path)
    logger.info("[+] 日志文件路径：" + os.path.abspath(global_log_name))

    # 1) 先下载指定的 JS 文件
    host = parsed.netloc.replace(":", "_")
    downloader = DownloadJs(js_urls, options)
    downloader.downloadJs(projectTag, host, 0)

    # 2) 再进行 JS 代码拆分 / 还原分析（分析已下载的文件）
    RecoverSpilt(projectTag, options).recoverStart()

    # 可选：敏感信息扫描
    if getattr(options, "finder", False):
        js_finder = JsFinderModule(projectTag, options)
        js_finder.start_scan()

    logger.info("[v] JS URL 分析完成")

# --- 功能升级：交互式总览报告生成逻辑 ---

def initialize_finder_overview_report(report_path):
    """初始化总览报告文件，写入HTML头部、样式和交互脚本"""
    report_title = "Finder 敏感信息扫描总览报告"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_template = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{report_title}</title>
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
    <h1>{report_title}</h1>
    <h2>报告生成时间: {timestamp}</h2>
    <table id="main-table">
        <thead>
            <tr>
                <th style="width:5%">序号</th>
                <th style="width:35%">目标URL (点击展开/折叠)</th>
                <th style="width:45%">结果摘要</th>
                <th style="width:15%">原始报告</th>
            </tr>
        </thead>
        <tbody>
        </tbody>
    </table>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const mainTableBody = document.querySelector('#main-table tbody');

            // --- BUG FIX: Unicode-safe Base64解码函数 ---
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
                    detailCell.colSpan = 4;
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
                let tabIndex = 0; // --- BUG FIX: 使用索引作为ID，更稳妥 ---

                for (const type in findings) {{
                    const safeId = `tab-${{id}}-${{tabIndex}}`;
                    tabsHtml += `<div class="tab-link ${{isFirstTab ? 'active' : ''}}" data-tab="${{safeId}}">${{escapeHtml(type)}} (${{findings[type].length}})</div>`;

                    let matchesHtml = '<ul style="padding:0;">';
                    findings[type].forEach((item, index) => {{
                        const contextId = `context-${{id}}-${{tabIndex}}-${{index}}`;

                        // --- 优化点: 在上下文中高亮显示匹配的敏感信息 ---
                        const safeMatch = escapeHtml(item.match);
                        const safeContext = escapeHtml(item.context);
                        // 使用 split 和 join 实现全局替换，比 replaceAll 兼容性更好
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
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_template)

def parse_detailed_report(report_path):
    """解析单个sensitive_info.html文件，提取摘要和所有详细信息"""
    summary = "已扫描，未发现敏感信息"
    details = defaultdict(list)
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if "未发现敏感信息" in content:
                return summary, {}
            soup = BeautifulSoup(content, 'html.parser')

        findings_summary = Counter()
        sidebar_links = soup.select('.sidebar ul li a')
        for link in sidebar_links:
            match = re.match(r'^(.*?)(\d+)$', link.get_text(strip=True))
            if match:
                finding_type, count = match.groups()
                findings_summary[finding_type.strip()] = int(count)
        if findings_summary:
            summary_parts = [f"{ftype}: {count}" for ftype, count in findings_summary.most_common()]
            summary = ", ".join(summary_parts)

        sections = soup.find_all('h2')
        for section in sections:
            section_id = section.get('id')
            if not section_id:
                continue
            section_title = section_id.replace("_", " ")

            match_grid = section.find_next_sibling('div', class_='match-grid')
            if not match_grid:
                continue

            for item in match_grid.find_all('div', class_='match-item'):
                match_text = item.select_one('.match-text').get_text(strip=True) if item.select_one('.match-text') else ''
                match_source = item.select_one('.match-source').get_text(strip=True).replace('来源: ', '') if item.select_one('.match-source') else ''
                match_context = item.select_one('.match-context').get_text(strip=True) if item.select_one('.match-context') else ''
                details[section_title].append({
                    "match": match_text,
                    "source": match_source,
                    "context": match_context
                })

        return summary, dict(details)
    except Exception as e:
        return f"解析报告失败: {str(e)}", {}

def append_to_overview_report(index, url, summary, details, detailed_report_path):
    """向总览报告中追加一行记录及对应的Base64编码的JSON数据"""
    summary_class = "summary-not-found"
    if details and "失败" not in summary and "异常" not in summary:
        summary_class = "summary-found"
    elif "失败" in summary or "异常" in summary:
        summary_class = "summary-error"

    link = "无"
    if detailed_report_path and os.path.exists(detailed_report_path):
        relative_path = os.path.relpath(detailed_report_path, start=os.getcwd())
        link = f'<a href="{quote(relative_path.replace(os.sep, "/"))}" target="_blank" onclick="event.stopPropagation();">点击查看</a>'

    table_row = f"""
            <tr class="data-row" data-id="{index}">
                <td>{index}</td>
                <td><a href="{url}" target="_blank" onclick="event.stopPropagation();">{url}</a></td>
                <td class="{summary_class}">{summary}</td>
                <td>{link}</td>
            </tr>
    """

    try:
        json_string = json.dumps(details, ensure_ascii=False)
        json_bytes = json_string.encode('utf-8')
        b64_bytes = base64.b64encode(json_bytes)
        b64_string = b64_bytes.decode('ascii')
    except Exception:
        b64_string = ""

    json_script = f"""
            <script type="application/json-base64" id="json-{index}" class="hidden">
            {b64_string}
            </script>
    """
    return table_row + json_script


def finalize_overview_report(report_path, all_rows_html):
    """将所有行数据写入报告并添加结尾"""
    with open(report_path, 'r+', encoding='utf-8') as f:
        content = f.read()
        tbody_pos = content.find('</tbody>')
        if tbody_pos != -1:
            final_content = content[:tbody_pos] + all_rows_html + content[tbody_pos:]
            f.seek(0)
            f.write(final_content)
            f.truncate()

def PackerInfoFinder():
    options = CommandLines().cmd()

    # -j 模式：只分析指定的 JS URL，不访问入口 HTML
    js_only_mode = getattr(options, "js", None) and not options.url and not options.list
    if js_only_mode:
        scan_js_urls_only(options)
        return

    # 修改文件名为时间戳格式
    timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
    # 定义报告路径
    html_report_dir = "/TIP/info_scan/Tools/webpackscan/Packer-InfoFinder/report/"
    # 确保目录存在（不存在则创建）
    if not os.path.exists(html_report_dir):
        os.makedirs(html_report_dir, exist_ok=True)
    
    overview_report_path = os.path.join(html_report_dir, f"Packer-Fuzzer-{timestamp}.html")

    is_batch_finder_scan = options.list and options.finder
    all_rows_html = []

    if is_batch_finder_scan:
        initialize_finder_overview_report(overview_report_path)
        print(f"[+] 批量Finder扫描模式已启用，将生成交互式总览报告: {os.path.abspath(overview_report_path)}")

    if options.url is None:
        urls = read_urls(options.list)
        total_urls = len(urls)

        if total_urls == 0:
            print("[错误] URL列表文件为空或无有效URL")
            exit(1)

        print(f"开始扫描 {total_urls} 个 URL...")
        print("==================================================")

        # 批量扫描配置（可根据需求调整）
        # 速度优先：max_retries=0, url_interval=0
        # 平衡模式：max_retries=1, url_interval=0.5
        # 稳定优先：max_retries=2, url_interval=1
        BATCH_MAX_RETRIES = 1  # 重试次数：0=无重试(最快), 1=平衡, 2=稳定
        BATCH_URL_INTERVAL = 0.5  # URL间隔(秒)：0=最快, 0.5=平衡, 1=稳定

        # URL 总超时时间（秒），由命令行参数控制：
        # - 0 或未设置：不对单个 URL 的总扫描时间做限制
        # - >0：在子进程中执行单个 URL 扫描，并施加总超时时间
        PER_URL_TIMEOUT = getattr(options, "url_timeout", 0) or 0

        # 记录批量任务启动时间，用于从 main.db 中区分本次扫描的记录
        batch_start_ts = int(time.time())

        # 统计变量
        success_count = 0
        error_count = 0

        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{total_urls}] 开始扫描 URL: {url}")
            print("==================================================")

            # 重试机制
            max_retries = BATCH_MAX_RETRIES
            retry_count = 0
            scan_success = False

            while retry_count <= max_retries and not scan_success:
                try:
                    if retry_count > 0:
                        print(f"[!] 第 {retry_count} 次重试...")
                        time.sleep(2 * retry_count)  # 重试前等待

                    # 网络连通性测试（仅首次或重试时显示）
                    if retry_count == 0 or i == 1:
                        testProxy(options, 1)

                    # 根据参数决定是否对单个 URL 施加总超时时间
                    if PER_URL_TIMEOUT and PER_URL_TIMEOUT > 0:
                        # 在子进程中执行单个URL扫描，并施加总超时时间
                        run_single_url_with_timeout(options, url, PER_URL_TIMEOUT)
                    else:
                        # 不启用总超时，直接在当前进程中执行扫描
                        options_dict = vars(options).copy()
                        _scan_single_url_worker(options_dict, url)

                    # 扫描成功
                    scan_success = True
                    success_count += 1

                    if is_batch_finder_scan:
                        host = urlparse(url).netloc.replace(":", "_")
                        project_tag = get_latest_project_tag_for_host(host, batch_start_ts)

                        summary_text = ""
                        details_data = {}
                        detailed_report_path = None

                        if not project_tag:
                            summary_text = "未找到当前扫描对应的项目标签（可能扫描失败或未创建数据库）"
                        else:
                            report_dir = os.path.join("tmp", f"{project_tag}_{host}", "finder_results")
                            report_file = os.path.join(report_dir, "sensitive_info.html")

                            if os.path.exists(report_file):
                                detailed_report_path = report_file
                                summary_text, details_data = parse_detailed_report(detailed_report_path)
                            else:
                                summary_text = "未生成报告文件 (可能未发现JS或未找到敏感信息)"

                        row_html = append_to_overview_report(i, url, summary_text, details_data, detailed_report_path)
                        all_rows_html.append(row_html)
                        print(f"[+] 已处理 {url} 的扫描结果。")

                    # 批量扫描时添加间隔，避免对目标服务器造成压力
                    if i < total_urls and BATCH_URL_INTERVAL > 0:
                        time.sleep(BATCH_URL_INTERVAL)

                except KeyboardInterrupt:
                    print("\n[!] 用户中断扫描")
                    if is_batch_finder_scan:
                        finalize_overview_report(overview_report_path, "\n".join(all_rows_html))
                        print(f"\n[v] 已生成部分扫描结果报告: {os.path.abspath(overview_report_path)}")
                    sys.exit(0)

                except Exception as e:
                    retry_count += 1
                    error_msg = str(e)

                    # 判断是否是可重试的错误
                    retryable_errors = [
                        "connection",
                        "timeout",
                        "unable to open database file",
                        "database is locked",
                        "网络",
                        "连接"
                    ]

                    is_retryable = any(keyword in error_msg.lower() for keyword in retryable_errors)

                    if is_retryable and retry_count <= max_retries:
                        print(f"[警告] 扫描URL {url} 时发生可恢复错误: {error_msg}")
                        print(f"[提示] 将在 {2 * retry_count} 秒后重试...")
                        continue
                    else:
                        # 不可重试或已达最大重试次数
                        print(f"[错误] 扫描URL {url} 时发生严重错误: {error_msg}")
                        error_count += 1

                        if is_batch_finder_scan:
                            error_summary = f"扫描失败: {error_msg}"
                            if retry_count > 0:
                                error_summary += f" (已重试{retry_count}次)"
                            row_html = append_to_overview_report(i, url, error_summary, {}, None)
                            all_rows_html.append(row_html)
                        break  # 跳出重试循环，继续下一个URL

        # 输出统计信息
        print("\n" + "="*50)
        print("批量扫描统计信息：")
        print(f"  总计URL数: {total_urls}")
        print(f"  成功扫描: {success_count} ({success_count*100//total_urls if total_urls > 0 else 0}%)")
        print(f"  失败数量: {error_count} ({error_count*100//total_urls if total_urls > 0 else 0}%)")
        print("="*50)

        if is_batch_finder_scan:
            finalize_overview_report(overview_report_path, "\n".join(all_rows_html))
            print(f"\n[v] 所有URL扫描完毕。交互式总览报告已成功生成: {os.path.abspath(overview_report_path)}")
        else:
            print(f"\n所有 {total_urls} 个 URL 扫描完毕。")

    else:
        testProxy(options, 1)
        per_url_timeout = getattr(options, "url_timeout", 0) or 0

        if per_url_timeout and per_url_timeout > 0:
            run_single_url_with_timeout(options, options.url, per_url_timeout)
        else:
            PackerFuzzer = Program(options)
            PackerFuzzer.check()

if __name__ == "__main__":
    RandomBanner()
    PackerInfoFinder()