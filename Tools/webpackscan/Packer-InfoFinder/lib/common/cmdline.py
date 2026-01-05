# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import optparse,sys


class CommandLines():

    def cmd(self):
        parse = optparse.OptionParser()
        parse.add_option('-u', '--url', dest='url', help='请输入目标 URL')
        parse.add_option('-c', '--cookie', dest='cookie', help='请输入网站 Cookies')
        parse.add_option('-d', '--head', dest='head', default='Cache-Control:no-cache', help='请输入额外的 HTTP 头')
        parse.add_option('-l', '--list', dest='list', help='请输入目标 URL 列表文件')
        parse.add_option('-p', '--proxy', dest='proxy', type='str', help='请输入代理地址')
        parse.add_option('-j', '--js', dest='js', type='str', help='指定要分析的 JS URL（多个用逗号分隔）')

        parse.add_option('-f', '--flag', dest='ssl_flag', default='1', type='str', help='SSL 安全标志')
        parse.add_option('-s', '--silent', dest='silent', type='str', help='静默模式（自定义报告名称）')

        # 在CommandLines类的cmd方法中添加以下行
        parse.add_option('--finder', dest='finder', action='store_true', default=False, help='启用JavaScript敏感信息扫描')  # 敏感信息扫描
        parse.add_option('-T', '--url-timeout', dest='url_timeout', type='int', default=0,
                         help='单个URL的总扫描超时时间(秒)，0表示关闭。建议：普通站点 300~600 秒。')

        # Dynamic JS Discovery options (Requirements 1.1, 1.3, 2.1, 2.4)
        parse.add_option('--browser', dest='browser', action='store_true', default=False,
                         help='启用无头浏览器模式以捕获动态加载的JS文件 (Enable headless browser mode)')
        parse.add_option('--browser-timeout', dest='browser_timeout', type='int', default=10000,
                         help='浏览器等待超时时间(毫秒)，默认10000 (Browser timeout in ms, default 10000)')
        parse.add_option('--max-iframe-depth', dest='max_iframe_depth', type='int', default=3,
                         help='iframe递归解析最大深度，默认3 (Max iframe recursion depth, default 3)')
        parse.add_option('--no-iframe', dest='no_iframe', action='store_true', default=False,
                         help='禁用iframe递归解析 (Disable iframe recursive parsing)')

        (options, args) = parse.parse_args()
        if options.list is None and options.url is None and getattr(options, 'js', None) is None:
            parse.print_help()
            sys.exit(0)
        return options


if __name__ == '__main__':
    print(CommandLines().cmd().cookie)
