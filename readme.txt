项目启动文件
scan_main_web.py：项目入口  python3 scan_main_web.py
dirscanmain.py:   目录扫描  python3 dirscanmain.py
server_check.sh s-h 项目启动脚本
nginx_conf目录：将dirscan_nginx.conf  infoscan_nginx.conf放到/etc/nginx/conf.d/目录下
【开启infoscan：bash server_check.sh info_scan_start
关闭infoscan：bash server_check.sh info_scan_stop
开启xray报告：bash server_check.sh startreportserver
关闭xray报告：bash server_check.sh stopreportserver
关闭rad&xray引擎：bash server_check.sh killscan
开启目录扫描引擎：bash server_check.sh startdirscan
关闭目录扫描引擎：bash server_check.sh stopdirscan
查看服务状态：bash server_check.sh status】




目前通过IP可以识别以下信息,正在完善更新中......

判断规则说明：
IP(位置): 调用cip.cc查询位置。

IP(属性): 自定义列表,遍历列表和cip.cc的数据二进行对比
#带宽出口列表
exitaddress = ["移动","电信","联通"]

#手机热点
hotspot = ["移动数据上网公共出口","中国电信北京研究院"]

#数据中心
datacenter = ["公司","数据中心"]

操作系统: 利用shell脚本，调用ping命令，返回值大于100是windows，返回值小于100是linux。
端口: 调用shodan接口查询端口。
公司: 调用icp备案信息查询公司名称。
公司位置：调用高德地图API接口，每日免费100次
历史域名: 调用ip138查询历史域名。
域名: 调用fofa查询域名，然后通过httpx判断存活。
网站标题: request，网页title标签内容。
CDN信息: 调用shell脚本，nslookup查询域名,如果查询到3个以上IP地址，存在cdn。
指纹: 调用tiderfinger指纹识别脚本。
子域名：调用https://crt.sh/ 查询子域名。
端口扫描：调用masscan端口扫描工具
端口扫描：调用nmap，ip存入队列中，放在后台扫描。
漏洞扫描：调用nuclei扫描器
xray+rad：下载 https://github.com/huan-cdm/batch_scan_domain
目录扫描：调用dirsearch扫描器
历史url: 调用otx和archive威胁情报
链接扫描：调用urlfinder（已完成）；其他链接爬取工具正在完善中.....