scan_main_web.py：web查询  python3 scan_main_web.py
http://127.0.0.1:5003/index/通过页面查询


scan_main_web.py：api接口请求
http://ip/webinterface/
请求方式：POST
参数名：ip
参数类型：string
参数值：1.1.1.1



scan_main_shell.py：命令行查询   python3 scan_main_shell.py ip

config.py：配置文件

output.json：结果文件

其他文件：自定义的库文件用于scan_main_web.py和scan_main_shell.py调用

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