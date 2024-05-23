项目部署路径（batch_scan_domain+info_scan） <br>
info_scan：主项目<br>
batch_scan_domain：xray+rad批量漏扫项目，可shell下运行，通过info_scan进行控制<br>

项目部署截图
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/startproject.jpg"  />


系统运行截图
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic3.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic4.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic2.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"  />

报告截图
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/report.png"  />

系统服务启动方法 <br>
启动服务参数：bash server_check.sh -h <br>
开启infoscan：bash server_check.sh info_scan_start <br>
关闭infoscan：bash server_check.sh info_scan_stop <br>
开启xray报告：bash server_check.sh startreportserver <br>
关闭xray报告：bash server_check.sh stopreportserver <br>
关闭rad&xray引擎：bash server_check.sh killscan <br>
开启目录扫描引擎：bash server_check.sh startdirscan <br>
关闭目录扫描引擎：bash server_check.sh stopdirscan <br>
开启链接扫描报告：bash server_check.sh startlinkscanserver <br>
关闭链接扫描报告：bash server_check.sh stoplinkscanserver <br>
查看服务状态：bash server_check.sh status <br>


判断规则说明：<br>
IP(位置): 调用cip.cc查询位置。

IP(属性): 自定义列表,遍历列表和cip.cc的数据二进行对比
#带宽出口列表
exitaddress = ["移动","电信","联通"]

#手机热点
hotspot = ["移动数据上网公共出口","中国电信北京研究院"]

#数据中心
datacenter = ["公司","数据中心"] <br>

操作系统: 利用shell脚本，调用ping命令，返回值大于100是windows，返回值小于100是linux<br>
端口: 调用shodan接口查询端口<br>
公司: 调用icp备案信息查询公司名称<br>
公司位置：调用高德地图API接口，每日免费100次<br>
历史域名: 调用ip138查询历史域名<br>
域名: 调用fofa查询域名，然后通过httpx判断存活<br>
网站标题: request，网页title标签内容<br>
CDN信息: 调用shell脚本，nslookup查询域名,如果查询到3个以上IP地址，存在cdn<br>
指纹: 调用tiderfinger指纹识别脚本<br>
子域名：调用crt.sh查询子域名<br>
端口扫描：调用masscan端口扫描工具<br>
端口扫描：调用nmap，ip存入队列中，放在后台扫描<br>
漏洞扫描：调用nuclei扫描器<br>
xray+rad：运行batch_scan_domain脚本 <br>
目录扫描：调用dirsearch扫描器<br>
历史url: 调用otx和archive威胁情报<br>
链接扫描：调用urlfinder<br>
weblogic扫描：调用WeblogicScan <br>
struts2扫描：调用Struts2-Scan <br>
指纹识别：调用EHole <br>
敏感信息：调用BBScan <br>
综合漏洞扫描：调用vulmap <br>