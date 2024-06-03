注意：<br>
保证系统正常运行需要2个项目：<br>
- [info_scan](https://github.com/huan-cdm/info_scan)：漏洞扫描主系统<br>
- [batch_scan_domain](hhttps://github.com/huan-cdm/batch_scan_domain)：xray+rad批量扫描，通过info_scan进行控制<br>

项目部署截图
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/startproject.jpg"  />

系统运行截图
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic3.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic4.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic2.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic22.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"  />

漏洞报告截图
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/report.png"  /><br><br>

系统后台服务启动参数 <br>
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
开启afrog报告：bash server_check.sh startafrogreportserver<br>
关闭afrog报告：bash server_check.sh stopafrogreportserver<br>
查看服务状态：bash server_check.sh status <br>


模块功能介绍：<br>
IP位置: 调用cip.cc <br>
IP属性: 自定义列表,遍历列表和cip.cc的数据二进行对比<br>
带宽出口列表：exitaddress = ["移动","电信","联通"]<br>
手机热点：hotspot = ["移动数据上网公共出口","中国电信北京研究院"]<br>
数据中心：datacenter = ["公司","数据中心"] <br>
操作系统: shell脚本<br>
端口: shodan、fofa、nmap<br>
公司: ICP备案信息查询网站<br>
公司位置：高德地图<br>
历史URL: fofa<br>
存活URL: fofa、httpx<br>
网站标题: python3 requests模块<br>
CDN信息: shell脚本nslookup<br>
指纹: tiderfinger<br>
子域名：crt证书<br>
rad+xray批量：batch_scan_domain<br>
漏洞扫描工具：nuclei、xray、rad、dirsearch、urlfinder、WeblogicScan、Struts2-Scan、vulmap、afrog、fscan<br>
DNS平台：ceye<br>
信息收集工具：EHole、BBScan<br>
威胁情报平台：otx、archive<br>