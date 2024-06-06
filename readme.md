注意：<br>
保证系统正常运行需要2个项目：<br>
- [info_scan](https://github.com/huan-cdm/info_scan)：漏洞扫描主系统<br>
- [batch_scan_domain](https://github.com/huan-cdm/batch_scan_domain)：xray+rad批量扫描，通过info_scan进行控制<br>
系统使用说明<br>
1. 安装python3+MySQL数据库<br>
2. 安装nginx中间件<br>
3. info_scan和batch_scan_domain 部署到/TIP/目录下<br>
4. 首次运行afrog需在/root/.config/afrog/afrog-config.yaml进行相关配置，需先注册ceye dns平台<br>
5. 将/TIP/info_scan/static/js/common.js中的x.x.x.x替换为vps ip，替换命令(:%s/x.x.x.x/vps_ip/g)
6. xray+rad按照官方文档配置即可<br>
7. info_scan系统相关配置在/TIP/info_scan/config.py文件配置<br>
8. 系统使用前需点击解锁按钮进行解锁<br>
9. nuclei poc路径在/root/nuclei-templates/目录下<br>
10. 系统主要功能分为三类，第一是对IP进行基础信息探测，第二是对URL进行漏洞扫描，第三是对URL数据进行处理<br>
11. 建议部署到Ubuntu系统下，不支持Windows系统<br>

程序文件
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic33.png"  />

项目部署
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/startproject.jpg"  />

系统运行
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic3.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic4.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic2.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic22.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"  />

漏洞报告
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
指纹: tiderfinger、EHole<br>
子域名：crt证书<br>
rad+xray批量：batch_scan_domain<br>
漏洞扫描工具：nuclei、xray、rad、dirsearch、urlfinder、WeblogicScan、Struts2-Scan、vulmap、afrog、fscan、shiro-exploit<br>
DNS平台：ceye<br>
敏感信息：BBScan<br>
威胁情报平台：otx、archive<br>
重点资产提取：自定义关键字列表，与EHole识别结果进行匹配<br>