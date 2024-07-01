注意：<br>
保证系统正常运行需要2个项目：<br>
- [info_scan](https://github.com/huan-cdm/info_scan)：漏洞扫描主系统<br>
- [batch_scan_domain](https://github.com/huan-cdm/batch_scan_domain)：xray+rad批量扫描，通过info_scan进行控制<br>

系统使用说明<br>
1. 安装python3+MySQL数据库<br>
2. 建议安装nginx反向代理web服务，部分接口会出现查询超时情况，可通过nginx控制超时时间，也可直接通过flask直接访问，只需修改scan_main_web.py和dirscanmain.py最后一行IP部分<br>
3. 不要修改目录，容易报错，将info_scan和batch_scan_domain部署到服务器的/TIP/目录下，<br>
4. 将/TIP/info_scan/static/js/common.js中的x.x.x.x替换为vps ip，替换命令(:%s/x.x.x.x/vps_ip/g)
5. info_scan系统相关配置在/TIP/info_scan/config.py文件配置<br>
6. 系统使用前需点击解锁按钮进行解锁<br>
7. 系统主要功能分为三类，第一是对IP进行基础信息探测，第二是对URL进行漏洞扫描，第三是对URL数据进行处理<br>
8. 建议部署到Ubuntu系统下，不支持Windows系统<br>
9. 系统设计初衷就是集成开源漏洞扫描器，让测试人员通过网页一键完成扫描，提升工作效率<br>
10. 需要通过pip3安装requirements.txt中的模块<br>
11. 建议先执行 python3 scan_main_web.py（主系统）和python3 dirscanmain.py（目录扫描子系统），确保系统运行正常后在利用bash server_check.sh进行管理<br>
12. nginx相关配置文件在nginx_conf目录下，将nginx.conf放到/etc/nginx目录下，将dirscan_nginx.conf和infoscan_nginx.conf放到/etc/nginx/conf.d目录下，执行nginx -t检查配置文件是否正确<br>
13. 系统需在开通以下端口：15555、16666、17777、18888、19999、3306<br>

├── /TIP
│   ├── info_scan
│   ├── batch_scan_domain

<br>
系统服务启动参数 <br>
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

程序文件
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic33.png"  />

项目部署
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/startproject.jpg"  />

系统运行
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic3.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic4.jpg"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic2.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhankai.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/service.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/pic22.png"  />
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"  />

漏洞报告
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/report.png"  /><br><br>