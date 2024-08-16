##### 虚拟机：
虚拟机账号密码：huan/admin@123<br>
1. 登录Linux系统，修改info_scan/config.py中的参数<br>
2. 修改info_scan/static/js/common.js文件第一行修改为自己虚拟机的IP地址<br>
3. 启动 bash /TIP/info_scan/server_check.sh -h 启动python后端服务，nginx和mysql未启动就手动启动一下<br>
网盘链接：<br>
https://pan.baidu.com/s/19EPOyjgf0JxbbOYymUr2vg?pwd=sufy
<br><br><br><br>
##### 源码安装：
注意：<br><br>
保证系统正常运行需要2个项目：<br><br>
- [info_scan](https://github.com/huan-cdm/info_scan)：漏洞扫描主系统<br>
- [batch_scan_domain](https://github.com/huan-cdm/batch_scan_domain)：xray+rad批量扫描，通过info_scan进行控制<br>

系统使用说明<br><br>
1. 安装python3+MySQL数据库<br>
2. 建议安装nginx反向代理web服务，部分接口会出现查询超时情况，可通过nginx控制超时时间，也可直接通过flask直接访问，只需修改scan_main_web.py和dirscanmain.py最后一行IP部分<br>
3. 不要修改目录，容易报错，将info_scan和batch_scan_domain部署到服务器的/TIP/目录下<br>
4. 将/TIP/info_scan/static/js/common.js第一行修改为自己服务器的IP地址<br>
5. info_scan系统相关配置在/TIP/info_scan/config.py文件配置<br>
6. 系统使用前需点击解锁按钮进行解锁<br>
7. 系统主要功能分为三类，第一是对IP进行基础信息探测，第二是对URL进行漏洞扫描，第三是对URL数据进行处理<br>
8. 建议部署到Ubuntu系统下，不支持Windows系统<br>
9. 系统设计初衷就是集成开源漏洞扫描器，让测试人员通过网页一键完成扫描，提升工作效率<br>
10. 需要通过pip3安装requirements.txt中的模块<br>
11. 建议先执行 python3 scan_main_web.py（主系统）和python3 dirscanmain.py（目录扫描子系统），确保系统运行正常后在利用bash server_check.sh进行管理<br>
12. nginx相关配置文件在nginx_conf目录下，将nginx.conf放到/etc/nginx目录下，将dirscan_nginx.conf和infoscan_nginx.conf放到/etc/nginx/conf.d目录下，执行nginx -t检查配置文件是否正确<br>
13. 系统需在开通以下端口：15555、16666、17777、18888、19999、3306<br>
14. pip3 install -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple/ 安装所需模块<br>

项目目录结构<br><br>
├── /TIP<br>
│   ├── info_scan<br>
│   ├── batch_scan_domain<br>

<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"/><br>

程序文件<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/code.png"/><br>

服务启动参数<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/backservicemanage.png"/><br>


部分功能截图<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/login1.jpg"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/login2.jpg"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhedie.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhankai.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/service.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/ipbasicinfo.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"/><br><br>

漏洞报告<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/report.png"/><br>
资产发现<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/assetfind1.png"/>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/assetfind2.png" /><br>
弱口令扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/weakpasswd.png" /><br>
总报告在线预览<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/onlineyulan.jpg" /><br>
特殊字符校验<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/saferule.png" /><br>
一键扫描重点资产漏洞<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/yijianscan.png" /><br>
支持工具详情<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/tools_assemble.png" /><br>