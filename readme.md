##### 虚拟机安装：
##### 虚拟机每个月更新一次，源码会及时更新，获取最新版可将项目 - [info_scan源码版](https://github.com/huan-cdm/info_scan)，替换到虚拟机的/TIP/目录下，然后重启相关服务；
虚拟机账号密码：huan/admin@123<br>
1. 登录Linux系统，修改/TIP/info_scan/config.py中相关参数，包括系统账号密码、接口key的配置都在这个文件<br>
2. 修改info_scan/static/js/common.js文件第一行修改为自己虚拟机的IP地址<br>
3. 项目开启命令：bash /TIP/info_scan/server_check.sh -h，nginx和mysql需执行service nginx start和service mysql start开启服务<br>
4. 修改/etc/nginx/conf.d/目录下所有文件中server_name字段替换为自己虚拟机的IP地址，重启nginx服务器<br>
5. 入口地址：http://虚拟机IP:19999/index/<br>
6. 项目源码路径：/TIP/*
网盘链接：<br>
- [info_scan虚拟机版](https://pan.baidu.com/s/19EPOyjgf0JxbbOYymUr2vg?pwd=sufy)
<br><br>

##### 源码安装：
注意：<br><br>
保证系统正常运行需要2个项目：<br><br>
- [info_scan](https://github.com/huan-cdm/info_scan)：漏洞扫描主系统<br>
- [batch_scan_domain](https://github.com/huan-cdm/batch_scan_domain)：xray+rad批量扫描，通过info_scan进行控制<br>
##### 集成相关工具：
漏洞扫描类：struts2、weblogic、shiro、springboot、thinkphp、泛微OA <br>
综合漏洞扫描类：afrog、fscan、hydra、urlfinder、vulmap、nuclei <br>
信息收集类：bbscan、ehole、nmap、otx威胁情报、crt子域名<br>
相关工具逐步完善......
<br><br>
<h2>更新日志：</h2>
<ul>
<li>2024-08-29更新<br> 
1. 新增ES数据库未授权访问批量扫描<br>
2. 新增程序运行状态显示绿色,停止状态显示红色<br>
</li>
<li>
2024-08-26更新<br> 
1. 新增高德地图API随机规则，可设置多个API，防止被耗尽；<br>
2. 新增为可选列表方式调用扫描器，勾选需要的扫描，包括开启扫描器、关闭扫描器、报告预览可一键完成；<br>
3. 完善扫描器的前端关闭功能；<br>
4. 新增扫描器时间限制，单位时间内只能提交配置好的提交次数，可通过配置文件进行配置；<br>
5. 前端页面优化；<br>
6. 部分已知问题处理；<br>
</li>

</ul>
系统使用说明
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
14. pip3 install -r requirements.txt -i https://pypi.mirrors.ustc.edu.cn/simple/ 安装所需模块<br><br>

项目目录结构
├── /TIP<br>
│   ├── info_scan<br>
│   ├── batch_scan_domain<br><br>
项目部署目录<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"/><br><br>
程序文件<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/code.png"/><br><br>
服务启动参数<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/backservicemanage.png"/><br><br>
系统登录<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/login1.jpg"/>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/login2.jpg"/><br><br>
IP基础信息查询<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/ipbasicinfo.png"/><br><br>
系统折叠展开<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhedie.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhankai.png"/><br><br>
系统服务管理<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/service.png"/><br><br>
目录扫描<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"/><br><br>
漏洞报告<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/report.png"/><br><br>
资产发现<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/assetfind1.png"/>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/assetfind2.png" /><br><br>
弱口令扫描<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/weakpasswd.png" /><br><br>
总报告在线预览<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/onlineyulan.jpg" /><br><br>
特殊字符校验<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/saferule.png" /><br><br>
可选列表方式调用扫描器<br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/checkinfoscan.png" /><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/infoscan_time.png" /><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/vulnscan_time.png" /><br><br>