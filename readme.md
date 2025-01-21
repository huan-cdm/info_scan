<h2>docker部署（beta版本）：</h2> 
1. 账号密码：nginx/web/mysql：admin/123456<br>
2. 创建docker自定义网络，使容器间完成通信：docker network create info_scan_network<br>
3. mysql环境：<br>
下载镜像：docker pull registry.cn-hangzhou.aliyuncs.com/huan666/ubuntu:0.1<br>
启动容器：docker run -d --name mysql -it --network info_scan_network -p 3306:3306 registry.cn-hangzhou.aliyuncs.com/huan666/ubuntu:0.1 /bin/bash<br>
进入容器：docker exec -it 容器ID /bin/bash<br>
启动mysql：service  mysql start<br>
4.平台环境：<br>
下载镜像：docker pull registry.cn-hangzhou.aliyuncs.com/huan666/ubuntu:0.2<br>
启动容器：docker run -d --name platform --network info_scan_network -p 16666:16666 -p 18888:18888 -p 17777:17777 -p 15555:15555 -p 19999:19999 -it registry.cn-hangzhou.aliyuncs.com/huan666/ubuntu:0.2 /bin/bash<br>
进入容器：docker exec -it 容器ID /bin/bash<br>
修改服务器IP：/etc/nginx/conf.d/*、/TIP/info_scan/finger.sh中ip_address字段、/TIP/info_scan/static/js/common.js<br>
启动平台服务：bash /TIP/info_scan/server_check.sh start、service nginx start<br>
访问地址：http://ip:19999/index/<br>
参数配置：平台-参数配置-系统配置下修改为有效的key，点击导航栏的重启按钮<br>


<h2>便携版本安装：</h2>
Linux服务器账号密码：huan/admin@123<br>
nginx账号密码：admin/123456<br>
web账号密码：admin/123456<br>
mysql账号密码：admin/123456<br>
1. 登录系统，在参数配置-系统配置下，修改key信息<br>
2. 修改/TIP/info_scan/static/js/common.js和/TIP/info_scan/finger.sh文件第一行和第二行修改为自己服务器的IP地址<br>
3. 系统启动参数：bash /TIP/info_scan/server_check.sh -h，nginx和mysql服务开机自启，如未开启成功，需执行service nginx start和service mysql start开启服务<br>
4. 修改/etc/nginx/conf.d/目录下所有文件中server_name字段替换为自己服务器的IP地址，重启nginx服务器<br>
5. 入口地址：http://服务器IP:19999/index/<br>

##### 便携版下载链接
- [info_scan_2025.01](https://pan.quark.cn/s/81003c01a616#/list/share)：2025.01.07更新，夸克网盘。
- [info_scan_2024.10](https://pan.quark.cn/s/81003c01a616#/list/share)：2024.10.07更新，夸克网盘（网盘空间不足，已删除。）。
- [info_scan_2024.08](https://pan.baidu.com/s/19EPOyjgf0JxbbOYymUr2vg?pwd=sufy)：2024.08.14、2024.08.29更新，百度网盘。
<br><br>

<h2>系统源码安装：</h2>
注意：<br><br>
保证系统正常运行需要2个项目：<br><br>

- [info_scan](https://github.com/huan-cdm/info_scan)：漏洞扫描主系统<br>
- [batch_scan_domain](https://github.com/huan-cdm/batch_scan_domain)：xray+rad批量扫描，通过info_scan进行控制<br>


<h2>集成相关工具：</h2> 
漏洞扫描类：struts2、weblogic、shiro、springboot、thinkphp、泛微OA、tomcat、fastjson、marshalsec、nacos、elasticsearch、tomcat、致远OA、用友OA、金蝶OA、万户OA <br>
综合漏洞扫描类：afrog、fscan、hydra、urlfinder、vulmap、nuclei、xray <br>
信息收集类：bbscan、ehole、nmap、otx威胁情报、crt子域名、crawlergo、waf识别、FUZZ<br>
未授权专项：redis、mongodb、memcached、zookeeper、ftp、CouchDB、docker、Hadoop、NFS（安装apt-get install nfs-common）、rsync、bcrypt。
<br><br>
<h2>bilibili教程：</h2>

- [info_scan_2024-10-12更新](https://www.bilibili.com/video/BV1Gt28YFEr3)<br>
- [info_scan_2025-1-4更新](https://www.bilibili.com/video/BV1surWYJEHX)<br>


<h2>nginx配置401认证：</h2>
配置方法：<br>
1. sudo apt-get install apache2-utils  #安装apache2-utils工具包<br>
2. sudo htpasswd -c /etc/nginx/htpasswd username #按照提示输入密码，username是你想要添加的用户名<br>
3. cp info_scan/nginx_conf/nginx_401.conf /etc/nginx/conf.d/ #将项目中关于401认证的配置文件复制到nginx自定义目录下，/etc/nginx/conf.d/目录会通过nginx.conf加载<br>
4. service nginx restart #重启服务生效<br>

<h2>更新日志：</h2>
<ul>
<li>
2025-1-12更新<br> 
1. 新增icon图标hash计算，可直接将计算结果赋值给fofa查询输入框；<br>
2. 新增开启扫描器显示当前程序状态；<br>
3. 已知问题处理与优化；<br>
4. 新增密码字典生成器；<br>
5. 新增MySQL数据库docker环境，下载可直接使用，自带系统所需的数据库和表；<br>
6. 新增平台+MySQL镜像<br>
</li>
<li>
2025-1-6更新<br> 
1. requirements.txt优化，删除掉python自带的库；<br>
2. 已知问题处理与优化；<br>
3. 便携版本更新-2025.01.07；<br>
</li>
<li>
2025-1-2更新<br> 
1. 新增bcrypt解密；<br>
2. 已知问题处理与优化；<br>
</li>
<li>
2024-12-27更新<br> 
1. 新增Elasticsearch未授权扫描；<br>
2. 下线部分冗余功能；<br>
3. 已知问题处理与优化；<br>
4. 新增指纹识别开关配置；<br>
</li>
<li>
2024-12-22更新<br> 
1. 新增redis、mongodb、memcached、zookeeper、ftp、CouchDB、docker、hadoop、NFS未授权漏洞扫描、rsync；<br>
2. 已知问题处理与优化；<br>
3. 新增资产校验开关,通过配置文件自定义是否校验资产格式；<br>
4. 替换掉部分alert弹窗,修改为自定义弹窗,包括批量漏洞扫描和信息收集等；<br>
5. 优化通过fofa获取资产接口,去掉之前的只保留以协议开头的资产，可获取所有资产；<br>
6. 弹窗页面整体从index.html迁移到tanchuang.html；<br>
</li>
<li>
2024-12-15更新<br> 
1. 更改ICP备案查询接口；<br>
2. 通过selenium库模拟用户点击行为防止被封禁；<br>
3. 已知问题处理与优化；<br>
4. 新增401认证；<br>
</li>
<li>
2024-12-09更新<br> 
1. 新增MSF Builder；<br>
2. 已知问题处理与优化；<br>
3. 新增接口请求自动刷新session,接口不请求情况下按照配置的时间失效；<br>
4. 新增资产扩展,扩大资产范围，提高漏洞数目；<br>
5. 新增subfinder扩展；<br>
</li>
<li>
2024-12-05更新<br> 
1. 新增网站导航和渗透测试常用命令；<br>
2. 已知问题处理与优化；<br>
</li>
<li>
2024-11-25更新<br> 
1. 新增前端配置会话过期时间，并自动加载配置；<br>
2. 已知问题处理与优化；<br>
3. 新增前端fofa配置，并自动加载配置；<br>
</li>
<li>
2024-11-24更新<br> 
1. fofa查询日志优化,修改为通过搜索语法查询历史资产；<br>
2. 已知问题处理与优化；<br>
3. 新增万户OA漏洞扫描；<br>
4. 新增会话过期时间限制，通过配置文件配置；<br>
</li>
<li>
2024-11-21更新<br> 
1. fofa资产发现进度查询；<br>
2. 已知问题处理；<br>
3. dnslog查询功能优化,通过弹窗异步显示到表格中；<br>
</li>
<li>
2024-11-13更新<br> 
1. 新增致远OA漏洞扫描功能；<br>
2. 新增用友OA漏洞扫描功能；<br>
3. 新增金蝶OA漏洞扫描功能；<br>
4. 已知问题处理；<br>
</li>
<li>
2024-11-04更新<br> 
1. 前端页面优化；<br>
2. 新增资产优化功能,可通过关键字对资产进行过滤与排除；<br>
3. 已知问题处理；<br>
4. 新增资产文件下载功能；<br>
</li>
<li>
2024-10-30更新<br> 
1. 存活检测程序运行时间统计；<br>
2. 接口额度初始化添加二次验证；<br>
3. xray监听运行时间统计；<br>
4. 已知问题处理与优化；<br>
</li>
<li>
2024-10-27更新<br> 
1. 新增信息收集类扫描器耗时统计；<br>
2. 已知问题处理与优化；<br>
3. 新增漏洞扫描类扫描器耗时统计；<br>
</li>
<li>
2024-10-20更新<br> 
1. 端口启动方式修改为单独开启一个新的线程放后台取队列中的IP进行扫描；<br>
2. 已知问题处理与优化；<br>
</li>
<li>
2024-10-15更新<br> 
1. 下线单个扫描入口；<br>
2. 已知问题处理与优化；<br>
3. 新增删除报告二次验证；<br>
</li>
<li>
2024-10-11更新<br> 
1. 第三方接口额度和剩余额度动态显示；<br>
2. 第三方接口查询次数限制；<br>
3. 已知问题处理与优化；<br>
4. 报告生成函数优化；<br>
</li>
<li>
2024-10-09更新<br> 
1. 统计第三方接口查询次数；<br>
2. 已知问题处理；<br>
3. 前端页面布局调整；<br>
4. 扫描器参数配置调整为通过弹窗显示；<br>
</li>
<li>
2024-10-07更新<br> 
1. 系统优化；<br>
2. 便携版更新；<br>
3. 系统管理新增指纹识别结果提示；<br>
4. 新增扫描前判断是否进行指纹识别,未进行指纹识别无法开启扫描程序；<br>
5. 新增标题图标；<br>
</li>
<li>
2024-09-28更新<br> 
1. 新增tomcat和nacos字典配置；<br>
2. 新增fscan扫描端口可前端配置和选择；<br>
3. xray未开启监听情况下，爬虫流量转发不通过时间差控制；<br>
4. 新增文本框行数查看功能；<br>
5. 已知问题处理和优化；<br>
</li>
<li>
2024-09-26更新<br> 
1. 弱口令扫描字典路径修改为通过配置文件配置；<br>
2. 增加字典是否添加成功判断逻辑；<br>
3. 已知问题处理；<br>
4. 开启爬虫流量转发会判断是否开启xray被动监听，否则不允许开启爬虫流量转发，爬虫不转发流量不需要开启xray被动监听逻辑；<br>
5. 关闭爬虫程序脚本优化；<br>
</li>
<li>
2024-09-23更新<br> 
1. 新增弱口令扫描前端字典配置功能；<br>
2. 前端页面优化；<br>
3. 已知问题处理；<br>
</li>
<li>
2024-09-22更新<br> 
1. 新增fofa查询日志查看与删除；<br>
2. 前端页面优化；<br>
3. 已知问题处理；<br>
</li>
<li>
2024-09-18更新<br> 
1. 新增爬虫扫描；<br>
2. 新增爬虫扫描流量代理；<br>
3. xray+crawlergo联动批量扫描<br>
4. 已知问题处理；<br>
</li>
<li>
2024-09-13更新<br> 
1. 新增40xbypass fuzz工具；<br>
2. 已知问题处理；<br>
</li>
<li>
2024-09-11更新<br> 
1. 新增fastjson1.2.24和fastjson1.2.47反序列化漏洞扫描；<br>
2. 前端页面优化；<br>
3. 已知问题处理；<br>
4. 新增端口扫描前端可自定义端口,并在文本框中显示；<br>
5. 新增WAF识别,识别完系统自动过滤存在WAF资产；<br>
</li>
<li>
2024-09-08更新<br> 
1. 新增Elasticsearch远程命令执行漏洞和插件目录穿越漏洞检测；<br>
2. 新增JNDI服务管理；<br>
</li>
<li>
2024-09-05更新<br> 
1. tomcat和nacos口令爆破字典文件在dict目录下配置；<br>
</li>
<li>
2024-09-03更新<br> 
1. 新增tomcat管理后台弱口令扫描；<br>
2. 前端页面优化；<br>
3. 已知问题处理；<br>
</li>
<li>2024-08-29更新<br> 
1. 新增ES数据库未授权访问批量扫描；<br>
2. 新增nacos相关漏洞扫描；<br>
3. 新增程序运行状态显示绿色,停止状态显示红色；<br>
4. shodan修改为可配置多个key,系统随机调用；<br>
5. 便携版更新到最新版；<br>
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
<li>
2024-08-15更新<br> 
1. 新增泛微OA漏洞扫描；<br> 
2. 优化fscan扫描；<br> 
3. 新增信息收集工具聚合；<br> 
4. 新增漏洞扫描和信息收集下拉列表重置选项；<br> 
5. 其他已知问题处理；<br> 
6. 前端页面调整；<br> 
</li>
<li>
2024-08-09更新<br>
1. 优化基于证书查询子域名接口；<br>
2. 优化基于otx查询历史url接口；<br>
3. 新增thinkphp漏洞扫描；<br>
4. 漏洞扫描工具聚合展示,通过js控制显示与隐藏；<br>
5. 新增基于证书查询子域名接口和基于otx查询历史url接口状态展示；<br>
6. 新增资产发现前端指定查询条数；<br>
7. 新增基于otx查询历史url接口前端关闭接口按钮；<br>
8. 优化报告整合功能；<br>
9. 其他已知问题处理；<br>
10. 前端页面调整；<br>
</li>
<li>
2024-08-01更新<br>
1. 重点资产新增thinkphp数量查询；<br>
2. 资产查看修改为5秒自动刷新；<br>
3. 新增文本框重置功能；<br>
4. 资产管理操作方法提示更新；<br>
5. 新增一键打开所有报告；<br>
6. 新增操作按钮提示语，通过onmouseenter和onmouseleave事件；<br>
7. 部分已知问题处理；<br>
8. httpx扫描器更新到v1.6.7版本；<br>
</li>
<li>
2024-07-28更新<br>
1. 新增一键springboot、shiro、struts2、weblogic漏洞扫描；<br>
2. 系统管理功能修改为自动刷新；<br>
3. 前端页面调整；<br>
4. 重点资产新增phpmyadmin数量查询；<br>
5. 部分已知问题处理；<br>
</li>
<li>
2024-07-24更新<br>
1. 重点资产识别规则通过存入数据库和配置文件，可通过配置文件选择；<br>
2. 页面新增筛选规则存入数据库；<br>
3. 页面新增一键删除所有规则，或者通过规则名称删除；<br>
4. 前端页面调整；<br>
5. 已知问题处理；<br>
</li>
<li>
2024-07-18更新<br>
1. 系统启动脚本优化更改为批量开启、关闭、重启；<br>
2. 目录扫描模块优化；<br>
3. 系统管理模块优化；<br>
4. 新增在线预览总报告；<br>
5. 新增前端重启相关服务功能；<br>
6. 页面调整；<br>
7. 已知问题处理；<br>
</li>
<li>
2024-07-07更新<br>
1. 新增弱口令扫描模块；<br>
2. 服务启动脚本优化；<br>
3. 部分已知问题处理；<br>
</li>
<li>
2024-07-01更新<br>
1. 新增通过fofa发现资产功能；<br>
2. 已知问题处理；<br>
</li>
<li>
2024-06-25更新<br>
1. 新增shiro、springboot漏洞扫描；<br>
2. 前端页面调整；<br>
3. 已知问题处理；<br>
</li>
<li>
2024-06-25之前<br>
系统开发阶段......
</li>
</ul>

<h2>系统使用说明：</h2>
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
项目部署目录<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/project.png"/><br><br>
程序文件<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/code.png"/><br><br>
服务启动参数<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/backservicemanage.png"/><br><br>
系统登录<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/login1.jpg"/>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/login2.jpg"/><br><br>
IP基础信息查询<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/ipbasicinfo.png"/><br><br>
展开收起<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhedie.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/zhankai.png"/><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/partconfigpage.png"/><br><br>
数据展示<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/service.png"/><br><br>
目录扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dirscanpic.jpg"/><br><br>
漏洞报告<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/report.png"/><br><br>
资产发现<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/assetfind1.png"/>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/assetfind2.png" /><br><br>
弱口令扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/weakpasswd.png" /><br><br>
总报告在线预览<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/onlineyulan.jpg" /><br><br>
特殊字符校验<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/saferule.png" /><br><br>
批量扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/piliang1scan.png" /><br><br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/piliang2scan.png" /><br><br>
JNDI服务管理<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/jndi.png" /><br><br>
fofa语法日志<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/fofaselectlog.png" /><br><br>
弱口令扫描字典配置<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/dictconfig.png" /><br><br>
ES数据库漏洞扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/elasticsearch_scan.png" /><br><br>
复核界面<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/recheck.png" /><br><br>
致远OA漏洞扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/seeyonscan.png" /><br><br>
用友OA漏洞扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/yonsuitescan.png" /><br><br>
金蝶OA漏洞扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/kingdeescan.png" /><br><br>
万户OA漏洞扫描<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/wanhuscan.png" /><br><br>
dnslog<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/ceyednslog.png" /><br><br>
系统参数配置<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/sys_part_conf.png" /><br><br>
网站导航<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/daohang.png" /><br><br>
401认证<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/401_auth.png" /><br><br>
未授权专项<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/weishouquan.png" /><br><br>
icon_hash计算<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/iconhash.png" /><br><br>
密码字典<br>
<img src="https://raw.githubusercontent.com/huan-cdm/info_scan/main/images/passdict.png" /><br><br>