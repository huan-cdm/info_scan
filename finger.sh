#! /bin/bash
# 自定义全局变量本机IP地址
ip_address="x.x.x.x"
# 爬虫流量代理地址
proxy_ip="http://127.0.0.1:7777"
case "${1}" in

    #指纹识别脚本
    finger)
    python3 ./tiderfinger/TideFinger.py -u ${2} | grep "Banner\|CMS_finger"
	;;
    

    #IP归属地查询
    location)
    locat=`curl cip.cc/${2} | grep "地址"`
    echo "${locat}"
    ;;

    #IP归属地查询
    location1)
    locat1=`curl cip.cc/${2} | grep "数据二"`
    echo "${locat1}"
    ;;

    


    #操作系统识别
    osscan)
    ping_result=$(ping ${2} -c 3 2>&1)
    #判断上一条命令知否执行成功
    if [ $? -eq 0 ]; then  
    # extract the TTL value  
    num=$(echo "$ping_result" | grep "ttl" | awk -F ' ' '{print $6}' | uniq | sed 's/ttl=//')  
      
    if [ ${num} -lt 100  ];then  
        echo "Linux"  
    elif [ ${num} -ge 100 ];then  
        echo "Windows"  
    else  
        echo "Not Found"  
    fi
      
    else  
        echo "Not Found"  
    fi
    ;;


    #判断是否存在CDN
    CDN_scan)
    cdn_result=$(nslookup ${2} | grep "Address" | wc -l | uniq 2>&1)
    #判断上一条命令是否执行成功
    if [ $? -eq 0 ];then
        num=$(nslookup ${2} | grep "Address" | wc -l | uniq)
        if [ ${num} -ge 3 ];then
            echo "有CDN"
        else
            echo "无CDN"
        fi
    else
        echo "Not Found"
    fi
    ;;

    #masscan端口扫描
    masscan_port)
    masscan_result=$(masscan $2 -p 1-10000 --rate=10000 | grep "Discovered")
    echo "${masscan_result}"
    ;;

    #nmap端口扫描
    nmap_port)
    echo "[+]$2" >> ./result/nmap.txt
    /usr/bin/nmap -Pn -sS -sV -T4  $2  -p $3  --min-rate=10000 | grep "tcp"  >> ./result/nmap.txt
    ;;

    #nmap队列扫描运行状态
    nmapstatus)
	ps_nmap=`ps -aux | grep /usr/bin/nmap | wc -l`
	if (( $ps_nmap > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    #开启nuclei扫描(原始URL)
    startnuclei_url)
    #   常用参数（https://blog.csdn.net/qq_35607078/article/details/131648824）
    #   -bulk-size 限制并行的主机数 默认25 
    #   -c 限制并行的模板数 默认25
    #   -rate-limit 每秒发送的最大请求数 默认150 
    #   -l 批量扫描
    #   -t 要运行的模板或模板目录列表
    #   -timeout 超时前等待的时间(以秒为单位) 默认 10秒
    #   dict="/root/nuclei-templates/http"
    # dict="/root/nuclei-templates/http"
	./nuclei_server/nuclei -l /TIP/batch_scan_domain/url.txt -t ${2} -c 10 -bulk-size 10  -rate-limit 30 -timeout 3 > ./result/nucleiresult.txt
	;;

    #开启nuclei扫描(通过第三方接口获取的URL)
    startnuclei_result)
    dict="/root/nuclei-templates/http"
	./nuclei_server/nuclei -l /TIP/batch_scan_domain/result.txt -t ${dict} -c 10 -bulk-size 10  -rate-limit 30 -timeout 3 > ./result/nucleiresult.txt
	;;

    #nuclei状态查询
    nucleistatus)
    ps_nuclei=`ps -aux | grep "nuclei_server/nuclei -l /TIP/batch_scan_domain" | wc -l`
	if (( $ps_nuclei > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #xray状态
    xraystatus)
    num_xray=`ps -aux | grep xray_linux_amd64 | wc -l`
    
    if (( $num_xray > 1 ))
    then
        echo "running"
    else
        echo "stop"
    
    fi
    ;;

    # 关闭xray
    stopxrayscan)
    pidd=`ps -aux | grep xray_linux_amd64 |awk -F " " '{print $2}'`
    
    for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启xray
    startxray_scan)
    # 需要进入下面的路径，否则无法启动程序
    cd /TIP/batch_scan_domain/
    # 使用date命令生成当前的时间戳  
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")  
    #拼接文件名  
    OUTPUT_FILE="/TIP/batch_scan_domain/report/xray-testphp-${TIMESTAMP}.html" 
    
    nohup /TIP/batch_scan_domain/xray_engine/xray_linux_amd64 webscan --listen 127.0.0.1:7777 --html-output "$OUTPUT_FILE" > /dev/null 2>&1 &
    # 打印出生成的文件名  
    echo "HTML output saved to $OUTPUT_FILE"

    ;;

    #rad运行状态
    radstatus)
    num_rad=`ps -aux | grep rad_linux_amd64 | wc -l`
    if (( $num_rad > 1 ))
    then
        echo "running"
    else
        echo "stop"
    fi
    ;;

    #历史URL数量
    history_url_num)
    his_num=`cat /TIP/batch_scan_domain/result.txt | wc -l`
    echo "${his_num}"
    ;;

    #文本框中URL数量
    textarea_url_num)
    textarea_url_num_value=`cat /TIP/batch_scan_domain/url.txt | wc -l`
    echo "${textarea_url_num_value}"
    ;;



    #################################目录扫描相关脚本#####################################################
    #目录扫描状态
    dirsearchstatus)
	ps_dirsearch=`ps -aux | grep dirsearch.py | wc -l`
	if (( $ps_dirsearch > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    #文件清洗服务运行状态
	fileclean)
	ps_fileclean=`ps -aux | grep filterdirsearchdata.sh | wc -l`
	if (( $ps_fileclean > 2 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    #目录扫描url数量
    dirsearchtargetnum)
	num=`cat /TIP/batch_scan_domain/url.txt | wc -l`
	echo "${num}"
	;;

    #目录扫描同步后的结果
    dirsearchsyncresult)
    dirsearchsyncresult_value=`cat /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt  | wc -l`
    #数量减2才是正确数量
    direserach_rsync_value=$[${dirsearchsyncresult_value}-2]
    echo "${direserach_rsync_value}"
    ;;

    #目录扫描启动脚本
    dirsearchscan)
    python3 /TIP/info_scan/dirsearch/dirsearch.py -l /TIP/batch_scan_domain/url.txt -e $2 -r -R $3 -i $4 -w $5 -t $6 exclude-sizes = 0b,123gb   > /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt
    ;;

    #目录扫描原始数量/reports目录下
    dirsearchscancount)
    dirsearchscancount_value=`cat /TIP/info_scan/dirsearch/reports/*/*.txt | wc -l`
    #数量减2才是正确数量
    direserach_value=$[${dirsearchscancount_value}-2]
    echo "${direserach_value}"
    ;;

    #kill 目录扫描进程
    killdirsearch)
	pidd=`ps -aux | grep "dirsearch.py" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;

    #报告阈值过滤
    thresholdvaluefilter)
    for n in `cat /TIP/info_scan/result/thresholdvalue.txt`
    do
        cat /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt  | grep -v ${n} > /TIP/info_scan/dirsearch/finalreport/dirsearchreport_tmp.txt
        mv /TIP/info_scan/dirsearch/finalreport/dirsearchreport_tmp.txt /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt
    done
    ;;

    #数据处理保留IP的url
    withdrawip)
    #去重
    sort /TIP/batch_scan_domain/url.txt | uniq >  /TIP/batch_scan_domain/url_tmp.txt
    mv /TIP/batch_scan_domain/url_tmp.txt /TIP/batch_scan_domain/url.txt

    #指定文件路径
    file="/TIP/batch_scan_domain/url.txt"
    #正则表达式匹配IPv4地址
    ip_pattern="(http://|https://)([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}"
    #使用grep命令查找所有匹配的IP地址
    grep -oE "$ip_pattern" "$file" > /TIP/batch_scan_domain/url_tmp.txt
    mv /TIP/batch_scan_domain/url_tmp.txt /TIP/batch_scan_domain/url.txt
    ;;

    #数据处理保留所有url
    uniqfilterdirsearch)
    #去重
    sort /TIP/batch_scan_domain/url.txt | uniq >  /TIP/batch_scan_domain/url_tmp.txt
    mv /TIP/batch_scan_domain/url_tmp.txt /TIP/batch_scan_domain/url.txt
    ;;

    #报告过滤黑名单同步
    blacklistsyncshell)
	num=`cat /TIP/info_scan/result/filterdirsearchblack.txt | wc -l`
    if (( $num == 0 ))
    then
        #echo "不存在过滤数据"
        echo "不存在过滤数据"
    else
        #echo "存在过滤数据"
        for i in `cat /TIP/info_scan/result/filterdirsearchblack.txt`
        do
            cat /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt  | grep -v ${i} > /TIP/info_scan/dirsearch/finalreport/dirsearchreport_tmp.txt
            mv /TIP/info_scan/dirsearch/finalreport/dirsearchreport_tmp.txt /TIP/info_scan/dirsearch/finalreport/dirsearchreport.txt
        done
        
    fi
    ;;

    #存活检测状态码为200
    survivaldetection)
    /TIP/info_scan/httpx_server/httpx -l /TIP/batch_scan_domain/url.txt -mc 200 > /TIP/batch_scan_domain/url_tmp.txt
    # 删除空行
    sed '/^$/d' /TIP/batch_scan_domain/url_tmp.txt > /TIP/batch_scan_domain/url.txt
    ;;

    #urlfinder引擎启动脚本
    urlfinder_start)
    #使用date命令生成当前的时间戳  
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    rm -rf /TIP/info_scan/urlfinder_server/result_tmp.txt
    /TIP/info_scan/urlfinder_server/URLFinder -f /TIP/batch_scan_domain/url.txt -m 2 -s all -s 200 -o /TIP/info_scan/urlfinder_server/report/urlfinder-${TIMESTAMP}.html > /TIP/info_scan/urlfinder_server/result_tmp.txt
    ;;



    # urlfinder扫描器状态
    urlfinder_status)
    ps_urlfinder_scan=`ps -aux | grep  "URLFinder"  | wc -l`
	if (( $ps_urlfinder_scan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;



    #批量判断cdn
    batch_cdn_scan)
    cdn_result=$(nslookup ${2} | grep "Address" | wc -l | uniq 2>&1)
    #判断上一条命令是否执行成功
    if [ $? -eq 0 ];then
        num=$(nslookup ${2} | grep "Address" | wc -l | uniq)
        if [ ${num} -ge 3 ];then 
            echo "有CDN"
        else 
            echo "无CDN"
        fi
    else
        echo "Not Found"
    fi
    ;;

    #不存在cdn的url脚本
    recognize_no_cdn)
    urlvalue=`cat /TIP/batch_scan_domain/url.txt | grep $2`
    echo "${urlvalue}"
    ;;

    # weblogic_poc扫描
    weblogic_poc_scan)
    python3 /TIP/info_scan/weblogin_scan/WeblogicScan.py -f /TIP/info_scan/weblogin_scan/target.txt | grep "+" > /TIP/info_scan/result/weblogic_poc.txt
    ;;

    # weblogic_poc运行状态
    weblogic_status)
	ps_weblogic=`ps -aux | grep WeblogicScan.py | wc -l`
	if (( $ps_weblogic > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;


    #kill weblogic漏洞扫描程序
    killweblogicprocess)
	pidd=`ps -aux | grep "WeblogicScan.py" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
    done
	;;


    #kill weblogic_poc
    killweblogic_poc)
	wpid=`ps -aux | grep "WeblogicScan.py" |awk -F " " '{print $2}'`
	for i in ${wpid}
	do
		kill -9 ${i}
    done
	;;
    

    # struts2漏洞扫描
    struts2_poc_scan)
    python3 /TIP/info_scan/struts2_scan/Struts2Scan.py -f /TIP/batch_scan_domain/url.txt | grep "*" | grep -v "results" > /TIP/info_scan/result/struts2_poc.txt
    ;;

    # struts2_poc运行状态
    struts2_status)
	ps_struts2=`ps -aux | grep Struts2Scan.py | wc -l`
	if (( $ps_struts2 > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    #kill struts2进程
    killstruts2process)
	pidd=`ps -aux | grep "Struts2Scan.py" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
    done
	;;

    # EHole指纹识别
    ehole_finger_scan)
    /TIP/info_scan/EHole_linux_amd64/EHole_linux_amd64 finger -l /TIP/batch_scan_domain/url.txt | grep "\[" > /TIP/info_scan/result/ehole_finger.txt
    ;;

    # BBScan敏感信息扫描
    bbscan_shell)
    cd /TIP/info_scan/BBScan
    python3 BBScan.py -f /TIP/batch_scan_domain/url.txt | grep "[+]" > /TIP/info_scan/result/bbscan_info.txt
    ;;


    # bbscan运行状态
    bbscan_status)
	ps_bbscan=`ps -aux | grep BBScan.py | wc -l`
	if (( $ps_bbscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;


    # vulmap漏洞扫描
    vulmapscan_shell)
    cd /TIP/info_scan/vulmap
    python3 vulmap.py -f /TIP/batch_scan_domain/url.txt -a  ${2} | grep "[+]" > /TIP/info_scan/result/vulmapscan_info.txt
    ;;


    # vulmap运行状态
    vulmapscan_status)
	ps_vulmapscan=`ps -aux | grep vulmap.py | wc -l`
	if (( $ps_vulmapscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    # ceye_dns记录
    ceye_dns)
    ceye_dns_result=`curl -s "http://api.ceye.io/v1/records?token=${2}&type=dns"`
    if [ -n "${ceye_dns_result}" ];then
        echo "${ceye_dns_result}"
    else
        echo "Error: Failed to retrieve CEYE DNS records." 
    fi
    ;;


    # 启动afrog程序
    startafrogprocess)
    cd /TIP/info_scan/afrog_scan/  
    if [ -f ./afrog ]; then  
        ./afrog -T /TIP/batch_scan_domain/url.txt | grep "http" > /TIP/info_scan/result/afrog_vuln.txt  
    else  
        echo "Error: afrog not found in /TIP/info_scan/afrog_scan/"  
    fi  
    ;;

    # afrog运行状态
    afrogscan_status)
	ps_afrogscan=`ps -aux | grep startafrogprocess | wc -l`
	if (( $ps_afrogscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    #kill afrog进程
    killafrog)
	pidd=`ps -aux | grep "afrog" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;
    
    #kill nmap进程
    killnmap)
	pidd=`ps -aux | grep "nmap" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;

    #kill vulmap进程
    killvulmap)
	pidd=`ps -aux | grep "vulmap" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;
    
     #kill nuclei进程
    killnuclei)
	pidd=`ps -aux | grep "nuclei" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;


    # 启动fscan扫描程序默认端口
    startfscanprocessmoren)
    cd /TIP/info_scan/fscan_tool/
    if [ -f ./fscan ]; then  
        # grep -vE  过滤多个参数
        ./fscan -hf /TIP/info_scan/fscan_tool/ip.txt -nopoc -p $2 | grep -vE 'start|已完成|扫描结束|alive' > /TIP/info_scan/result/fscan_vuln.txt
        echo "Error: fscan not found in /TIP/info_scan/fscan_tool/"  
    fi  
    ;;




    #kill fscan进程
    killfscan)
	pidd=`ps -aux | grep "fscan" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;

    # fscan运行状态
    fscan_status)
	ps_fscanscan=`ps -aux | grep startfscanprocess | wc -l`
	if (( $ps_fscanscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    # shiro 默认key扫描
    shiro_scan)
    python3 /TIP/info_scan/shiro-tool/shiro-exploit.py check -u $2 >>  /TIP/info_scan/result/shiro_vuln.txt
    ;;

    # shiro运行状态
    shiro_status)
	ps_shiroscan=`ps -aux | grep shiro-exploit.py | wc -l`
	if (( $ps_shiroscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;


    #关闭shiro漏洞扫描程序
    killshirovulnscanprocess)
	pidd=`ps -aux | grep "shiro-exploit.py" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
    done
	;;


     # httpx运行状态
    httpx_status)
	ps_httpxscan=`ps -aux | grep /TIP/info_scan/httpx_server/httpx | wc -l`
	if (( $ps_httpxscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    # 自定义指纹列表过滤
    finger_filter_shell)
    result=`cat /TIP/info_scan/result/ehole_finger.txt | grep $2`
    echo "$result"
    ;;


    # 总资产URL数量
    url_file_num)
    url_num=`cat /TIP/batch_scan_domain/url_back.txt | wc -l`
    echo "${url_num}"
    ;;

     # 当前资产URL数量
    current_url_file_num)
    url_current_num=`cat /TIP/batch_scan_domain/url.txt | wc -l`
    echo "${url_current_num}"
    ;;

    # Ehole指纹识别运行状态
    ehole_status)
	ps_eholescan=`ps -aux | grep EHole | wc -l`
	if (( $ps_eholescan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;


    #nuclei模板文件查看
    templatenuclei)
    templatenuclei_result=`find $2 -type f`
    echo "${templatenuclei_result}"
    ;;


    # 启动springboot漏洞扫描程序
    start_springboot)
    /TIP/info_scan/SpingBoot_Scan/ssp_linux_amd64 -uf /TIP/batch_scan_domain/url.txt | grep "+" > /TIP/info_scan/result/springboot_result.txt
    ;;


    # springboot扫描运行状态
    springboot_scan_status)
	ps_springbootscan=`ps -aux | grep ssp_linux_amd64 | wc -l`
	if (( $ps_springbootscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

     #关闭springboot漏洞扫描程序
    killspringbootvulnscanprocess)
	pidd=`ps -aux | grep "ssp_linux_amd64" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
    done
	;;


    #kill bbscan进程
    killbbscan)
	pidd=`ps -aux | grep "BBScan.py" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
	;;


    # 调用hydra弱口令扫描工具
    # Ubuntu安装命令：apt-get install hydra
    # centos安装命令：yum install hydra

    # hydra扫描器状态
    hydra_status)
    ps_hydra_scan=`ps -aux | grep  "/usr/bin/hydra"  | wc -l`
	if (( $ps_hydra_scan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;


    # 关闭hydra扫描器
    killhydra)
    pidd=`ps -aux | grep "/usr/bin/hydra" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
    ;;



    # 关闭urlfinder扫描器
    killurlfinder)
    pidd=`ps -aux | grep "URLFinder" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
    ;;


    # 关闭EHole扫描器
    killEHole)
    pidd=`ps -aux | grep "EHole_linux_amd64" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii}
    done
    ;;

    # 调用hydra爆破mysql弱口令
    mysql_weak_password)
    /usr/bin/hydra -L /TIP/info_scan/dict/mysql/user.txt -P /TIP/info_scan/dict/mysql/pass.txt -M /TIP/info_scan/result/hydra_ip.txt mysql > /TIP/info_scan/result/hydra_result.txt
    ;;
    
    # 调用hydra爆破ssh弱口令
     ssh_weak_password)
    /usr/bin/hydra -L /TIP/info_scan/dict/ssh/user.txt -P /TIP/info_scan/dict/ssh/pass.txt -M /TIP/info_scan/result/hydra_ip.txt ssh > /TIP/info_scan/result/hydra_result.txt
    ;;

    # 调用hydra爆破ftp弱口令
     ftp_weak_password)
    /usr/bin/hydra -L /TIP/info_scan/dict/ftp/user.txt -P /TIP/info_scan/dict/ftp/pass.txt -M /TIP/info_scan/result/hydra_ip.txt ftp > /TIP/info_scan/result/hydra_result.txt
    ;;

    # 调用hydra爆破redis弱口令
     redis_weak_password)
    /usr/bin/hydra  -P /TIP/info_scan/dict/redis/pass.txt -M /TIP/info_scan/result/hydra_ip.txt redis > /TIP/info_scan/result/hydra_result.txt
    ;;

    # 调用hydra爆破mssql弱口令
     mssql_weak_password)
    /usr/bin/hydra -L /TIP/info_scan/dict/mssql/user.txt -P /TIP/info_scan/dict/mssql/pass.txt -M /TIP/info_scan/result/hydra_ip.txt mssql > /TIP/info_scan/result/hydra_result.txt
    ;;

    # 前端软重启服务
    restartinfoscan)

    # 软重启info_scan
    pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		kill -9 ${aes} 2>/dev/null
	done
	nohup python3 ./scan_main_web.py > /dev/null 2>&1 &

    # 软重启dirscan
    dirscanpid=`ps -aux | grep  dirscanmain.py | awk -F " " '{print $2}'`
	for dirid in ${dirscanpid}
	do
		kill -9 ${dirid} 2>/dev/null
	done

	nohup python3 ./dirscanmain.py > /dev/null 2>&1 &
    ;;
    


    # 软重启后系统服务状态
    infoscanstatus)
    infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	if (( $infopid > 1 ))
	then
		echo -e "running" 
	else
		echo -e "stop"
	fi
    ;;


    # 关闭所有服务
    stopallserver)
    # 关闭info_scan
	pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		kill -9 ${aes} 2>/dev/null
	done
	

	# 关闭dirscan
	dirscanpid=`ps -aux | grep  dirscanmain.py | awk -F " " '{print $2}'`
	for dirid in ${dirscanpid}
	do
		kill -9 ${dirid} 2>/dev/null
	done

	# 关闭xray
	pidd=`ps -aux | grep 8081 |awk -F " " '{print $2}'`
    
    for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
	done


	# 关闭afrog
	afpid=`ps -aux | grep 8082 |awk -F " " '{print $2}'`
    
    for ii in ${afpid}
	do

		kill -9 ${ii} 2>/dev/null
		
	done



	# 关闭urlfinder
	linkpidd=`ps -aux | grep 8089 |awk -F " " '{print $2}'`
    
    for ii in ${linkpidd}
	do
		
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # 计算springboot、weblogic、struts2、shiro 资产行数,分别传入springboot_file.txt、weblogic_file.txt、struts2_file.txt、shiro_file.txt
    zhongdian_file_num)
    num=`cat /TIP/info_scan/result/keyasset/$2 | wc -l`
    echo "${num}"
    ;;

    # python后端服务展示给前端
    infoinfostatus)
    infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
    if (( $infopid > 1 ))
	then
		echo -e "running  (19999)" 
	else
		echo -e "stop"
	fi
    ;;

    xray_report_status)
    xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
    if (( $xraypid > 1 ))
	then
		echo -e "running  (18888)" 
	else
		echo -e "stop"
	fi
    ;;

    urlfinder_report_status)
    urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
    if (( $urlfinderpid > 1 ))
	then
		echo -e "running  (16666)" 
	else
		echo -e "stop"
	fi
    ;;

    dirsub_sys_status)
    dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
    if (( $dirscanpid > 1 ))
	then
		echo -e "running  (17777)" 
       
	else
		echo -e "stop"
	fi
    ;;

    afrog_report_status)
    afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
    if (( $afrogpid > 1 ))
	then
		echo -e "running  (15555)" 
	else
		echo -e "stop"
	fi
    ;;


    # thinkphp漏洞扫描
    thinkphp_vuln_scan)
    python3 /TIP/info_scan/TPscan/TPscan.py -u $2 >>  /TIP/info_scan/result/thinkphp_vuln.txt
    ;;


    # TPscan运行状态
    TPscan_status)
	ps_tpscan=`ps -aux | grep TPscan.py | wc -l`
	if (( $ps_tpscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

    #关闭thinkphp漏洞扫描程序
    killthinkphpprocess)
	pidd=`ps -aux | grep "TPscan.py" |awk -F " " '{print $2}'`
	for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
    done
	;;


    # 通过otx查询域名绑定的url
    otx_domain_url_shell)
    python3 /TIP/info_scan/basic.py otx_domain_url_lib >> /TIP/info_scan/result/otxhistoryurl.txt
    ;;



    # 通过证书查询子域名
    crt_subdomain_shell)
    python3 /TIP/info_scan/basic.py crt_subdomain_lib >> /TIP/info_scan/result/subdomain.txt
    ;;


    # 通过证书查询子域名运行状态
    crt_subdomain_shell_status)
	crt_subdomain_shell_lib=`ps -aux | grep "crt_subdomain_lib" | wc -l`
	if (( $crt_subdomain_shell_lib > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;


    # 通过otx查询域名运行状态
    otx_domain_url_shell_status)
	ps_otx_domain_url_lib=`ps -aux | grep "otx_domain_url_lib" | wc -l`
	if (( $ps_otx_domain_url_lib > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;


    # 关闭otx_domain_url_shell
    kill_otx_domain_url_shell)
	otx_domain_url_shell_pid=`ps -aux | grep "otx_domain_url_lib" |awk -F " " '{print $2}'`
    
    for ii in ${otx_domain_url_shell_pid}
	do
		
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    #otx历史url数量
    otx_history_url_num)
    otx_his_num=`cat /TIP/info_scan/result/otxhistoryurl.txt | wc -l`
    echo "${otx_his_num}"
    ;;

    # 指纹识别结果数量
    ehole_finger_num)
    ehole_num=`cat /TIP/info_scan/result/ehole_finger.txt | wc -l`
    echo "${ehole_num}"
    ;;

    # 敏感信息结果数量
    bbscan_scan_num)
    bbscan_num=`cat /TIP/info_scan/result/bbscan_info.txt | wc -l`
    echo "${bbscan_num}"
    ;;

    # jndi结果数量
    jndi_num)
    jndi_num=`cat /TIP/info_scan/result/jndi_result.txt | wc -l`
    echo "${jndi_num}"
    ;;

    # struts2结果数量
    struts2_scan_num)
    struts2_num=`cat /TIP/info_scan/result/struts2_poc.txt | wc -l`
    echo "${struts2_num}"
    ;;

    # weblogic结果数量
    weblogic_scan_num)
    weblogic_num=`cat /TIP/info_scan/result/weblogic_poc.txt | wc -l`
    echo "${weblogic_num}"
    ;;


    # shiro结果数量
    shiro_scan_num)
    shiro_num=`cat /TIP/info_scan/result/shiro_vuln.txt | wc -l`
    echo "${shiro_num}"
    ;;

    # springboot结果数量
    springboot_scan_num)    
    springboot_num=`cat /TIP/info_scan/result/springboot_result.txt | wc -l`
    echo "${springboot_num}"
    ;;

    # thinkphp结果数量
    thinkphp_scan_num)    
    thinkphp_num=`cat /TIP/info_scan/result/thinkphp_vuln.txt | wc -l`
    echo "${thinkphp_num}"
    ;;

    # fscan结果数量
    fscan_scan_num)    
    fscan_num=`cat /TIP/info_scan/result/fscan_vuln.txt | wc -l`
    echo "${fscan_num}"
    ;;

    # hydra结果数量
    hydra_scan_num)    
    hydra_num=`cat /TIP/info_scan/result/hydra_result.txt | wc -l`
    echo "${hydra_num}"
    ;;

    # nmap结果数量
    nmap_scan_num)    
    nmap_num=`cat /TIP/info_scan/result/nmap.txt | wc -l`
    echo "${nmap_num}"
    ;;


    # vulmap结果数量
    vulmap_scan_num)    
    vulmap_num=`cat /TIP/info_scan/result/vulmapscan_info.txt | wc -l`
    echo "${vulmap_num}"
    ;;


    # nuclei结果数量
    nuclei_scan_num)    
    nuclei_num=`cat /TIP/info_scan/result/nucleiresult.txt | wc -l`
    echo "${nuclei_num}"
    ;;

    # weaver结果数量
    weaver_scan_num)    
    weaver_num=`cat /TIP/info_scan/result/weaver_vuln.txt | wc -l`
    echo "${weaver_num}"
    ;;


    # subdomain结果数量
    subdomain_scan_num)    
    subdomain_num=`cat /TIP/info_scan/result/subdomain.txt | wc -l`
    echo "${subdomain_num}"
    ;;


    # 关闭crt_subdomain_shell
    kill_crt_subdomain_shell)
	crt_subdomainshell_pid=`ps -aux | grep "crt_subdomain_lib" |awk -F " " '{print $2}'`
    
    for ii in ${crt_subdomainshell_pid}
	do
		
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启泛微OA漏洞扫描
    weaver_exp_scan)
    python3 /TIP/info_scan/weaver_exp/main.py  -f /TIP/batch_scan_domain/url.txt > /TIP/info_scan/result/weaver_vuln.txt
    ;;

    # 泛微OA扫描器运行状态
    weaver_status)
    weaver_lib=`ps -aux | grep "weaver_exp/main.py" | wc -l`
	if (( $weaver_lib > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;


    # 关闭泛微OA漏洞扫描
    kill_weaver_scan)
	weaver_pid=`ps -aux | grep "weaver_exp/main.py" |awk -F " " '{print $2}'`
    
    for ii in ${weaver_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 启动es未授权检测脚本
    start_es_shell)
    python3 /TIP/info_scan/vuln_lib.py es_unauthorized > /TIP/info_scan/result/esunauthorized.txt
    ;;

    # es未授权检测脚本运行状态
    es_unauthorized_status)
    es_unauthorized_ps=`ps -aux | grep "vuln_lib.py es_unauthorized" | wc -l`
	if (( $es_unauthorized_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;


    #es未授权访问漏洞数量
    es_unautorized_num)
    es_num=`cat /TIP/info_scan/result/esunauthorized.txt | wc -l`
    echo "${es_num}"
    ;;


    # 关闭es未授权访问扫描程序
    stopes_unauthorized)
    esscan_pid=`ps -aux | grep "es_unauthorized" |awk -F " " '{print $2}'`
    
    for ii in ${esscan_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # 开启nacos漏洞检测工具
    start_nacos_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py nacos_vuln_scan > /TIP/info_scan/result/nacosvuln.txt
    ;;

    # nacos漏洞扫描程序运行状态
    nacos_vuln_scan_status)
    nacos_scan_ps=`ps -aux | grep "vuln_lib.py nacos_vuln_scan" | wc -l`
	if (( $nacos_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #nacos漏洞数量
    nacos_vuln_num)
    nacos_num=`cat /TIP/info_scan/result/nacosvuln.txt | wc -l`
    echo "${nacos_num}"
    ;;

    
    # 关闭nacos漏洞扫描程序
    stop_nacos_scan)
    nacos_pid=`ps -aux | grep "nacos_vuln_scan" |awk -F " " '{print $2}'`
    
    for ii in ${nacos_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # ---------------未授权访问类漏洞专项---------------
    # 开启redis未授权扫描
    start_redis_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py redis_unauthorizedset_scan_lib > /TIP/info_scan/result/redis_unauthorized.txt
    ;;

    # redis未授权扫描程序运行状态
    redis_vuln_scan_status)
    redis_scan_ps=`ps -aux | grep "vuln_lib.py redis_unauthorizedset_scan_lib" | wc -l`
	if (( $redis_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #redis未授权漏洞数量
    redis_vuln_num)
    redis_num=`cat /TIP/info_scan/result/redis_unauthorized.txt | wc -l`
    echo "${redis_num}"
    ;;

    # 关闭redis漏洞扫描程序
    stop_redis_scan)
    redis_pid=`ps -aux | grep "redis_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${redis_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启mongodb未授权扫描
    start_mongodb_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py mongodb_unauthorizedset_scan_lib > /TIP/info_scan/result/mongodb_unauthorized.txt
    ;;

    # mongodb未授权扫描程序运行状态
    mongodb_vuln_scan_status)
    mongodb_scan_ps=`ps -aux | grep "vuln_lib.py mongodb_unauthorizedset_scan_lib" | wc -l`
	if (( $mongodb_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #mongodb未授权漏洞数量
    mongodb_vuln_num)
    mongodb_num=`cat /TIP/info_scan/result/mongodb_unauthorized.txt | wc -l`
    echo "${mongodb_num}"
    ;;

    # 关闭mongodb漏洞扫描程序
    stop_mongodb_scan)
    mongodb_pid=`ps -aux | grep "mongodb_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${mongodb_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启memcached未授权扫描
    start_memcached_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py memcached_unauthorizedset_scan_lib > /TIP/info_scan/result/memcached_unauthorized.txt
    ;;

    # memcached未授权扫描程序运行状态
    memcached_vuln_scan_status)
    memcached_scan_ps=`ps -aux | grep "vuln_lib.py memcached_unauthorizedset_scan_lib" | wc -l`
	if (( $memcached_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #memcached未授权漏洞数量
    memcached_vuln_num)
    memcached_num=`cat /TIP/info_scan/result/memcached_unauthorized.txt | wc -l`
    echo "${memcached_num}"
    ;;

    # 关闭memcached漏洞扫描程序
    stop_memcached_scan)
    memcached_pid=`ps -aux | grep "memcached_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${memcached_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # 开启zookeeper未授权扫描
    start_zookeeper_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py zookeeper_unauthorizedset_scan_lib > /TIP/info_scan/result/zookeeper_unauthorized.txt
    ;;

    # zookeeper未授权扫描程序运行状态
    zookeeper_vuln_scan_status)
    zookeeper_scan_ps=`ps -aux | grep "vuln_lib.py zookeeper_unauthorizedset_scan_lib" | wc -l`
	if (( $zookeeper_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #zookeeper未授权漏洞数量
    zookeeper_vuln_num)
    zookeeper_num=`cat /TIP/info_scan/result/zookeeper_unauthorized.txt | wc -l`
    echo "${zookeeper_num}"
    ;;


    # 关闭zookeeper漏洞扫描程序
    stop_zookeeper_scan)
    zookeeper_pid=`ps -aux | grep "zookeeper_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${zookeeper_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启ftp未授权扫描
    start_ftp_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py ftp_unauthorizedset_scan_lib > /TIP/info_scan/result/ftp_unauthorized.txt
    ;;

    # ftp未授权扫描程序运行状态
    ftp_vuln_scan_status)
    ftp_scan_ps=`ps -aux | grep "vuln_lib.py ftp_unauthorizedset_scan_lib" | wc -l`
	if (( $ftp_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #ftp未授权漏洞数量
    ftp_vuln_num)
    ftp_num=`cat /TIP/info_scan/result/ftp_unauthorized.txt | wc -l`
    echo "${ftp_num}"
    ;;

    # 关闭ftp漏洞扫描程序
    stop_ftp_scan)
    ftp_pid=`ps -aux | grep "ftp_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${ftp_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启couchdb未授权扫描
    start_couchdb_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py couchdb_unauthorizedset_scan_lib > /TIP/info_scan/result/couchdb_unauthorized.txt
    ;;

    # couchdb未授权扫描程序运行状态
    couchdb_vuln_scan_status)
    couchdb_scan_ps=`ps -aux | grep "vuln_lib.py couchdb_unauthorizedset_scan_lib" | wc -l`
	if (( $couchdb_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;


    #couchdb未授权漏洞数量
    couchdb_vuln_num)
    couchdb_num=`cat /TIP/info_scan/result/couchdb_unauthorized.txt | wc -l`
    echo "${couchdb_num}"
    ;;

    # 关闭couchdb漏洞扫描程序
    stop_couchdb_scan)
    couchdb_pid=`ps -aux | grep "couchdb_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${couchdb_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启docker未授权扫描
    start_docker_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py docker_unauthorizedset_scan_lib > /TIP/info_scan/result/docker_unauthorized.txt
    ;;

    # docker未授权扫描程序运行状态
    docker_vuln_scan_status)
    docker_scan_ps=`ps -aux | grep "vuln_lib.py docker_unauthorizedset_scan_lib" | wc -l`
	if (( $docker_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    #docker未授权漏洞数量
    docker_vuln_num)
    docker_num=`cat /TIP/info_scan/result/docker_unauthorized.txt | wc -l`
    echo "${docker_num}"
    ;;

    # 关闭docker漏洞扫描程序
    stop_docker_scan)
    docker_pid=`ps -aux | grep "docker_unauthorizedset_scan_lib" |awk -F " " '{print $2}'`
    
    for ii in ${docker_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # ---------------未授权访问类漏洞专项---------------



    # tomcat漏洞扫描程序运行状态
    tomcat_vuln_scan_status)
    tomcat_scan_ps=`ps -aux | grep "vuln_lib.py tomcat_vuln_scan" | wc -l`
	if (( $tomcat_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 关闭tomcat漏洞扫描程序
    stop_tomcat_scan)
    tomcat_pid=`ps -aux | grep "tomcat_vuln_scan" |awk -F " " '{print $2}'`
    for ii in ${tomcat_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启tomcat漏洞扫描程序
    start_tomcat_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py tomcat_vuln_scan > /TIP/info_scan/result/tomcat_vuln.txt
    ;;

    #tomcat漏洞数量
    tomcat_vuln_num)
    tomcat_num=`cat /TIP/info_scan/result/tomcat_vuln.txt | wc -l`
    echo "${tomcat_num}"
    ;;

    # 致远OA漏洞扫描程序运行状态
    seeyon_vuln_scan_status)
    seeyon_scan_ps=`ps -aux | grep "vuln_lib.py seeyon_vuln_scan" | wc -l`
	if (( $seeyon_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 关闭致远OA漏洞扫描程序
    stop_seeyon_scan)
    seeyon_pid=`ps -aux | grep "seeyon_vuln_scan" |awk -F " " '{print $2}'`
    for ii in ${seeyon_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    # 开启致远OA漏洞扫描程序
    start_seeyon_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py seeyon_vuln_scan > /TIP/info_scan/result/seeyon_vuln.txt
    ;;

    #致远OA漏洞数量
    seeyon_vuln_num)
    seeyon_num=`cat /TIP/info_scan/result/seeyon_vuln.txt | wc -l`
    echo "${seeyon_num}"
    ;;


    # 用友OA漏洞扫描程序运行状态
    yonsuite_vuln_scan_status)
    yonsuite_scan_ps=`ps -aux | grep "vuln_lib.py yonsuite_vuln_scan" | wc -l`
	if (( $yonsuite_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 关闭用友OA漏洞扫描程序
    stop_yonsuite_scan)
    yonsuite_pid=`ps -aux | grep "yonsuite_vuln_scan" |awk -F " " '{print $2}'`
    for ii in ${yonsuite_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # 开启用友OA漏洞扫描程序
    start_yonsuite_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py yonsuite_vuln_scan > /TIP/info_scan/result/yonsuite_vuln.txt
    ;;


    #用友OA漏洞数量
    yonsuite_vuln_num)
    yonsuite_num=`cat /TIP/info_scan/result/yonsuite_vuln.txt | wc -l`
    echo "${yonsuite_num}"
    ;;


    # 金蝶OA漏洞扫描程序运行状态
    kingdee_vuln_scan_status)
    kingdee_scan_ps=`ps -aux | grep "vuln_lib.py kingdeeoa_vuln_scan" | wc -l`
	if (( $kingdee_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 关闭金蝶OA漏洞扫描程序
    stop_kingdee_scan)
    kingdee_pid=`ps -aux | grep "kingdeeoa_vuln_scan" |awk -F " " '{print $2}'`
    for ii in ${kingdee_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # 开启金蝶OA漏洞扫描程序
    start_kingdee_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py kingdeeoa_vuln_scan > /TIP/info_scan/result/kingdee_vuln.txt
    ;;


    #金蝶OA漏洞数量
    kingdee_vuln_num)
    kingdee_num=`cat /TIP/info_scan/result/kingdee_vuln.txt | wc -l`
    echo "${kingdee_num}"
    ;;


     # 万户OA漏洞扫描程序运行状态
    wanhu_vuln_scan_status)
    wanhu_scan_ps=`ps -aux | grep "vuln_lib.py wanhuoa_vuln_scan" | wc -l`
	if (( $wanhu_scan_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

     # 关闭万户OA漏洞扫描程序
    stop_wanhu_scan)
    wanhu_pid=`ps -aux | grep "wanhuoa_vuln_scan" |awk -F " " '{print $2}'`
    for ii in ${wanhu_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # 开启万户OA漏洞扫描程序
    start_wanhu_scan_shell)
    python3 /TIP/info_scan/vuln_lib.py wanhuoa_vuln_scan > /TIP/info_scan/result/wanhu_vuln.txt
    ;;

    #万户OA漏洞数量
    wanhu_vuln_num)
    wanhu_num=`cat /TIP/info_scan/result/wanhu_vuln.txt | wc -l`
    echo "${wanhu_num}"
    ;;


    # 开启jndi服务
    start_jndi_python)
    cd /TIP/info_scan/jndi_server/malice_web
    nohup python3 -m http.server 9991 --bind 127.0.0.1 > /dev/null 2>&1 &
    ;;

    start_jndi)
    cd /TIP/info_scan/jndi_server
    nohup java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://${ip_address}:9998/#TouchFile" 9999 > /TIP/info_scan/result/jndi_result.txt 2>&1 &
    echo "${jndi_result}"
    ;;

   


    # 关闭jndi服务
    stop_jndi_python)
    jndi_python_pid=`ps -aux | grep "9991" |awk -F " " '{print $2}'`

    jndi_pid=`ps -aux | grep "9999" |awk -F " " '{print $2}'`

    for i in ${jndi_python_pid}
	do
		kill -9 ${i} 2>/dev/null
	done

    for j in ${jndi_pid}
	do
		kill -9 ${j} 2>/dev/null
	done

    ;;


    # jndi服务状态
    jndi_server_status)
    jndi_ps=`ps -aux | grep "9999" | wc -l`
	if (( $jndi_ps > 1 ))
	then
		echo "running  (9999)"
	else
		echo "stop"
	fi
    ;;

    jndi_python_server_status)
    jndi_python_ps=`ps -aux | grep "9991" | wc -l`
	if (( $jndi_python_ps > 1 ))
	then
		echo "running  (9998)"
	else
		echo "stop"
	fi
    ;;


     # fastjson漏洞扫描程序运行状态
    fastjson_scan_status)
    fastjson_ps=`ps -aux | grep "vuln_lib.py fastjson_vuln_scan" | wc -l`
	if (( $fastjson_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 开启fastjson漏洞扫描程序
    start_fastjson_shell)
    python3 /TIP/info_scan/vuln_lib.py fastjson_vuln_scan > /TIP/info_scan/result/fastjson_vuln.txt
    ;;

     # 关闭fastjson漏洞扫描程序
    stop_fastjson_scan)
    fastjson_pid=`ps -aux | grep "fastjson_vuln_scan" |awk -F " " '{print $2}'`
    for ii in ${fastjson_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    #fastjson漏洞数量
    fastjson_vuln_num)
    fastjson_num=`cat /TIP/info_scan/result/fastjson_vuln.txt | wc -l`
    echo "${fastjson_num}"
    ;;
    

    # WAF相关检测
    waf_scan_shell)
    /usr/bin/wafw00f $2
    ;;

    # 存在waf文件过滤
    waf_filter)
    cat /TIP/batch_scan_domain/url.txt | grep -v "$2" > /TIP/batch_scan_domain/url_tmp.txt
    mv /TIP/batch_scan_domain/url_tmp.txt /TIP/batch_scan_domain/url.txt
    ;;


    # 开启waf设备扫描检测
    start_scan_waf)
    python3 /TIP/info_scan/vuln_lib.py waf_tool_scan > /TIP/info_scan/result/waf_result.txt
    ;;

    # WAF设备扫描运行状态
    waf_scan_status)
    waf_ps=`ps -aux | grep "vuln_lib.py waf_tool_scan" | wc -l`
	if (( $waf_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 关闭WAF设备扫描检测
    kill_waf_scan)
    waf_pid=`ps -aux | grep "waf_tool_scan" |awk -F " " '{print $2}'`
    for ii in ${waf_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    #WAF识别数量
    waf_vuln_num)
    waf_num=`cat /TIP/info_scan/result/waf_result.txt | wc -l`
    echo "${waf_num}"
    ;;

    # 开启40xbypass扫描程序
    startbypass)
    /TIP/info_scan/40Xbypass/40xbypass -xD $2 > /TIP/info_scan/result/403bypass_result.txt
    ;;

    # 40xbypass扫描程序运行状态
    bypassstatus)
    bypass_ps=`ps -aux | grep "40xbypass" | wc -l`
	if (( $bypass_ps > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
    ;;

    # 关闭40xbypass扫描程序
    stopbypass)
    bypass_pid=`ps -aux | grep "40xbypass" |awk -F " " '{print $2}'`
    for ii in ${bypass_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;

    #40xbypass数量
    bypass_vuln_num)
    bypass_num=`cat /TIP/info_scan/result/403bypass_result.txt | wc -l`
    echo "${bypass_num}"
    ;;


    # 开启crawlergo爬虫,不转发流量
    start_crawlergo)
    /TIP/info_scan/crawlergo_scan/crawlergo_linux_amd64 -c /usr/bin/google-chrome -t 10 $2 
     ;;

    start_crawlergo_shell)
    python3 /TIP/info_scan/basic.py start_crawlergo_scan_lib >> /TIP/info_scan/result/crawlergo_result.txt
    ;;



    # 开启crawlergo爬虫,转发流量
    start_crawlergo_proxy)
    /TIP/info_scan/crawlergo_scan/crawlergo_linux_amd64 -c /usr/bin/google-chrome -t 10 --request-proxy ${proxy_ip} $2 
    
    ;;


    start_crawlergo_proxy_shell)
    python3 /TIP/info_scan/basic.py start_crawlergo_scan_proxy_lib >> /TIP/info_scan/result/crawlergo_result.txt
    
    ;;


    # crawlergo运行状态
    crawlergo_status)
    crawlergo_ps=`ps -aux | grep "crawlergo_linux_amd64" | wc -l`
	if (( $crawlergo_ps > 1 ))
	then
		echo "running (代理地址：http://127.0.0.1:7777)"
	else
		echo "stop"
	fi
    ;;

    # 关闭crawlergo爬虫
    stop_crawlergo)
    crawlergo_pid=`ps -aux | grep "crawlergo" |awk -F " " '{print $2}'`
    for ii in ${crawlergo_pid}
	do
		kill -9 ${ii} 2>/dev/null
	done
    ;;


    # crawlergo爬取结果数量
    crawlergo_num)
    bypass_num_part=`cat /TIP/info_scan/result/crawlergo_result.txt | wc -l`
    echo "${bypass_num_part}"
    ;;

    # 资产管理文本框行数显示
    assset_textarea_num)
    assset_textarea_num_value=`cat $2 | wc -l`
    echo "${assset_textarea_num_value}"
    ;;

    # 过滤状态码为200的url
    httpxfilterstatus)
    /TIP/info_scan/httpx_server/httpx -l /TIP/info_scan/result/domain.txt -mc 200 
    ;;

    # 汇总报告生成状态
    totalreport_num)
    num=`ls /TIP/info_scan/result/*xlsx | wc -l`
    echo "${num}"
    ;;

    # afrog报告数量
    afrognum)
    num=`ls /TIP/info_scan/afrog_scan/reports/ | wc -l`
    echo "${num}"
    ;;

    # api接口报告数量
    apinum)
    num=`ls /TIP/info_scan/urlfinder_server/report/ | wc -l`
    echo "${num}"
    ;;

    # xray报告数量
    xraynum)
    num=`ls /TIP/batch_scan_domain/report/ | wc -l`
    echo "${num}"
    ;;

    # nmap报告数量
    nmapnum)
    num=`cat /TIP/info_scan/result/nmap.txt | wc -l`
    echo "${num}"
    ;;

    # 扩大资产范围
    startsubfinder)
    /TIP/info_scan/subfinder-scan/subfinder -dL /TIP/info_scan/result/subfinder_target.txt > /TIP/info_scan/result/subfinder_result.txt
    ;;

    subfinder_httpx)
    /TIP/info_scan/httpx_server/httpx -l /TIP/info_scan/result/subfinder_result.txt -mc 200 > /TIP/batch_scan_domain/url_tmp.txt
    # 删除空行
    sed '/^$/d' /TIP/batch_scan_domain/url_tmp.txt > /TIP/batch_scan_domain/url.txt
    # 去重
    sort /TIP/batch_scan_domain/url.txt | uniq > /TIP/batch_scan_domain/url_tmp.txt
    mv /TIP/batch_scan_domain/url_tmp.txt /TIP/batch_scan_domain/url.txt
    ;;

     # subfinder运行状态
    subfinder_status)
	ps_subfinderscan=`ps -aux | grep /TIP/info_scan/subfinder-scan/subfinder | wc -l`
	if (( $ps_subfinderscan > 1 ))
	then
		echo "running"
	else
		echo "stop"
	fi
	;;

esac
