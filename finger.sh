#! /bin/bash
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
    echo "" >> ./result/nmap.txt
    echo "" >> ./result/nmap.txt
    # 输出当前时间  
    current_time=$(date +"%Y-%m-%d %H:%M:%S")  
    echo "当前时间：$current_time" >> ./result/nmap.txt
    echo "IP地址："$2 >> ./result/nmap.txt
    /usr/bin/nmap -Pn -sS -sV -T4  $2  -p 1-65535  --min-rate=10000 | grep "tcp"  >> ./result/nmap.txt
    ;;

    #nmap队列扫描运行状态
    nmapstatus)
	ps_nmap=`ps -aux | grep /usr/bin/nmap | wc -l`
	if (( $ps_nmap > 1 ))
	then
		echo "nmap：运行中..."
	else
		echo "nmap：停止"
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
    dict="/root/nuclei-templates/http"
	./nuclei_server/nuclei -l /TIP/batch_scan_domain/url.txt -t ${dict} -c 10 -bulk-size 10  -rate-limit 30 -timeout 3 > ./result/nucleiresult.txt
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
		echo "nuclei：运行中..."
	else
		echo "nuclei：停止"
	fi
    ;;

    #xray状态
    xraystatus)
    num_xray=`ps -aux | grep xray-testphp | wc -l`
    num_xray_status=`ps -aux | grep xray-testphp | grep html`
    if (( $num_xray > 1 ))
    then
        echo "xray：""${num_xray_status}"
    else
        echo "xray：停止"
    
    fi
    ;;

    #rad运行状态
    radstatus)
    num_rad=`ps -aux | grep radscan.py | wc -l`
    num_rad_status=`ps -aux | grep rad_engine/rad_linux_amd64 | grep http-proxy`
    if (( $num_rad > 1 ))
    then
        echo "rad：""${num_rad_status}"
    else
        echo "rad：停止"
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
		echo "dirscan：运行中..."
	else
		echo "dirscan：停止"
	fi
	;;

    #文件清洗服务运行状态
	fileclean)
	ps_fileclean=`ps -aux | grep filterdirsearchdata.sh | wc -l`
	if (( $ps_fileclean > 2 ))
	then
		echo "正在运行中........."
	else
		echo "已停止"
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
    mv /TIP/batch_scan_domain/url_tmp.txt /TIP/batch_scan_domain/url.txt
    ;;

    #urlfinder引擎启动脚本
    urlfinder_start)
    #使用date命令生成当前的时间戳  
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    rm -rf /TIP/info_scan/urlfinder_server/result_tmp.txt
    /TIP/info_scan/urlfinder_server/URLFinder -f /TIP/batch_scan_domain/url.txt -m 2 -s all -s 200 -o /TIP/info_scan/urlfinder_server/report/urlfinder-${TIMESTAMP}.html > /TIP/info_scan/urlfinder_server/result_tmp.txt
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
		echo "weblogic_scan：运行中..."
	else
		echo "weblogic_scan：停止"
	fi
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
		echo "struts2_scan：运行中..."
	else
		echo "struts2_scan：停止"
	fi
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
		echo "bbscan_scan：运行中..."
	else
		echo "bbscan_scan：停止"
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
		echo "vulmap_scan：运行中..."
	else
		echo "vulmap_scan：停止"
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


    # ceye_http记录
    ceye_http)
    ceye_http_result=`curl -s "http://api.ceye.io/v1/records?token=${2}&type=http"`
    if [ -n "${ceye_http_result}" ];then
        echo "${ceye_http_result}"
    else
        echo "Error: Failed to retrieve CEYE HTTP records." 
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
		echo "afrog_scan：运行中..."
	else
		echo "afrog_scan：停止"
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
    
    

    # 启动fscan扫描程序
    startfscanprocess)
    cd /TIP/info_scan/fscan_tool/
    if [ -f ./fscan ]; then  
        # grep -vE  过滤多个参数
        # ./fscan -h $2 -nopoc | grep -vE 'start|已完成|扫描结束|alive' > /TIP/info_scan/result/fscan_vuln.txt
        ./fscan -hf /TIP/info_scan/fscan_tool/ip.txt -nopoc | grep -vE 'start|已完成|扫描结束|alive' > /TIP/info_scan/result/fscan_vuln.txt
    else  
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
		echo "fscan_scan：运行中..."
	else
		echo "fscan_scan：停止"
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
		echo "shiro_scan：运行中..."
	else
		echo "shiro_scan：停止"
	fi
	;;

     # httpx运行状态
    httpx_status)
	ps_httpxscan=`ps -aux | grep /TIP/info_scan/httpx_server/httpx | wc -l`
	if (( $ps_httpxscan > 1 ))
	then
		echo "httpx：运行中..."
	else
		echo "httpx：停止"
	fi
	;;

    # 自定义指纹列表过滤
    finger_filter_shell)
    result=`cat /TIP/info_scan/result/ehole_finger.txt | grep $2`
    echo "$result"
    ;;


    # 目标URL数量
    url_file_num)
    url_num=`cat /TIP/batch_scan_domain/url.txt | wc -l`
    echo "${url_num}"
    ;;

    # Ehole指纹识别运行状态
    ehole_status)
	ps_eholescan=`ps -aux | grep EHole | wc -l`
	if (( $ps_eholescan > 1 ))
	then
		echo "ehole：运行中..."
	else
		echo "ehole：停止"
	fi
	;;


    #nuclei模板文件查看
    templatenuclei)
    templatenuclei_result=`find $2 -type f`
    echo "${templatenuclei_result}"
    ;;
    
esac


