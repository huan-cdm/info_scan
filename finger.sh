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
		echo "nmap状态：运行中"
	else
		echo "nmap状态：停止"
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
		echo "nuclei状态：运行中"
	else
		echo "nuclei状态：停止"
	fi
    ;;

    #xray状态
    xraystatus)
    num_xray=`ps -aux | grep xray-testphp | wc -l`
    num_xray_status=`ps -aux | grep xray-testphp | grep html`
    if (( $num_xray > 1 ))
    then
        echo "xray状态：""${num_xray_status}"
    else
        echo "xray状态：停止"
    
    fi
    ;;

    #rad运行状态
    radstatus)
    num_rad=`ps -aux | grep radscan.py | wc -l`
    num_rad_status=`ps -aux | grep rad_engine/rad_linux_amd64 | grep http-proxy`
    if (( $num_rad > 1 ))
    then
        echo "rad状态：""${num_rad_status}"
    else
        echo "rad状态：停止"
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
		echo "dirscan状态：运行中"
	else
		echo "dirscan状态：停止"
	fi
	;;

    #文件清洗服务运行状态
	fileclean)
	ps_fileclean=`ps -aux | grep filterdirsearchdata.sh | wc -l`
	if (( $ps_fileclean > 2 ))
	then
		echo "正在运行中......"
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
esac
