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
		echo "队列状态：运行中"
	else
		echo "队列状态：停止"
	fi
	;;

    #开启nuclei扫描
    startnuclei)
    #   常用参数（https://blog.csdn.net/qq_35607078/article/details/131648824）
    #   -bulk-size 限制并行的主机数 默认25 
    #   -c 限制并行的模板数 默认25
    #   -rate-limit 每秒发送的最大请求数 默认150 
    #   -l 批量扫描
    #   -t 要运行的模板或模板目录列表
    #   -timeout 超时前等待的时间(以秒为单位) 默认 10秒
    #   dict="/root/nuclei-templates/http"
    dict="/root/nuclei-templates/http"
	./nuclei_server/nuclei -l ./result/domainstatuscode.txt -t ${dict} -c 10 -bulk-size 10  -rate-limit 30 -timeout 3 > ./result/nucleiresult.txt
	;;
esac
