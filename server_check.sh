 #! /bin/bash
 if [ "$1" == "-h" ]; then  
    echo "开启infoscan：bash server_check.sh info_scan_start"  
    echo "关闭infoscan：bash server_check.sh info_scan_stop"  
    echo "开启xray报告：bash server_check.sh startreportserver"  
    echo "关闭xray报告：bash server_check.sh stopreportserver" 
	echo "关闭rad&xray引擎：bash server_check.sh killscan"
	echo "查看服务状态：bash server_check.sh status"
    exit 0  #退出脚本，如果不需要执行其他命令的话
fi  



case "${1}" in
   
    #info_scan web启动脚本
    info_scan_start)
    nohup python3 ./scan_main_web.py > ./scan_main_web.out &
    sleep 0.1s
	echo "info_scan_web已启动"
	;;

    #info_scan web关闭脚本
    info_scan_stop)
	rm -rf ./scan_main_web.out
    pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		echo "正在结束进程${aes}"
		kill -9 ${aes}
	done
	sleep 0.1s
    echo "info_scan_web已关闭"
	;;

	#开启xray报告访问服务
    #本地开启127.0.0.1，利用nginx反向代理，映射到公网访问
    startreportserver)
    cd /TIP/batch_scan_domain/report
    nohup python3 -m http.server 8081 --bind 127.0.0.1 & > /TIP/batch_scan_domain/httpserver.out
    
    ;;

    #关闭xray报告访问服务
    stopreportserver)
	rm -rf /TIP/batch_scan_domain/httpserver.out
    pidd=`ps -aux | grep 8081 |awk -F " " '{print $2}'`
    
    for ii in ${pidd}
	do
		echo ".正在结束进程${ii}"
		kill -9 ${ii}
		sleep 0.1s
	done
    ;;

	#kill rad和xray引擎
	killscan)
	xraypid=`ps -aux | grep xray |awk -F " " '{print $2}'`
	radpid=`ps -aux | grep rad_linux_amd64 |awk -F " " '{print $2}'`

	for xrayline in ${xraypid}
	do
		echo ".正在结束进程${xrayline}"
		kill -9 ${xrayline}
		sleep 0.1s
	done

	for radline in ${radpid}
	do
		echo ".正在结束进程${radline}"
		kill -9 ${radline}
		sleep 0.1s
	done
	;;



	#服务运行状态
	status)
	infopid=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}' | wc -l`
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi
	;;
    
esac