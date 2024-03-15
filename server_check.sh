 #! /bin/bash
 if [ "$1" == "-h" ]; then  
    echo "开启infoscan：bash server_check.sh info_scan_start"  
    echo "关闭infoscan：bash server_check.sh info_scan_stop"  
    echo "开启xray报告：bash server_check.sh startreportserver"  
    echo "关闭xray报告：bash server_check.sh stopreportserver" 
	echo "关闭rad&xray引擎：bash server_check.sh killscan"
	echo "开启目录扫描引擎：bash server_check.sh startdirscan"
	echo "关闭目录扫描引擎：bash server_check.sh stopdirscan"
	echo "开启链接扫描报告：bash server_check.sh startlinkscanserver"
	echo "关闭链接扫描报告：bash server_check.sh stoplinkscanserver"
	echo "查看服务状态：bash server_check.sh status"
    exit 0  #退出脚本，如果不需要执行其他命令的话
fi  



case "${1}" in
   
    #info_scan web启动脚本
    info_scan_start)
    nohup python3 ./scan_main_web.py > /dev/null 2>&1 &
    sleep 0.1s
	echo "info_scan_web已启动"
	;;

	#目录扫描启动脚本
	startdirscan)
    nohup python3 ./dirscanmain.py > /dev/null 2>&1 &
    sleep 0.1s
	echo "目录扫描已启动"
	;;

    #info_scan web关闭脚本
    info_scan_stop)
    pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		echo "正在结束进程${aes}"
		kill -9 ${aes}
	done
	sleep 0.1s
    echo "info_scan_web已关闭"
	;;

	#目录扫描关闭脚本
	stopdirscan)
    dirscanpid=`ps -aux | grep  dirscanmain.py | awk -F " " '{print $2}'`
	for dirid in ${dirscanpid}
	do
		echo "正在结束进程${dirid}"
		kill -9 ${dirid}
	done
	sleep 0.1s
    echo "目录扫描已关闭"
	;;

	#开启xray报告访问服务
    #本地开启127.0.0.1，利用nginx反向代理
    startreportserver)
    cd /TIP/batch_scan_domain/report
    nohup python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
    ;;

    #关闭xray报告访问服务
    stopreportserver)
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
	#kill xray
	for xrayline in ${xraypid}
	do
		kill -9 ${xrayline}
	done

	#kill rad
	for radline in ${radpid}
	do
		kill -9 ${radline}
	done
	
	;;



	#服务运行状态
	status)
	infopid=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}' | wc -l`
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	sleep 0.5s
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi
	sleep 0.5s
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi
	sleep 0.5s
	#链接扫描报告服务
	if (( $urlfinderpid > 1 ))
	then
		echo -e "urlfinderreport：" "\033[32m√\033[0m" 
	else
		echo -e "urlfinderreport：" "\033[31mX\033[0m"
	fi
	sleep 0.5s
    #目录扫描服务
	if (( $dirscanpid > 1 ))
	then
		echo -e "目录扫描：" "\033[32m√\033[0m" 
	else
		echo -e "目录扫描：" "\033[31mX\033[0m"
	fi
	;;




	#开启链接扫描报告服务
    #本地开启127.0.0.1，利用nginx反向代理
    startlinkscanserver)
    cd /TIP/info_scan/urlfinder_server/report
    nohup python3 -m http.server 8089 --bind 127.0.0.1 > /dev/null 2>&1 &
    ;;

	#关闭链接扫描报告访问服务
    stoplinkscanserver)
    linkpidd=`ps -aux | grep 8089 |awk -F " " '{print $2}'`
    
    for ii in ${linkpidd}
	do
		echo ".正在结束进程${ii}"
		kill -9 ${ii}
		sleep 0.1s
	done
    ;;

esac
