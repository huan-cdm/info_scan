 #! /bin/bash
 if [ "$1" == "-h" ]; then  
	echo -e "[+]------------------------------------------"
    echo "开启所有服务：bash server_check.sh start"  
    echo "关闭所有服务：bash server_check.sh stop" 
	echo "重启所有服务：bash server_check.sh restart" 
	echo "查看服务状态：bash server_check.sh status" 
	echo -e "[+]------------------------------------------"
    echo "开启infoscan：bash server_check.sh startinfoscan"  
    echo "关闭infoscan：bash server_check.sh stopinfoscan"  
	echo "重启infoscan：bash server_check.sh restartinfoscan"  
	echo -e "[+]------------------------------------------"
    echo "开启xray报告：bash server_check.sh startxrayreport"  
    echo "关闭xray报告：bash server_check.sh stopxrayreport" 
	echo "重启xray报告：bash server_check.sh restartxrayreport" 
	echo -e "[+]------------------------------------------"
	echo "开启dirscan：bash server_check.sh startdirscan"
	echo "关闭dirscan：bash server_check.sh stopdirscan"
	echo "重启dirscan：bash server_check.sh restartdirscan"
	echo -e "[+]------------------------------------------"
	
	echo "开启URLFinder报告：bash server_check.sh startURLFinder"
	echo "关闭URLFinder报告：bash server_check.sh stopURLFinder"
	echo "重启URLFinder报告：bash server_check.sh restartURLFinder"
	echo -e "[+]------------------------------------------"
	echo "开启afrog报告：bash server_check.sh startafrogreport"
	echo "关闭afrog报告：bash server_check.sh stopafrogreport"
	echo "重启afrog报告：bash server_check.sh restartafrogreport"
	echo -e "[+]------------------------------------------"
    exit 0  #退出脚本，如果不需要执行其他命令的话
fi  



case "${1}" in
   
    #启动infoscan
    startinfoscan)
    nohup python3 ./scan_main_web.py > /dev/null 2>&1 &
    sleep 0.5s
	infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi
	;;


    #关闭infoscan
    stopinfoscan)
    pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		kill -9 ${aes} 2>/dev/null
	done
	sleep 0.5s
	infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi
	;;

	# 重启infoscan
	restartinfoscan)
	pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		kill -9 ${aes} 2>/dev/null
	done
	sleep 0.5s
	echo "infoscan正在重启中......"
	sleep 0.5s
	nohup python3 ./scan_main_web.py > /dev/null 2>&1 &
	infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi
	;;


	#目录扫描启动脚本
	startdirscan)
    nohup python3 ./dirscanmain.py > /dev/null 2>&1 &
    sleep 0.5s
	dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	#目录扫描服务
	if (( $dirscanpid > 1 ))
	then
		echo -e "dirscan：" "\033[32m√\033[0m" 
	else
		echo -e "dirscan：" "\033[31mX\033[0m"
	fi
	;;

	#目录扫描关闭脚本
	stopdirscan)
    dirscanpid=`ps -aux | grep  dirscanmain.py | awk -F " " '{print $2}'`
	for dirid in ${dirscanpid}
	do
		kill -9 ${dirid} 2>/dev/null
	done
	sleep 0.5s
    dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	#目录扫描服务
	if (( $dirscanpid > 1 ))
	then
		echo -e "dirscan：" "\033[32m√\033[0m" 
	else
		echo -e "dirscan：" "\033[31mX\033[0m"
	fi
	;;

	# 重启目录扫描
	restartdirscan)
	dirscanpid=`ps -aux | grep  dirscanmain.py | awk -F " " '{print $2}'`
	for dirid in ${dirscanpid}
	do
		kill -9 ${dirid} 2>/dev/null
	done
	sleep 0.5s
	echo "dirscan正在重启中......"
	sleep 0.5s
	nohup python3 ./dirscanmain.py > /dev/null 2>&1 &
	dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	#目录扫描服务
	if (( $dirscanpid > 1 ))
	then
		echo -e "dirscan：" "\033[32m√\033[0m" 
	else
		echo -e "dirscan：" "\033[31mX\033[0m"
	fi

	;;


	#开启xray报告访问服务
    #本地开启127.0.0.1，利用nginx反向代理
    startxrayreport)
    cd /TIP/batch_scan_domain/report
    nohup python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
	sleep 0.5s
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi

    ;;

    #关闭xray报告访问服务
    stopxrayreport)
    pidd=`ps -aux | grep 8081 |awk -F " " '{print $2}'`
    
    for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
	done

	sleep 0.5s
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi
    ;;


	# 重启xray报告访问服务
	restartxrayreport)

	pidd=`ps -aux | grep 8081 |awk -F " " '{print $2}'`
    
    for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
	done

	sleep 0.5s
	echo "xrayreport正在重启中......"
	sleep 0.5s
	cd /TIP/batch_scan_domain/report
    nohup python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi

	;;



	# 开启afrog报告服务
	# 本地开启127.0.0.1，利用nginx反向代理
	startafrogreport)
    cd /TIP/info_scan/Tools/afrog_scan/reports
    nohup python3 -m http.server 8082 --bind 127.0.0.1 > /dev/null 2>&1 &
	
	sleep 0.5s
	afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
	# afrog服务状态
	if (( $afrogpid > 1 ))
	then
		echo -e "afrogreport：" "\033[32m√\033[0m" 
	else
		echo -e "afrogreport：" "\033[31mX\033[0m"
	fi

    ;;


	# 关闭afrog报告服务
	stopafrogreport)
    afpid=`ps -aux | grep 8082 |awk -F " " '{print $2}'`
    
    for ii in ${afpid}
	do

		kill -9 ${ii} 2>/dev/null
		
	done

	sleep 0.5s
	afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
	# afrog服务状态
	if (( $afrogpid > 1 ))
	then
		echo -e "afrogreport：" "\033[32m√\033[0m" 
	else
		echo -e "afrogreport：" "\033[31mX\033[0m"
	fi
    ;;


	# 重启afrog报告服务
	restartafrogreport)

	afpid=`ps -aux | grep 8082 |awk -F " " '{print $2}'`
    
    for ii in ${afpid}
	do

		kill -9 ${ii} 2>/dev/null
		
	done

	sleep 0.5s
	echo "afrogreport正在重启中......"
	sleep 0.5s

	cd /TIP/info_scan/Tools/afrog_scan/reports
    nohup python3 -m http.server 8082 --bind 127.0.0.1 > /dev/null 2>&1 &
	
	
	afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
	# afrog服务状态
	if (( $afrogpid > 1 ))
	then
		echo -e "afrogreport：" "\033[32m√\033[0m" 
	else
		echo -e "afrogreport：" "\033[31mX\033[0m"
	fi
	;;


	#kill rad和xray引擎
	killscan)
	xraypid=`ps -aux | grep xray |awk -F " " '{print $2}'`
	radpid=`ps -aux | grep rad_linux_amd64 |awk -F " " '{print $2}'`
	#kill xray
	for xrayline in ${xraypid}
	do
		kill -9 ${xrayline} 2>/dev/null
	done

	#kill rad
	for radline in ${radpid}
	do
		kill -9 ${radline} 2>/dev/null
	done
	
	;;



	#服务运行状态
	status)
	infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
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
		echo -e "dirscan：" "\033[32m√\033[0m" 
	else
		echo -e "dirscan：" "\033[31mX\033[0m"
	fi
	sleep 0.5s

	# afrog服务状态
	if (( $afrogpid > 1 ))
	then
		echo -e "afrogreport：" "\033[32m√\033[0m" 
	else
		echo -e "afrogreport：" "\033[31mX\033[0m"
	fi
	;;




	#开启链接扫描报告服务
    #本地开启127.0.0.1，利用nginx反向代理
    startURLFinder)
    cd /TIP/info_scan/Tools/urlfinder_server/report
    nohup python3 -m http.server 8089 --bind 127.0.0.1 > /dev/null 2>&1 &
	
	sleep 0.5s
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	#链接扫描报告服务
	if (( $urlfinderpid > 1 ))
	then
		echo -e "urlfinderreport：" "\033[32m√\033[0m" 
	else
		echo -e "urlfinderreport：" "\033[31mX\033[0m"
	fi
    ;;

	#关闭链接扫描报告访问服务
    stopURLFinder)
    linkpidd=`ps -aux | grep 8089 |awk -F " " '{print $2}'`
    
    for ii in ${linkpidd}
	do
		
		kill -9 ${ii} 2>/dev/null
		
	done

	sleep 0.5s
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	#链接扫描报告服务
	if (( $urlfinderpid > 1 ))
	then
		echo -e "urlfinderreport：" "\033[32m√\033[0m" 
	else
		echo -e "urlfinderreport：" "\033[31mX\033[0m"
	fi
    ;;


	#重启链接扫描报告访问服务
	restartURLFinder)
	linkpidd=`ps -aux | grep 8089 |awk -F " " '{print $2}'`
    
    for ii in ${linkpidd}
	do
		
		kill -9 ${ii} 2>/dev/null
		
	done

	sleep 0.5s
	echo "URLFinderreport正在重启中......"
	sleep 0.5s
	cd /TIP/info_scan/Tools/urlfinder_server/report
    nohup python3 -m http.server 8089 --bind 127.0.0.1 > /dev/null 2>&1 &
	
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	#链接扫描报告服务
	if (( $urlfinderpid > 1 ))
	then
		echo -e "URLFinderreport：" "\033[32m√\033[0m" 
	else
		echo -e "URLFinderreport：" "\033[31mX\033[0m"
	fi
	;;


	# 开启所有服务
	start)
	# 开启info_scan
	nohup python3 ./scan_main_web.py > /dev/null 2>&1 &
    sleep 0.5s
	infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi

	# 开启目录扫描
	nohup python3 ./dirscanmain.py > /dev/null 2>&1 &
    sleep 0.5s
	dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	#目录扫描服务
	if (( $dirscanpid > 1 ))
	then
		echo -e "dirscan：" "\033[32m√\033[0m" 
	else
		echo -e "dirscan：" "\033[31mX\033[0m"
	fi


	# 开启xray报告
	cd /TIP/batch_scan_domain/report
    nohup python3 -m http.server 8081 --bind 127.0.0.1 > /dev/null 2>&1 &
	sleep 0.5s
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi

	# 开启afrog
	cd /TIP/info_scan/Tools/afrog_scan/reports
    nohup python3 -m http.server 8082 --bind 127.0.0.1 > /dev/null 2>&1 &
	
	sleep 0.5s
	afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
	# afrog服务状态
	if (( $afrogpid > 1 ))
	then
		echo -e "afrogreport：" "\033[32m√\033[0m" 
	else
		echo -e "afrogreport：" "\033[31mX\033[0m"
	fi

	# 开启urlfinder
	cd /TIP/info_scan/Tools/urlfinder_server/report
    nohup python3 -m http.server 8089 --bind 127.0.0.1 > /dev/null 2>&1 &
	
	sleep 0.5s
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	#链接扫描报告服务
	if (( $urlfinderpid > 1 ))
	then
		echo -e "urlfinderreport：" "\033[32m√\033[0m" 
	else
		echo -e "urlfinderreport：" "\033[31mX\033[0m"
	fi
	;;


	# 关闭所有服务
	stop)
	# 关闭info_scan
	pides=`ps -aux | grep  scan_main_web.py | awk -F " " '{print $2}'`
	for aes in ${pides}
	do
		kill -9 ${aes} 2>/dev/null
	done
	sleep 0.5s
	infopid=`ps -aux | grep  scan_main_web.py |awk -F " " '{print $2}' | wc -l`
	#infoscan运行状态
	if (( $infopid > 1 ))
	then
		echo -e "infoscan：" "\033[32m√\033[0m" 
	else
		echo -e "infoscan：" "\033[31mX\033[0m"
	fi

	# 关闭dirscan
	dirscanpid=`ps -aux | grep  dirscanmain.py | awk -F " " '{print $2}'`
	for dirid in ${dirscanpid}
	do
		kill -9 ${dirid} 2>/dev/null
	done
	sleep 0.5s
    dirscanpid=`ps -aux | grep dirscanmain.py |awk -F " " '{print $2}' | wc -l`
	#目录扫描服务
	if (( $dirscanpid > 1 ))
	then
		echo -e "dirscan：" "\033[32m√\033[0m" 
	else
		echo -e "dirscan：" "\033[31mX\033[0m"
	fi

	# 关闭xray
	pidd=`ps -aux | grep 8081 |awk -F " " '{print $2}'`
    
    for ii in ${pidd}
	do
		kill -9 ${ii} 2>/dev/null
	done

	sleep 0.5s
	xraypid=`ps -aux | grep 8081 |awk -F " " '{print $2}' | wc -l`
	#xray报告服务
	if (( $xraypid > 1 ))
	then
		echo -e "xrayreport：" "\033[32m√\033[0m" 
	else
		echo -e "xrayreport：" "\033[31mX\033[0m"
	fi

	# 关闭afrog
	afpid=`ps -aux | grep 8082 |awk -F " " '{print $2}'`
    
    for ii in ${afpid}
	do

		kill -9 ${ii} 2>/dev/null
		
	done

	sleep 0.5s
	afrogpid=`ps -aux | grep 8082 |awk -F " " '{print $2}' | wc -l`
	# afrog服务状态
	if (( $afrogpid > 1 ))
	then
		echo -e "afrogreport：" "\033[32m√\033[0m" 
	else
		echo -e "afrogreport：" "\033[31mX\033[0m"
	fi


	# 关闭urlfinder
	linkpidd=`ps -aux | grep 8089 |awk -F " " '{print $2}'`
    
    for ii in ${linkpidd}
	do
		
		kill -9 ${ii} 2>/dev/null
		
	done

	sleep 0.5s
	urlfinderpid=`ps -aux | grep 8089 |awk -F " " '{print $2}' | wc -l`
	#链接扫描报告服务
	if (( $urlfinderpid > 1 ))
	then
		echo -e "urlfinderreport：" "\033[32m√\033[0m" 
	else
		echo -e "urlfinderreport：" "\033[31mX\033[0m"
	fi
	;;

	# 重启所有服务
	restart)
	bash server_check.sh stop
	bash server_check.sh start
	;;


esac