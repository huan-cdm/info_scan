#! /bin/bash
 if [ "$1" == "-h" ]; then  
    echo "启动rad：bash start.sh startrad"  
    echo "启动xray：bash start.sh startxray"  
    exit 0  #退出脚本，如果不需要执行其他命令的话  
fi  

case "${1}" in
    #调用rad
    startrad)
    #./rad_engine/rad_linux_amd64 --target ${2}
    ./rad_engine/rad_linux_amd64 --target ${2} -http-proxy 127.0.0.1:7777
	;;
    
    #调用xray
    startxray)
    # 使用date命令生成当前的时间戳  
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")  
    #拼接文件名  
    OUTPUT_FILE="./report/xray-testphp-${TIMESTAMP}.html" 
    #./xray_engine/xray_linux_amd64 webscan --listen 127.0.0.1:7777 --html-output "$OUTPUT_FILE"
    nohup ./xray_engine/xray_linux_amd64 webscan --listen 127.0.0.1:7777 --html-output "$OUTPUT_FILE" > /dev/null 2>&1 &
    # 打印出生成的文件名  
    echo "HTML output saved to $OUTPUT_FILE"
    ;;
esac
