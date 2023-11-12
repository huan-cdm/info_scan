#! /bin/bash
case "${1}" in
    #指纹识别脚本
    finger)
    python3 ./tiderfinger/TideFinger.py -u ${2} | grep "Banner\|CMS_finger"
	;;
    
    #IP属地
    location)
    locat=`curl cip.cc/${2} | grep "地址"`
    echo "${locat}"
    ;;
esac