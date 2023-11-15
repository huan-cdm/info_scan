#! /bin/bash
locat=`curl cip.cc/${2} | grep "地址"`
echo "${locat}"