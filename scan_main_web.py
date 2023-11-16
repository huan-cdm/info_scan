'''
Description:[网页查询接口启动文件]
Author:[huan666]
Date:[2023/11/15]
'''
from flask import Flask, render_template,request
import httpx_status
import finger_recognize
import icp
import basic
import ip138
import subprocess
import os

app = Flask(__name__,template_folder='./templates') 
  
@app.route('/', methods=['GET'])  
def get_data():
    ip = request.args.get('ip')
    
    #状态码为200的url
    data1=httpx_status.status_scan(ip)

    #状态码为200的url指纹信息
    data3 = finger_recognize.finger_scan(ip)

    #icp备案信息
    data4 = icp.icp_scan(ip)

    #ip归属地
    output = subprocess.check_output(["sh", "./finger.sh","location",ip], stderr=subprocess.STDOUT)
    output_list = output.decode().splitlines()
    #定义列表
    location_list = []
    for ii in output_list:
        if "地址" in ii:
            location_list.append(ii)
    localtion_list_1 = location_list[0].replace("地址","")
    localtion_list_result = localtion_list_1.replace(":","")
    
    
    #端口信息
    port = basic.shodan_api(ip)

    #ip138域名
    ip138_domain = ip138.ip138_scan(ip)

    #操作系统识别
    os_type = os.popen('bash ./finger.sh osscan'+' '+ip).read()
    return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4
    ,data5=localtion_list_result,data6=port,data7=ip138_domain,data8=os_type)
  
  

if __name__ == '__main__':  
    app.run(host="0.0.0.0",port=80)