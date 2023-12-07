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
import re
import cdn_lib
import title_lib
import subdomain_lib
import ipstatus_lib
import gaodeapi
from flask import jsonify



app = Flask(__name__,template_folder='./templates') 
''' 
@app.route('/', methods=['GET'])  
def get_data():
'''
@app.route("/ipscaninterface/",methods=['post'])
def ipscaninterface():
    ip = request.form['ip']
    #ip = request.args.get('ip')

    
    #状态码为200的url
    data1=httpx_status.status_scan(ip)
    
    #状态码为200的url指纹信息
    data3 = finger_recognize.finger_scan(ip)

    #icp备案信息
    data4 = icp.icp_scan(ip)

    #公司位置信息
    try:
        companylocation = gaodeapi.gaodescan(data4)
    except:
        pass

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

    #去掉https://或者http://
    urls_list_1 = [re.sub(r'http://|https://', '', url) for url in data1]
    urls_list = []
    for aa in urls_list_1:
        if "cn" in aa or "com" in aa:
            urls_list.append(aa)
    #定义存放cdn结果列表
    cdn_list_1 = []
    #定义存放子域名的列表
    subdomain_list_1 = []
    for bb in urls_list:
       
        #cdn存放结果
        cdn_result = cdn_lib.cdnscan(bb)
        cdn_list_1.append(cdn_result)

        #子域名存放列表
        subdomain_result = subdomain_lib.subdomain_scan(bb)
        subdomain_list_1.append(subdomain_result)
    try:
        flattened_list = [item for sublist in subdomain_list_1 for item in sublist]
    except:
        pass
    
    #CDN列表去重
    cdn_list = list(set(cdn_list_1))
    if len(cdn_list) == 0:
        cdn_list.append("None")
    

    #子域名列表去重
    subdomain_list = list(set(flattened_list))
    if len(subdomain_list) ==0:
        subdomain_list.append("None")
    

    #网站标题
    site_title_list = []
    for sa in data1:
        site_title = title_lib.title_scan(sa)
        site_title_list.append(site_title)
    site_title_list_result = list(set(site_title_list))
    if len(site_title_list_result) == 0:
        site_title_list_result.append("None")


    
    #IP属性判断
    try:
        ipstatus = ipstatus_lib.ipstatus_scan(ip)
    except:
        pass

    return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4
    ,data5=localtion_list_result,data6=port,data7=ip138_domain,data8=os_type,data9=cdn_list
    ,data10=site_title_list_result,data11=subdomain_list,data12=ipstatus,data13=companylocation)
  

#跳转首页
@app.route("/index/")
def index():
    
    return render_template('index.html')



if __name__ == '__main__':  
    app.run(host="0.0.0.0",port=80)