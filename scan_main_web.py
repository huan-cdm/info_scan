from flask import Flask, render_template,request
import scan_lib
import httpx_status
import finger_recognize
import icp
import os
import basic
app = Flask(__name__,template_folder='./templates') 
  
@app.route('/', methods=['GET'])  
def get_data():
    ip = request.args.get('ip')
    #data = scan_lib.shodan_fofa_api(ip)
    
    #状态码为200的url
    data1=httpx_status.status_scan(ip)

    #状态码为200的url指纹信息
    data3 = finger_recognize.finger_scan(ip)

    #icp备案信息
    data4 = icp.icp_scan(ip)

    #ip归属地
    location_1 = os.popen('bash ./finger.sh location'+' '+ip).read()
    location_11 = location_1.replace("地址","")
    location = location_11.replace(":","")

    #端口信息
    port = basic.shodan_api(ip)
    return render_template('index.html',data1=data1,data2=ip,data3=data3,data4=data4,data5=location,data6=port)
  
  

if __name__ == '__main__':  
    app.run(host="0.0.0.0",port=80)
