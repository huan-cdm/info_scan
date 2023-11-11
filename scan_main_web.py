from flask import Flask, render_template,request
import scan_lib
import httpx_status
import finger_recognize
app = Flask(__name__,template_folder='./templates') 
  
@app.route('/', methods=['GET'])  
def get_data():
    ip = request.args.get('ip')
    data = scan_lib.shodan_fofa_api(ip)
    
    #状态码为200的url
    data1=httpx_status.status_scan(ip)

    #状态码为200的url指纹信息
    data3 = finger_recognize.finger_scan(ip)
    
    return render_template('index.html', data=data, data1=data1,data2=ip,data3=data3)
  
  

if __name__ == '__main__':  
    app.run(host="0.0.0.0",port=80)
