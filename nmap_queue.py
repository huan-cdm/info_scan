import threading  
import subprocess  
import queue  

  
# 创建一个队列来存储IP地址  
ip_queue = queue.Queue()  
  
# 定义一个函数来执行ping操作  
def ping_ip(ip):  
    result = subprocess.run(["sh", "./finger.sh","nmap_port",ip], stdout=subprocess.PIPE)  
    return result.stdout.decode()  
  
# 定义一个函数来处理队列中的IP地址并执行ping操作  
def process_queue():  
    while True:  
        try:  
            ip = ip_queue.get(block=False)  
            ping_result = ping_ip(ip)  
            print(f"Ping result for IP {ip}: {ping_result}")  
        except queue.Empty:  
            pass  
      
# 启动后台线程来处理队列中的IP地址  
threading.Thread(target=process_queue, daemon=True).start()  
  
 
def add_ip(ip):  
    
    if ip:  
        ip_queue.put(ip)
        print("IP added to queue") 
    else:
        print("Invalid IP address")