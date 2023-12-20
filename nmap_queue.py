import threading  
import subprocess  
import queue
import time

  
# 创建一个队列来存储IP地址  
ip_queue = queue.Queue()  
  
# 定义一个函数执行端口扫描 
def nmapscan(ip):  
    result = subprocess.run(["sh", "./finger.sh","nmap_port",ip], stdout=subprocess.PIPE)  
    return result.stdout.decode()  
  
# 定义一个函数来处理队列中的IP地址并执行端口扫描  
def process_queue():  
    while True:  
        try:  
            ip = ip_queue.get(block=False)  
            port_result = nmapscan(ip)  
            print(f"Port scanning has been completed {ip}: {port_result}")  
        except queue.Empty:
            time.sleep(3)
        except Exception as e:
            print(f"An error occurred: {e}")
      
# 启动后台线程来处理队列中的IP地址  
threading.Thread(target=process_queue, daemon=True).start()  
  
 
def add_ip(ip):  
    
    if ip:  
        ip_queue.put(ip)
        print("IP added to queue") 
    else:
        print("Invalid IP address")
