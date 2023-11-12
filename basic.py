'''
Description:[IP开放端口信息]
Author:[huan666]
Date:[2023/11/12]
'''
import shodan
from config import shodankey

def shodan_api(ip):
    apis = shodan.Shodan(shodankey)
    try:
        result = apis.host(ip)
    except:
        pass
    try:
        port = result['ports']
        port_list = []
        if len(port) == 0:
            port_list.append("NULL")
        else:
            port_list = port
        return port_list
    except:
        pass