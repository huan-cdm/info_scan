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
        for ii in port:
            port_list.append(ii)
        if len(port_list) == 0:
            port_list.append("NULL")
            
        return port_list
    except:
        pass