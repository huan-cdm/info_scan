'''
Author:[huan666]
Date:[2024/01/12]
'''
import requests  
from fake_useragent import UserAgent
import time   
  
def urlinfo(domain_list, output_file='/TIP/batch_scan_domain/result.txt'):  
    UA = UserAgent()  
    print("开始获取域名信息...")  
  
    #打开文件用于写入  
    with open(output_file, 'w', encoding='utf-8') as file:
        for domain in domain_list:
            time.sleep(3)  
            url = "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/url_list?limit=500&page=1"  
            headers={
            'Cookie':'Hm_lvt_ecdd6f3afaa488ece3938bcdbb89e8da=1615729527; Hm_lvt_d39191a0b09bb1eb023933edaa468cd5=1617883004,1617934903,1618052897,1618228943; Hm_lpvt_d39191a0b09bb1eb023933edaa468cd5=1618567746',
            'Host':'otx.alienvault.com',
            'User-Agent':UA.random
    }
  
            try:  
                res = requests.get(url, headers=headers, allow_redirects=False)  
                res.raise_for_status()  #如果请求失败，将引发HTTPError异常  
                res_json = res.json()
                
                data = res_json.get('url_list', [])
  
                # 将每个URL写入文件  
                for item in data:  
                    url_text = item.get('url','')  
                    file.write(url_text + '\n')  
  
            except requests.exceptions.RequestException as e:  
                print(f"请求失败: {e}")  
                continue  # 跳过当前域名，继续下一个  
  
    print("域名信息获取完毕，已写入到文件:", output_file)  
