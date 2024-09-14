'''
Description:[整合扫描器报告存入到vuln_report.xlsx中]
Author:[huan666]
Date:[2024/05/31]
pip install pandas openpyxl
'''
import pandas as pd
from config import ceye_key
import os
import re

def report_xlsx():

    # 每次执行清空历史报告，生成新数据
    os.popen('rm -rf /TIP/info_scan/result/vuln_report.xlsx')

    # weblogic
    weblogic_report_list = []
    weblogic_file = open("/TIP/info_scan/result/weblogic_poc.txt",encoding='utf-8')
    for weblogic_line in weblogic_file.readlines():
        weblogic_report_list.append(weblogic_line.strip())
    
    # nmap
    nmap_report_list = []
    nmap_file = open("/TIP/info_scan/result/nmap.txt",encoding='utf-8')
    for nmap_line in nmap_file.readlines():
        nmap_report_list.append(nmap_line.strip())
    
    # struts2
    struts2_report_list = []
    struts2_file = open("/TIP/info_scan/result/struts2_poc.txt",encoding='utf-8')
    for struts2_line in struts2_file.readlines():
        struts2_report_list.append(struts2_line.strip())

    # nuclei
    nuclei_report_list = []
    nuclei_file = open("/TIP/info_scan/result/nucleiresult.txt",encoding='utf-8')
    for nuclei_line in nuclei_file.readlines(): 
        #显示优化去掉颜色字符
        pattern = re.compile(r'\x1b\[[0-9;]*m')
        clean_text = pattern.sub('', nuclei_line)
        nuclei_report_list.append(clean_text.strip())

    # Ehole
    ehole_report_list = []
    ehole_file = open("/TIP/info_scan/result/ehole_finger.txt",encoding='utf-8')
    for ehole_line in ehole_file.readlines(): 
        #显示优化去掉颜色字符
        patternq = re.compile(r'\x1b\[[0-9;]*m')
        cleanq_text = patternq.sub('', ehole_line)
        ehole_report_list.append(cleanq_text.strip())


    # bbscan
    bbscan_report_list = []
    bbscan_file = open("/TIP/info_scan/result/bbscan_info.txt",encoding='utf-8')
    for bbscan_line in bbscan_file.readlines():
        bbscan_report_list.append(bbscan_line.strip())

    # subdomain
    subdomain_report_list = []
    subdomain_file = open("/TIP/info_scan/result/subdomain.txt",encoding='utf-8')
    for subdomain_line in subdomain_file.readlines():
        subdomain_report_list.append(subdomain_line.strip())


    # vulmap
    vulmap_report_list = []
    vulmap_file = open("/TIP/info_scan/result/vulmapscan_info.txt",encoding='utf-8')
    for vulmap_line in vulmap_file.readlines(): 
        #显示优化去掉颜色字符
        patternq = re.compile(r'\x1b\[[0-9;]*m')
        cleanq_text = patternq.sub('', vulmap_line)
        vulmap_report_list.append(cleanq_text.strip())

    # xray
    xray_report_list = ["xray_poc-->预览报告-->查看报告"]
    
    # urlfinder
    urlfinder_report_list = ["目录扫描-->预览报告-->查看报告"]

    # afrog
    afrog_report_list = ["afrog_poc-->预览报告-->查看报告"]

    # ceye_dns
    ceye_dns = os.popen('bash ./finger.sh ceye_dns'+' '+ceye_key).read()
    ceye_dns_list = [ceye_dns]

    # ceye_dns
    ceye_http = os.popen('bash ./finger.sh ceye_http'+' '+ceye_key).read()
    ceye_http_list = [ceye_http]


    # fscan
    fscan_report_list = []
    fscan_file = open("/TIP/info_scan/result/fscan_vuln.txt",encoding='utf-8')
    for fscan_line in fscan_file.readlines():
        fscan_report_list.append(fscan_line.strip())


    # shiro报告
    lines = []
    with open('/TIP/info_scan/result/shiro_vuln.txt', 'r') as f:
        for line in f:
            lines.append(line.strip())    
     #文件结果优化展示
    liness = []
    for line1 in lines:
        #页面显示优化
        pattern = re.compile(r'\x1b\[[0-9;]*m')
        clean_text = pattern.sub('', line1)
        liness.append(clean_text)
    # 使用列表推导式创建一个新列表，其中不包含以'Checking :'开头的元素  
    filtered_list = [item for item in liness if not item.startswith('Checking :')]
    filtered_list_new = []
    for fi in filtered_list:
        result = fi.replace("","")
        filtered_list_new.append(result)

     # springboot
    springboot_report_list = []
    springboot_file = open("/TIP/info_scan/result/springboot_result.txt",encoding='utf-8')
    for springboot_line in springboot_file.readlines():
        springboot_report_list.append(springboot_line.strip())   


    # hydra弱口令
    hydra_report_list = []
    hydra_file = open("/TIP/info_scan/result/hydra_result.txt",encoding='utf-8')
    for hydra_line in hydra_file.readlines():
        hydra_report_list.append(hydra_line.strip())
    

    # thinkphp
    thinkphp_report_list = []
    thinkphp_file = open("/TIP/info_scan/result/thinkphp_vuln.txt",encoding='utf-8')
    for thinkphp_line in thinkphp_file.readlines():
        thinkphp_report_list.append(thinkphp_line.strip())


    # 历史url
    otx_url_report_list = []
    otx_url_file = open("/TIP/info_scan/result/otxhistoryurl.txt",encoding='utf-8')
    for otx_url_line in otx_url_file.readlines():
        otx_url_report_list.append(otx_url_line.strip())

    
    # weaver
    weaver_report_list = []
    weaver_file = open("/TIP/info_scan/result/weaver_vuln.txt",encoding='utf-8')
    for weaver_line in weaver_file.readlines(): 
        #显示优化去掉颜色字符
        pattern = re.compile(r'\x1b\[[0-9;]*m')
        clean_text = pattern.sub('', weaver_line)
        weaver_report_list.append(clean_text.strip())

     # es未授权访问
    es_report_list = []
    es_file = open("/TIP/info_scan/result/esunauthorized.txt",encoding='utf-8')
    for es_line in es_file.readlines():
        es_report_list.append(es_line.strip())


    # nacos漏洞
    nacos_report_list = []
    nacos_file = open("/TIP/info_scan/result/nacosvuln.txt",encoding='utf-8')
    for nacos_line in nacos_file.readlines():
        nacos_report_list.append(nacos_line.strip())

    # JNDI日志
    jndi_report_list = []
    jndi_file = open("/TIP/info_scan/result/jndi_result.txt",encoding='utf-8')
    for jndi_line in jndi_file.readlines():
        jndi_report_list.append(jndi_line.strip())

    # tomcat漏洞
    tomcat_report_list = []
    tomcat_file = open("/TIP/info_scan/result/tomcat_vuln.txt",encoding='utf-8')
    for tomcat_line in tomcat_file.readlines():
        tomcat_report_list.append(tomcat_line.strip())
    
    # fastjson漏洞
    fastjson_report_list = []
    fastjson_file = open("/TIP/info_scan/result/fastjson_vuln.txt",encoding='utf-8')
    for fastjson_line in fastjson_file.readlines():
        fastjson_report_list.append(fastjson_line.strip())
    
    # WAF识别
    waf_report_list = []
    waf_file = open("/TIP/info_scan/result/waf_result.txt",encoding='utf-8')
    for waf_line in waf_file.readlines():
        waf_report_list.append(waf_line.strip())

    # 40Xbypass
    bypass_report_list = []
    bypass_file = open("/TIP/info_scan/result/403bypass_result.txt",encoding='utf-8')
    for bypass_line in bypass_file.readlines():
        bypass_report_list.append(bypass_line.strip())
    
    
    # 将列表转换为 pandas 的 DataFrame
    df_a = pd.DataFrame(weblogic_report_list, columns=['weblogic'])
    df_b = pd.DataFrame(nmap_report_list, columns=['端口信息'])
    df_c = pd.DataFrame(struts2_report_list, columns=['struts2'])
    df_d = pd.DataFrame(nuclei_report_list, columns=['nuclei'])
    df_e = pd.DataFrame(ehole_report_list, columns=['指纹信息'])
    df_f = pd.DataFrame(bbscan_report_list, columns=['敏感信息'])
    df_g = pd.DataFrame(subdomain_report_list, columns=['子域名'])
    df_h = pd.DataFrame(vulmap_report_list, columns=['vulmap'])
    df_i = pd.DataFrame(xray_report_list, columns=['xray'])
    df_j = pd.DataFrame(urlfinder_report_list, columns=['urlfinder'])
    df_k = pd.DataFrame(afrog_report_list, columns=['afrog'])
    df_l = pd.DataFrame(ceye_dns_list, columns=['ceye_dns'])
    df_m = pd.DataFrame(ceye_http_list, columns=['ceye_http'])
    df_n = pd.DataFrame(fscan_report_list, columns=['fscan'])
    df_o = pd.DataFrame(filtered_list_new, columns=['shiro'])
    df_p = pd.DataFrame(springboot_report_list, columns=['springboot'])
    df_r = pd.DataFrame(hydra_report_list, columns=['hydra'])
    df_s = pd.DataFrame(thinkphp_report_list, columns=['thinkphp'])
    df_t = pd.DataFrame(otx_url_report_list, columns=['历史url'])
    df_u = pd.DataFrame(weaver_report_list, columns=['泛微OA'])
    df_v = pd.DataFrame(es_report_list, columns=['ES未授权'])
    df_w = pd.DataFrame(nacos_report_list, columns=['nacos'])
    df_x = pd.DataFrame(jndi_report_list, columns=['JNDI日志'])
    df_y = pd.DataFrame(tomcat_report_list, columns=['tomcat'])
    df_z = pd.DataFrame(fastjson_report_list, columns=['fastjson'])
    df_a1 = pd.DataFrame(waf_report_list, columns=['WAF'])
    df_b1 = pd.DataFrame(bypass_report_list, columns=['40Xbypass'])

    # 创建一个 ExcelWriter 对象，用于写入 Excel 文件  
    with pd.ExcelWriter('/TIP/info_scan/result/vuln_report.xlsx', engine='openpyxl') as writer:
        # 将 DataFrame 写入不同的工作表  
        df_a.to_excel(writer, sheet_name='weblogic', index=False)
        df_b.to_excel(writer, sheet_name='端口信息', index=False)
        df_c.to_excel(writer, sheet_name='struts2', index=False)
        df_d.to_excel(writer, sheet_name='nuclei', index=False)
        df_e.to_excel(writer, sheet_name='指纹信息', index=False)
        df_f.to_excel(writer, sheet_name='敏感信息', index=False)
        df_g.to_excel(writer, sheet_name='子域名', index=False)
        df_h.to_excel(writer, sheet_name='vulmap', index=False)
        df_i.to_excel(writer, sheet_name='xray', index=False)
        df_j.to_excel(writer, sheet_name='urlfinder', index=False)
        df_k.to_excel(writer, sheet_name='afrog', index=False)
        df_l.to_excel(writer, sheet_name='ceye_dns', index=False)
        df_m.to_excel(writer, sheet_name='ceye_http', index=False)
        df_n.to_excel(writer, sheet_name='fscan', index=False)
        df_o.to_excel(writer, sheet_name='shiro', index=False)
        df_p.to_excel(writer, sheet_name='springboot', index=False)
        df_r.to_excel(writer, sheet_name='hydra', index=False)
        df_s.to_excel(writer, sheet_name='thinkphp', index=False)
        df_t.to_excel(writer, sheet_name='历史url', index=False)
        df_u.to_excel(writer, sheet_name='泛微OA', index=False)
        df_v.to_excel(writer, sheet_name='ES未授权', index=False)
        df_w.to_excel(writer, sheet_name='nacos', index=False)
        df_x.to_excel(writer, sheet_name='JNDI日志', index=False)
        df_y.to_excel(writer, sheet_name='tomcat', index=False)
        df_z.to_excel(writer, sheet_name='fastjson', index=False)
        df_a1.to_excel(writer, sheet_name='WAF', index=False)
        df_b1.to_excel(writer, sheet_name='40Xbypass', index=False)