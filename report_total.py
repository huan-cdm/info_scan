'''
Description:[整合扫描器报告存入到vuln_report.xlsx中]
Author:[huan666]
Date:[2024/05/01]
pip install pandas openpyxl
'''
import pandas as pd
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
    
    '''
    # 使用正则表达式匹配并提取URL  
    pattern = r'(https?://\S+)'  
  
    # 使用列表推导式提取URL，并检查它们是否以http://或https://开头  
    urls = [match.group(1) for entry in nuclei_report_list for match in re.finditer(pattern, entry) if match.group(1).startswith(('http://', 'https://'))]  
  
    #  nuclei 以http://或者https://开头的字符串，其余删除
    nuclei_report_list_new = []
    for url in urls:  
        nuclei_report_list_new.append(url)

    # 列表去重
    nuclei_report_list_uniq = list(set(nuclei_report_list_new))
    '''
    
    # 将列表转换为 pandas 的 DataFrame
    df_a = pd.DataFrame(weblogic_report_list, columns=['weblogic'])
    df_b = pd.DataFrame(nmap_report_list, columns=['端口信息'])
    df_c = pd.DataFrame(struts2_report_list, columns=['struts2'])
    df_d = pd.DataFrame(nuclei_report_list, columns=['nuclei'])
    df_e = pd.DataFrame(ehole_report_list, columns=['指纹信息'])
    df_f = pd.DataFrame(bbscan_report_list, columns=['敏感信息'])

    # 创建一个 ExcelWriter 对象，用于写入 Excel 文件  
    with pd.ExcelWriter('/TIP/info_scan/result/vuln_report.xlsx', engine='openpyxl') as writer:
        # 将 DataFrame 写入不同的工作表  
        df_a.to_excel(writer, sheet_name='weblogic', index=False)
        df_b.to_excel(writer, sheet_name='端口信息', index=False)
        df_c.to_excel(writer, sheet_name='struts2', index=False)
        df_d.to_excel(writer, sheet_name='nuclei', index=False)
        df_e.to_excel(writer, sheet_name='指纹信息', index=False)
        df_f.to_excel(writer, sheet_name='敏感信息', index=False)