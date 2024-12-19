'''
Description:[整合扫描器报告存入到vuln_report.xlsx中]
Author:[huan666]
Date:[2024/05/31]
pip install pandas openpyxl
'''
import pandas as pd
import os
import re
import basic

def report_xlsx():

    # 每次执行清空历史报告，生成新数据
    os.popen('rm -rf /TIP/info_scan/result/vuln_report.xlsx')

    # 新增列表为空判断
    # weblogic
    weblogic_report_list = []
    weblogic_file = open("/TIP/info_scan/result/weblogic_poc.txt",encoding='utf-8')
    for weblogic_line in weblogic_file.readlines():
        weblogic_report_list.append(weblogic_line.strip())
    if len(weblogic_report_list) == 0:
        weblogic_report_list.append("暂无数据")

    # nmap
    nmap_report_list = []
    nmap_file = open("/TIP/info_scan/result/nmap.txt",encoding='utf-8')
    for nmap_line in nmap_file.readlines():
        nmap_report_list.append(nmap_line.strip())
    if len(nmap_report_list) == 0:
        nmap_report_list.append("暂无数据")
    
    # struts2
    struts2_report_list = []
    struts2_file = open("/TIP/info_scan/result/struts2_poc.txt",encoding='utf-8')
    for struts2_line in struts2_file.readlines():
        struts2_report_list.append(struts2_line.strip())
    if len(struts2_report_list) == 0:
        struts2_report_list.append("暂无数据")

    # nuclei
    nuclei_report_list = []
    nuclei_file = open("/TIP/info_scan/result/nucleiresult.txt",encoding='utf-8')
    for nuclei_line in nuclei_file.readlines(): 
        #显示优化去掉颜色字符
        pattern = re.compile(r'\x1b\[[0-9;]*m')
        clean_text = pattern.sub('', nuclei_line)
        nuclei_report_list.append(clean_text.strip())
    if len(nuclei_report_list) == 0:
        nuclei_report_list.append("暂无数据")

    # Ehole
    ehole_report_list = []
    ehole_file = open("/TIP/info_scan/result/ehole_finger.txt",encoding='utf-8')
    for ehole_line in ehole_file.readlines(): 
        #显示优化去掉颜色字符
        patternq = re.compile(r'\x1b\[[0-9;]*m')
        cleanq_text = patternq.sub('', ehole_line)
        ehole_report_list.append(cleanq_text.strip())
    if len(ehole_report_list) == 0:
        ehole_report_list.append("暂无数据")

    # bbscan
    bbscan_report_list = []
    bbscan_file = open("/TIP/info_scan/result/bbscan_info.txt",encoding='utf-8')
    for bbscan_line in bbscan_file.readlines():
        bbscan_report_list.append(bbscan_line.strip())
    if len(bbscan_report_list) == 0:
        bbscan_report_list.append("暂无数据")

    # subdomain
    subdomain_report_list = []
    subdomain_file = open("/TIP/info_scan/result/subdomain.txt",encoding='utf-8')
    for subdomain_line in subdomain_file.readlines():
        subdomain_report_list.append(subdomain_line.strip())
    if len(subdomain_report_list) == 0:
        subdomain_report_list.append("暂无数据")

    # vulmap
    vulmap_report_list = []
    vulmap_file = open("/TIP/info_scan/result/vulmapscan_info.txt",encoding='utf-8')
    for vulmap_line in vulmap_file.readlines(): 
        #显示优化去掉颜色字符
        patternq = re.compile(r'\x1b\[[0-9;]*m')
        cleanq_text = patternq.sub('', vulmap_line)
        vulmap_report_list.append(cleanq_text.strip())
    if len(vulmap_report_list) == 0:
        vulmap_report_list.append("暂无数据")

    # xray
    xray_report_list = ["xray_poc-->预览报告-->查看报告"]
    
    # urlfinder
    urlfinder_report_list = ["目录扫描-->预览报告-->查看报告"]

    # afrog
    afrog_report_list = ["afrog_poc-->预览报告-->查看报告"]

    # ceye_dns
    ceye_key = basic.select_session_time_lib(5)
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
    if len(fscan_report_list) == 0:
        fscan_report_list.append("暂无数据")


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
    if len(filtered_list_new) == 0:
        filtered_list_new.append("暂无数据")

     # springboot
    springboot_report_list = []
    springboot_file = open("/TIP/info_scan/result/springboot_result.txt",encoding='utf-8')
    for springboot_line in springboot_file.readlines():
        springboot_report_list.append(springboot_line.strip())   
    if len(springboot_report_list) == 0:
        springboot_report_list.append("暂无数据")

    # hydra弱口令
    hydra_report_list = []
    hydra_file = open("/TIP/info_scan/result/hydra_result.txt",encoding='utf-8')
    for hydra_line in hydra_file.readlines():
        hydra_report_list.append(hydra_line.strip())
    if len(hydra_report_list) == 0:
        hydra_report_list.append("暂无数据")

    # thinkphp
    thinkphp_report_list = []
    thinkphp_file = open("/TIP/info_scan/result/thinkphp_vuln.txt",encoding='utf-8')
    for thinkphp_line in thinkphp_file.readlines():
        thinkphp_report_list.append(thinkphp_line.strip())
    if len(thinkphp_report_list) == 0:
        thinkphp_report_list.append("暂无数据")


    # 历史url
    otx_url_report_list = []
    otx_url_file = open("/TIP/info_scan/result/otxhistoryurl.txt",encoding='utf-8')
    for otx_url_line in otx_url_file.readlines():
        otx_url_report_list.append(otx_url_line.strip())
    if len(otx_url_report_list) == 0:
        otx_url_report_list.append("暂无数据")

    
    # weaver
    weaver_report_list = []
    weaver_file = open("/TIP/info_scan/result/weaver_vuln.txt",encoding='utf-8')
    for weaver_line in weaver_file.readlines(): 
        #显示优化去掉颜色字符
        pattern = re.compile(r'\x1b\[[0-9;]*m')
        clean_text = pattern.sub('', weaver_line)
        weaver_report_list.append(clean_text.strip())
    if len(weaver_report_list) == 0:
        weaver_report_list.append("暂无数据")

     # es未授权访问
    es_report_list = []
    es_file = open("/TIP/info_scan/result/esunauthorized.txt",encoding='utf-8')
    for es_line in es_file.readlines():
        es_report_list.append(es_line.strip())
    if len(es_report_list) == 0:
        es_report_list.append("暂无数据")


    # nacos漏洞
    nacos_report_list = []
    nacos_file = open("/TIP/info_scan/result/nacosvuln.txt",encoding='utf-8')
    for nacos_line in nacos_file.readlines():
        nacos_report_list.append(nacos_line.strip())
    if len(nacos_report_list) == 0:
        nacos_report_list.append("暂无数据")

    # JNDI日志
    jndi_report_list = []
    jndi_file = open("/TIP/info_scan/result/jndi_result.txt",encoding='utf-8')
    for jndi_line in jndi_file.readlines():
        jndi_report_list.append(jndi_line.strip())
    if len(jndi_report_list) == 0:
        jndi_report_list.append("暂无数据")

    # tomcat漏洞
    tomcat_report_list = []
    tomcat_file = open("/TIP/info_scan/result/tomcat_vuln.txt",encoding='utf-8')
    for tomcat_line in tomcat_file.readlines():
        tomcat_report_list.append(tomcat_line.strip())
    if len(tomcat_report_list) == 0:
        tomcat_report_list.append("暂无数据")
    
    # fastjson漏洞
    fastjson_report_list = []
    fastjson_file = open("/TIP/info_scan/result/fastjson_vuln.txt",encoding='utf-8')
    for fastjson_line in fastjson_file.readlines():
        fastjson_report_list.append(fastjson_line.strip())
    if len(fastjson_report_list) == 0:
        fastjson_report_list.append("暂无数据")
    
    # WAF识别
    waf_report_list = []
    waf_file = open("/TIP/info_scan/result/waf_result.txt",encoding='utf-8')
    for waf_line in waf_file.readlines():
        waf_report_list.append(waf_line.strip())
    if len(waf_report_list) == 0:
        waf_report_list.append("暂无数据")

    # fuzz
    bypass_report_list = []
    bypass_file = open("/TIP/info_scan/result/403bypass_result.txt",encoding='utf-8')
    for bypass_line in bypass_file.readlines():
        bypass_report_list.append(bypass_line.strip())
    if len(bypass_report_list) == 0:
        bypass_report_list.append("暂无数据")
    
    # crawlergo
    crawlergo_report_list = []
    crawlergo_file = open("/TIP/info_scan/result/crawlergo_result.txt",encoding='utf-8')
    for crawlergo_line in crawlergo_file.readlines():
        crawlergo_report_list.append(crawlergo_line.strip())
    if len(crawlergo_report_list) == 0:
        crawlergo_report_list.append("暂无数据")

    # 致远OA
    seeyon_report_list = []
    seeyon_file = open("/TIP/info_scan/result/seeyon_vuln.txt",encoding='utf-8')
    for seeyon_line in seeyon_file.readlines():
        seeyon_report_list.append(seeyon_line.strip())
    if len(seeyon_report_list) == 0:
        seeyon_report_list.append("暂无数据")

    # 用友OA
    yonsuite_report_list = []
    yonsuite_file = open("/TIP/info_scan/result/yonsuite_vuln.txt",encoding='utf-8')
    for yonsuite_line in yonsuite_file.readlines():
        yonsuite_report_list.append(yonsuite_line.strip())
    if len(yonsuite_report_list) == 0:
        yonsuite_report_list.append("暂无数据")

    # 金蝶OA
    kingdee_report_list = []
    kingdee_file = open("/TIP/info_scan/result/kingdee_vuln.txt",encoding='utf-8')
    for kingdee_line in kingdee_file.readlines():
        kingdee_report_list.append(kingdee_line.strip())
    if len(kingdee_report_list) == 0:
        kingdee_report_list.append("暂无数据")

    # 万户OA
    wanhu_report_list = []
    wanhu_file = open("/TIP/info_scan/result/wanhu_vuln.txt",encoding='utf-8')
    for wanhu_line in wanhu_file.readlines():
        wanhu_report_list.append(wanhu_line.strip())
    if len(wanhu_report_list) == 0:
        wanhu_report_list.append("暂无数据")

    # redis
    redis_report_list = []
    redis_file = open("/TIP/info_scan/result/redis_unauthorized.txt",encoding='utf-8')
    for redis_line in redis_file.readlines():
        redis_report_list.append(redis_line.strip())
    if len(redis_report_list) == 0:
        redis_report_list.append("暂无数据")

    # mongodb
    mongodb_report_list = []
    mongodb_file = open("/TIP/info_scan/result/mongodb_unauthorized.txt",encoding='utf-8')
    for mongodb_line in mongodb_file.readlines():
        mongodb_report_list.append(mongodb_line.strip())
    if len(mongodb_report_list) == 0:
        mongodb_report_list.append("暂无数据")

    # memcached
    memcached_report_list = []
    memcached_file = open("/TIP/info_scan/result/memcached_unauthorized.txt",encoding='utf-8')
    for memcached_line in memcached_file.readlines():
        memcached_report_list.append(memcached_line.strip())
    if len(memcached_report_list) == 0:
        memcached_report_list.append("暂无数据")

    # zookeeper
    zookeeper_report_list = []
    zookeeper_file = open("/TIP/info_scan/result/zookeeper_unauthorized.txt",encoding='utf-8')
    for zookeeper_line in zookeeper_file.readlines():
        zookeeper_report_list.append(zookeeper_line.strip())
    if len(zookeeper_report_list) == 0:
        zookeeper_report_list.append("暂无数据")

     # ftp
    ftp_report_list = []
    ftp_file = open("/TIP/info_scan/result/ftp_unauthorized.txt",encoding='utf-8')
    for ftp_line in ftp_file.readlines():
        ftp_report_list.append(ftp_line.strip())
    if len(ftp_report_list) == 0:
        ftp_report_list.append("暂无数据")


    # CouchDB
    CouchDB_report_list = []
    CouchDB_file = open("/TIP/info_scan/result/couchdb_unauthorized.txt",encoding='utf-8')
    for CouchDB_line in CouchDB_file.readlines():
        CouchDB_report_list.append(CouchDB_line.strip())
    if len(CouchDB_report_list) == 0:
        CouchDB_report_list.append("暂无数据")

    # docker
    docker_report_list = []
    docker_file = open("/TIP/info_scan/result/docker_unauthorized.txt",encoding='utf-8')
    for docker_line in docker_file.readlines():
        docker_report_list.append(docker_line.strip())
    if len(docker_report_list) == 0:
        docker_report_list.append("暂无数据")
    
    # hadoop
    hadoop_report_list = []
    hadoop_file = open("/TIP/info_scan/result/hadoop_unauthorized.txt",encoding='utf-8')
    for hadoop_line in hadoop_file.readlines():
        hadoop_report_list.append(hadoop_line.strip())
    if len(hadoop_report_list) == 0:
        hadoop_report_list.append("暂无数据")

    # nfs
    nfs_report_list = []
    nfs_file = open("/TIP/info_scan/result/nfs_unauthorized.txt",encoding='utf-8')
    for nfs_line in nfs_file.readlines():
        nfs_report_list.append(nfs_line.strip())
    if len(nfs_report_list) == 0:
        nfs_report_list.append("暂无数据")
    
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
    df_b1 = pd.DataFrame(bypass_report_list, columns=['FUZZ'])
    df_c1 = pd.DataFrame(crawlergo_report_list, columns=['crawlergo'])
    df_d1 = pd.DataFrame(seeyon_report_list, columns=['致远OA'])
    df_e1 = pd.DataFrame(yonsuite_report_list, columns=['用友OA'])
    df_f1 = pd.DataFrame(kingdee_report_list, columns=['金蝶OA'])
    df_g1 = pd.DataFrame(wanhu_report_list, columns=['万户OA'])
    df_h1 = pd.DataFrame(redis_report_list, columns=['redis'])
    df_i1 = pd.DataFrame(mongodb_report_list, columns=['mongodb'])
    df_j1 = pd.DataFrame(memcached_report_list, columns=['memcached'])
    df_k1 = pd.DataFrame(zookeeper_report_list, columns=['zookeeper'])
    df_l1 = pd.DataFrame(ftp_report_list, columns=['ftp'])
    df_m1 = pd.DataFrame(CouchDB_report_list, columns=['CouchDB'])
    df_n1 = pd.DataFrame(docker_report_list, columns=['docker'])
    df_o1 = pd.DataFrame(hadoop_report_list, columns=['hadoop'])
    df_p1 = pd.DataFrame(nfs_report_list, columns=['NFS'])


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
        df_b1.to_excel(writer, sheet_name='FUZZ', index=False)
        df_c1.to_excel(writer, sheet_name='crawlergo', index=False)
        df_d1.to_excel(writer, sheet_name='致远OA', index=False)
        df_e1.to_excel(writer, sheet_name='用友OA', index=False)
        df_f1.to_excel(writer, sheet_name='金蝶OA', index=False)
        df_g1.to_excel(writer, sheet_name='万户OA', index=False)
        df_h1.to_excel(writer, sheet_name='redis', index=False)
        df_i1.to_excel(writer, sheet_name='mongodb', index=False)
        df_j1.to_excel(writer, sheet_name='memcached', index=False)
        df_k1.to_excel(writer, sheet_name='zookeeper', index=False)
        df_l1.to_excel(writer, sheet_name='ftp', index=False)
        df_m1.to_excel(writer, sheet_name='CouchDB', index=False)
        df_n1.to_excel(writer, sheet_name='docker', index=False)
        df_o1.to_excel(writer, sheet_name='hadoop', index=False)
        df_p1.to_excel(writer, sheet_name='NFS', index=False)