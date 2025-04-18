function largescreenfunc() {
    // 定义一个函数来处理AJAX请求
    function fetchData() {
        $.getJSON("/largescreenpagedata/",
            function (info) {
                // 系统信息实时显示
                document.getElementById("cpuid").innerHTML = info.cpuinfo;
                document.getElementById("cputhreadsid").innerHTML = info.cpu_threads;
                document.getElementById("memoryid").innerHTML = info.memoryinfo;
                document.getElementById("urlid").innerHTML = info.total_assets_num;
                document.getElementById("disk_read_id").innerHTML = info.disk_read;
                document.getElementById("disk_write_id").innerHTML = info.disk_write;
                document.getElementById("pidnumid").innerHTML = info.pidnum;
                document.getElementById("networkid").innerHTML = info.net_rate;
                document.getElementById("hostnameassetsid").innerHTML = info.assets_hostname;
                document.getElementById("siteassetsid").innerHTML = info.assets_site;
                document.getElementById("shodanpercentid").innerHTML = info.shodan_account_info_percent;
                document.getElementById("sessiontimeid").innerHTML = info.session_time;
                // 第三方接口额度成功和失败查询
                document.getElementById("fofasuccessid").innerHTML = info.fofa_inter_num_success;
                document.getElementById("fofafailid").innerHTML = info.fofa_inter_num_fail;
                document.getElementById("shodansuccessid").innerHTML = info.shodan_inter_num_success;
                document.getElementById("shodanfailid").innerHTML = info.shodan_inter_num_fail;
                document.getElementById("crtsuccessid").innerHTML = info.crt_inter_num_success;
                document.getElementById("crtfailid").innerHTML = info.crt_inter_num_fail;
                document.getElementById("icpsuccessid").innerHTML = info.icp_inter_num_success;
                document.getElementById("icpfailid").innerHTML = info.icp_inter_num_fail;
                document.getElementById("gdsuccessid").innerHTML = info.gd_inter_num_success;
                document.getElementById("gdfailid").innerHTML = info.gd_inter_num_fail;
                document.getElementById("otxsuccessid").innerHTML = info.otx_inter_num_success;
                document.getElementById("otxfailid").innerHTML = info.otx_inter_num_fail;

                // 第三方接口额度总量和剩余查询
                document.getElementById("fofatotalid").innerHTML = info.tatal_fofa_num;
                document.getElementById("fofaremainid").innerHTML = info.fofa_remaining_num;
                document.getElementById("shodantotalid").innerHTML = info.total_shodan_num;
                document.getElementById("shodanremainid").innerHTML = info.shodan_remaining_num;
                document.getElementById("crttotalid").innerHTML = info.tatal_crt_num;
                document.getElementById("crtremainid").innerHTML = info.crt_remaining_num;
                document.getElementById("icptotalid").innerHTML = info.tatal_icp_num;
                document.getElementById("icpremainid").innerHTML = info.icp_remaining_num;
                document.getElementById("amaptotalid").innerHTML = info.tatal_amap_num;
                document.getElementById("amapremainid").innerHTML = info.amap_remaining_num;
                document.getElementById("otxtotalid").innerHTML = info.tatal_otx_num;
                document.getElementById("otxremainid").innerHTML = info.otx_remaining_num;

                // 高危资产数量统计
                document.getElementById("pointassetsid1").innerHTML = info.shiro_num;
                document.getElementById("pointassetsid2").innerHTML = info.springboot_num;
                document.getElementById("pointassetsid3").innerHTML = info.struts2_num;
                document.getElementById("pointassetsid4").innerHTML = info.weblogic_num;
                document.getElementById("pointassetsid5").innerHTML = info.ruoyi_num;
                document.getElementById("pointassetsid6").innerHTML = info.WordPress_num;
                document.getElementById("pointassetsid7").innerHTML = info.jboss_num;
                document.getElementById("pointassetsid8").innerHTML = info.phpmyadmin_num;
                document.getElementById("pointassetsid9").innerHTML = info.ThinkPHP_num;
                document.getElementById("pointassetsid10").innerHTML = info.nacos_num;
                document.getElementById("pointassetsid11").innerHTML = info.fanwei_num;
                document.getElementById("pointassetsid12").innerHTML = info.tomcat_num;

                // 服务运行状态实时统计查询
                document.getElementById("jndiserviceid1").innerHTML = info.jndi_status1;
                document.getElementById("jndiserviceid2").innerHTML = info.jndi_status2;
                document.getElementById("xrayreportserviceid1").innerHTML = info.xray_report_status1;
                document.getElementById("xrayreportserviceid2").innerHTML = info.xray_report_status2;
                document.getElementById("urlfinderreportserviceid1").innerHTML = info.urlfinder_report_status1;
                document.getElementById("urlfinderreportserviceid2").innerHTML = info.urlfinder_report_status2;
                document.getElementById("afrogreportserviceid1").innerHTML = info.afrog_report_status1;
                document.getElementById("afrogreportserviceid2").innerHTML = info.afrog_report_status2;
                document.getElementById("pythoninfoid1").innerHTML = info.infoinfostatus1;
                document.getElementById("pythoninfoid2").innerHTML = info.infoinfostatus2;
                document.getElementById("pythonsubinfoid1").innerHTML = info.dirsub_sys_status1;
                document.getElementById("pythonsubinfoid2").innerHTML = info.dirsub_sys_status2;
                document.getElementById("mysqlserviceid1").innerHTML = info.mysql_status1;
                document.getElementById("mysqlserviceid2").innerHTML = info.mysql_status2;
                document.getElementById("xraybindportid1").innerHTML = info.xraystatus1;
                document.getElementById("xraybindportid2").innerHTML = info.xraystatus2;
                document.getElementById("totalreportid1").innerHTML = info.total_report_status_result1;
                document.getElementById("totalreportid2").innerHTML = info.total_report_status_result2;
                document.getElementById("cdnscanid1").innerHTML = info.cdn_status1;
                document.getElementById("cdnscanid2").innerHTML = info.cdn_status2;

                // 未授权专项扫描状态和耗时
                document.getElementById("unredisscanid1").innerHTML = info.redis_status1;
                document.getElementById("unredisscanid2").innerHTML = info.redis_status2;
                document.getElementById("unredisscanid3").innerHTML = info.rediscontime;
                document.getElementById("unmongodbid1").innerHTML = info.mongodb_status1;
                document.getElementById("unmongodbid2").innerHTML = info.mongodb_status2;
                document.getElementById("unmongodbid3").innerHTML = info.mongodbcontime;
                document.getElementById("unmemcachedid1").innerHTML = info.memcached_status1;
                document.getElementById("unmemcachedid2").innerHTML = info.memcached_status2;
                document.getElementById("unmemcachedid3").innerHTML = info.memcachedcontime;
                document.getElementById("unzookeeperid1").innerHTML = info.zookeeper_status1;
                document.getElementById("unzookeeperid2").innerHTML = info.zookeeper_status2;
                document.getElementById("unzookeeperid3").innerHTML = info.zookeepercontime;
                document.getElementById("unftpid1").innerHTML = info.ftp_status1;
                document.getElementById("unftpid2").innerHTML = info.ftp_status2;
                document.getElementById("unftpid3").innerHTML = info.ftpcontime;
                document.getElementById("unCouchDBid1").innerHTML = info.couchdb_status1;
                document.getElementById("unCouchDBid2").innerHTML = info.couchdb_status2;
                document.getElementById("unCouchDBid3").innerHTML = info.couchdbcontime;
                document.getElementById("undockerid1").innerHTML = info.docker_status1;
                document.getElementById("undockerid2").innerHTML = info.docker_status2;
                document.getElementById("undockerid3").innerHTML = info.dockercontime;
                document.getElementById("unHadoopid1").innerHTML = info.hadoop_status1;
                document.getElementById("unHadoopid2").innerHTML = info.hadoop_status2;
                document.getElementById("unHadoopid3").innerHTML = info.hadoopcontime;
                document.getElementById("unNFSid1").innerHTML = info.nfs_status1;
                document.getElementById("unNFSid2").innerHTML = info.nfs_status2;
                document.getElementById("unNFSid3").innerHTML = info.nfscontime;
                document.getElementById("unrsyncid1").innerHTML = info.rsync_status1;
                document.getElementById("unrsyncid2").innerHTML = info.rsync_status2;
                document.getElementById("unrsyncid3").innerHTML = info.rsynccontime;
                document.getElementById("unelasticsearchid1").innerHTML = info.unes1_status1;
                document.getElementById("unelasticsearchid2").innerHTML = info.unes1_status2;
                document.getElementById("unelasticsearchid3").innerHTML = info.unes1contime;

                // 信息收集类专项
                document.getElementById("unfingerid1").innerHTML = info.eholestatus1;
                document.getElementById("unfingerid2").innerHTML = info.eholestatus2;
                document.getElementById("unfingerid3").innerHTML = info.eholecontime;
                document.getElementById("unbbscanid1").innerHTML = info.bbscanstatus1;
                document.getElementById("unbbscanid2").innerHTML = info.bbscanstatus2;
                document.getElementById("unbbscanid3").innerHTML = info.bbscancontime;
                document.getElementById("unotxscanid1").innerHTML = info.otx_status1;
                document.getElementById("unotxscanid2").innerHTML = info.otx_status2;
                document.getElementById("unotxscanid3").innerHTML = info.otxcontime;
                document.getElementById("uncrtscanid1").innerHTML = info.crt_status1;
                document.getElementById("uncrtscanid2").innerHTML = info.crt_status2;
                document.getElementById("uncrtscanid3").innerHTML = info.crtcontime;
                document.getElementById("unportscanid1").innerHTML = info.nmapstatus1;
                document.getElementById("unportscanid2").innerHTML = info.nmapstatus2;
                document.getElementById("unportscanid3").innerHTML = info.nmapcontime;
                document.getElementById("unwafscanid1").innerHTML = info.waf_status1;
                document.getElementById("unwafscanid2").innerHTML = info.waf_status2;
                document.getElementById("unwafscanid3").innerHTML = info.wafcontime;
                document.getElementById("unfuzzscanid1").innerHTML = info.bypass_status1;
                document.getElementById("unfuzzscanid2").innerHTML = info.bypass_status2;
                document.getElementById("unfuzzscanid3").innerHTML = info.bypasscontime;
                document.getElementById("unpachongscanid1").innerHTML = info.crawlergo_status1;
                document.getElementById("unpachongscanid2").innerHTML = info.crawlergo_status2;
                document.getElementById("unpachongscanid3").innerHTML = info.crawlergocontime;
                document.getElementById("unapiscanid1").innerHTML = info.subfinder_status1;
                document.getElementById("unapiscanid2").innerHTML = info.subfinder_status2;
                document.getElementById("unapiscanid3").innerHTML = info.subfindercontime;

                // 框架组件专项
                document.getElementById("unstruts2id1").innerHTML = info.struts2status1;
                document.getElementById("unstruts2id2").innerHTML = info.struts2status2;
                document.getElementById("unstruts2id3").innerHTML = info.struts2contime;
                document.getElementById("unweblogicid1").innerHTML = info.weblogicstatus1;
                document.getElementById("unweblogicid2").innerHTML = info.weblogicstatus2;
                document.getElementById("unweblogicid3").innerHTML = info.weblogiccontime;
                document.getElementById("unshiroscanid1").innerHTML = info.shirostatus1;
                document.getElementById("unshiroscanid2").innerHTML = info.shirostatus2;
                document.getElementById("unshiroscanid3").innerHTML = info.shirocontime;
                document.getElementById("unspringbootscanid1").innerHTML = info.springbootstatus1;
                document.getElementById("unspringbootscanid2").innerHTML = info.springbootstatus2;
                document.getElementById("unspringbootscanid3").innerHTML = info.springbootcontime;
                document.getElementById("unthinkphpscanid1").innerHTML = info.thinkphpstatus1;
                document.getElementById("unthinkphpscanid2").innerHTML = info.thinkphpstatus2;
                document.getElementById("unthinkphpscanid3").innerHTML = info.thinkphpcontime;
                document.getElementById("unElasticsearchscanid1").innerHTML = info.es_unauthorized_status1;
                document.getElementById("unElasticsearchscanid2").innerHTML = info.es_unauthorized_status2;
                document.getElementById("unElasticsearchscanid3").innerHTML = info.esccontime;
                document.getElementById("unnacosscanid1").innerHTML = info.nacos_status1;
                document.getElementById("unnacosscanid2").innerHTML = info.nacos_status2;
                document.getElementById("unnacosscanid3").innerHTML = info.nacoscontime;
                document.getElementById("untomcatscanid1").innerHTML = info.tomcat_status1;
                document.getElementById("untomcatscanid2").innerHTML = info.tomcat_status2;
                document.getElementById("untomcatscanid3").innerHTML = info.tomcatcontime;
                document.getElementById("unfastjsonscanid1").innerHTML = info.fastjson_status1;
                document.getElementById("unfastjsonscanid2").innerHTML = info.fastjson_status2;
                document.getElementById("unfastjsonscanid3").innerHTML = info.fastjsoncontime;

                // 综合专项
                document.getElementById("unafrogscanid1").innerHTML = info.afrogscanstatus1;
                document.getElementById("unafrogscanid2").innerHTML = info.afrogscanstatus2;
                document.getElementById("unafrogscanid3").innerHTML = info.afrogcontime;
                document.getElementById("unfscanid1").innerHTML = info.fscanstatus1;
                document.getElementById("unfscanid2").innerHTML = info.fscanstatus2;
                document.getElementById("unfscanid3").innerHTML = info.fscancontime;
                document.getElementById("unhydrascanid1").innerHTML = info.hydrastatus1;
                document.getElementById("unhydrascanid2").innerHTML = info.hydrastatus2;
                document.getElementById("unhydrascanid3").innerHTML = info.weakpasscontime;
                document.getElementById("unvulmapscanid1").innerHTML = info.vulmapscanstatus1;
                document.getElementById("unvulmapscanid2").innerHTML = info.vulmapscanstatus2;
                document.getElementById("unvulmapscanid3").innerHTML = info.vulmapcontime;
                document.getElementById("unnucleiscanid1").innerHTML = info.nucleistatus1;
                document.getElementById("unnucleiscanid2").innerHTML = info.nucleistatus2;
                document.getElementById("unnucleiscanid3").innerHTML = info.nucleicontime;
                document.getElementById("unfanweiscanid1").innerHTML = info.weaver_status1;
                document.getElementById("unfanweiscanid2").innerHTML = info.weaver_status2;
                document.getElementById("unfanweiscanid3").innerHTML = info.weavercontime;
                document.getElementById("unzhiyuanscanid1").innerHTML = info.seeyonstatus1;
                document.getElementById("unzhiyuanscanid2").innerHTML = info.seeyonstatus2;
                document.getElementById("unzhiyuanscanid3").innerHTML = info.seeyoncontime;
                document.getElementById("unyongyouscanid1").innerHTML = info.yonsuite_status1;
                document.getElementById("unyongyouscanid2").innerHTML = info.yonsuite_status2;
                document.getElementById("unyongyouscanid3").innerHTML = info.yonsuitecontime;
                document.getElementById("unjindiescanid1").innerHTML = info.kingdee_status1;
                document.getElementById("unjindiescanid2").innerHTML = info.kingdee_status2;
                document.getElementById("unjindiescanid3").innerHTML = info.kingdeecontime;
                document.getElementById("unwanhuscanid1").innerHTML = info.wanhu_status1;
                document.getElementById("unwanhuscanid2").innerHTML = info.wanhu_status2;
                document.getElementById("unwanhuscanid3").innerHTML = info.wanhucontime;
            });
    }

    // 调用fetchData函数初始化显示
    fetchData();

    // 设置定时器，每5000毫秒（5秒）执行一次fetchData函数
    var intervalId = setInterval(fetchData, 5000);
}

// 确保在页面卸载或组件销毁时清除定时器，以防止内存泄漏
window.addEventListener("beforeunload", function () {
    clearInterval(intervalId);
});
