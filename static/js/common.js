// 上线后需替换为自己的服务器IP地址
var ipvalue = "http://x.x.x.x"


function fanhui() {
    var input = document.getElementById("myInput");
    input.value = "";
    window.location.href = "/index/";
}



//nmap扫描结果预览
function nmapjumpfunc() {

    window.open("/nmapresultshow/");
}

//nuclei扫描结果预览
function nucleijumpfunc() {

    window.open("/nucleiresultshow/");
}


//xray报告预览
function xrayreportshow() {
    window.open(ipvalue + ":18888/", "_blank");
}


//urlfinder报告预览
function urlfinderreportshow() {
    window.open(ipvalue + ":16666/", "_blank");
}


//文本框内容添加
function sendtextareadata() {
    // 获取textarea的值  
    const text = document.getElementById('myTextarea').value;
    // 按换行符分割文本为数组  
    const lines = text.split('\n');
    // 使用jQuery的$.ajax方法发送POST请求到Flask后端  
    $.ajax({
        url: '/submit_data/',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ lines: lines }),
        dataType: 'json',
        success: function (info) {
            alert(info.file_line)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    });
}




//历史url预览
function historyurlpreviewfunc() {

    window.open("/previewhistoryurl/");
}





//路径去重处理函数
function processURLs() {
    var inputUrls = document.getElementById('urlInput').value.split('\n');
    var outputDiv = document.getElementById('output');
    outputDiv.innerHTML = ''; // 清空输出区域

    var uniquePaths = [];

    inputUrls.forEach(function (url) {
        var path = url.substring(0, url.lastIndexOf('/') + 1);
        if (!uniquePaths.includes(path)) {
            uniquePaths.push(path);
            var outputLine = document.createElement('p');
            outputLine.textContent = path;
            outputDiv.appendChild(outputLine);
        }
    });
}

//archive 历史url查询
function archiveurlshowfunc() {
    var inputValue = document.getElementById("myInput").value;
    window.open("https://web.archive.org/cdx/search?collapse=urlkey&fl=original&limit=10000000000000000&matchType=domain&output=text&url=" + inputValue, "_blank");
}


//启用按钮
function startbutton() {
    var button2 = document.getElementById("button2");
    button2.disabled = false;
    var button3 = document.getElementById("button3");
    button3.disabled = false;
    var button19 = document.getElementById("button19");
    button19.disabled = false;
    var button20 = document.getElementById("button20");
    button20.disabled = false;
    var button24 = document.getElementById("button24");
    button24.disabled = false;
    var button25 = document.getElementById("button25");
    button25.disabled = false;
    var button51 = document.getElementById("button51");
    button51.disabled = false;
    var button63 = document.getElementById("button63");
    button63.disabled = false;
    var button72 = document.getElementById("button72");
    button72.disabled = false;
    var button73 = document.getElementById("button73");
    button73.disabled = false;
    var button74 = document.getElementById("button74");
    button74.disabled = false;
    var button75 = document.getElementById("button75");
    button75.disabled = false;
    var button76 = document.getElementById("button76");
    button76.disabled = false;
    var button77 = document.getElementById("button77");
    button77.disabled = false;
    var button83 = document.getElementById("button83");
    button83.disabled = false;
    var button84 = document.getElementById("button84");
    button84.disabled = false;
}

//禁用按钮
function stopbutton() {
    var button2 = document.getElementById("button2");
    button2.disabled = true;
    var button3 = document.getElementById("button3");
    button3.disabled = true;
    var button19 = document.getElementById("button19");
    button19.disabled = true;
    var button20 = document.getElementById("button20");
    button20.disabled = true;
    var button24 = document.getElementById("button24");
    button24.disabled = true;
    var button25 = document.getElementById("button25");
    button25.disabled = true;
    var button51 = document.getElementById("button51");
    button51.disabled = true;
    var button63 = document.getElementById("button63");
    button63.disabled = true;
    var button72 = document.getElementById("button72");
    button72.disabled = true;
    var button73 = document.getElementById("button73");
    button73.disabled = true;
    var button74 = document.getElementById("button74");
    button74.disabled = true;
    var button75 = document.getElementById("button75");
    button75.disabled = true;
    var button76 = document.getElementById("button76");
    button76.disabled = true;
    var button77 = document.getElementById("button77");
    button77.disabled = true;
    var button83 = document.getElementById("button83");
    button83.disabled = true;
    var button84 = document.getElementById("button84");
    button84.disabled = true;
}


//跳转到目录扫描页面
function jumpdirscanpage() {
    window.open(ipvalue + ":17777/dirscanpage/", "_blank");
}


//数据处理模块
function filedeweightingfunc() {
    var fileqingxiname = $('select[name="fileqingxiname"]').val();
    $.ajax({
        url: '/uniqdirsearchtargetinterface/',
        method: 'POST',
        data: {
            fileqingxiname: fileqingxiname
        },
        success: function (res) {
            console.log(res)
            console.log('资产去重成功点击文本查看最新数据')
        },
        error: function () {
            alert('资产去重处理出错')
        },
        complete: function () {
            alert('资产去重成功点击文本查看最新数据')
        }
    })
}

//存活检测
function filterstatuscodefunc() {
    $.ajax({
        url: '/filterstatuscodebyhttpx/',
        method: 'GET',

        success: function (info) {
            alert(info.httpx_status_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步启动注销系统
function signoutfunc() {
    $.ajax({
        url: '/signout/',
        method: 'GET',
        success: function (info) {
            alert(info.zhuxiaostatus);
            window.location.href = info.zhuxiaoredirect_url;
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//CDN检测
function filtercdndatafunc() {
    $.ajax({
        url: '/cdn_service_recogize/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            console.log('CDN检测成功点击文本查看最新数据')
        },
        error: function () {
            alert('存活检测出现错误')
        },
        complete: function () {
            alert('CDN检测成功点击文本查看最新数据')
        }
    })
}



//资产回退
function assetsbackspacefunc() {
    $.ajax({
        url: '/assetsbackspaceinterface/',
        method: 'GET',

        success: function (res) {
            alert('资产回退成功点击编辑资产查看最新数据')
        },
        error: function () {
            alert('内部错误')
        },
        complete: function () {
            
        }
    })
}



//weblogic_poc报告预览
function weblogicreportfunc() {
    window.open("/weblogic_poc_report/", "_blank");
}



//struts2_poc报告预览
function struts2reportfunc() {
    window.open("/struts2_poc_report/", "_blank");
}



//报告整合
function reporttotalfunc() {
    $.ajax({
        url: '/report_total_interface/',
        method: 'GET',
        success: function (info) {
            alert(info.total_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

//报告下载
function reportdownloadfunc() {
    window.open("/report_download_interface/", "_blank");
}

//ehole_finger报告预览
function eholefingerreportfunc() {
    window.open("/ehole_finger_report/", "_blank");
}


//子域名结果预览
function showsubdomainfunc() {
    window.open("/showsubdomainreport/");
}



//vulmap漏扫报告预览
function vulmapscanreportfunc() {
    window.open("/vulmapscanreport/");
}



//目标url的值赋值给 textarea 文本框
function targeturlcopytextareafunc() {
    $.ajax({
        url: '/url_list_textarea_show/',
        method: 'GET',
        success: function (info) {
            // 假设info.textvalue是一个数组  
            var textAreaContent = ''; // 初始化一个空字符串来保存textarea的内容  

            // 遍历info.textvalue数组，为每个元素添加换行符并追加到textAreaContent  
            for (var i = 0; i < info.textvalue.length; i++) {
                textAreaContent += info.textvalue[i] + '\n'; // 追加元素和换行符  
            }

            // 将textAreaContent的内容赋值给textarea  
            $('#myTextarea').val(textAreaContent); // 假设textarea的id是myTextarea
            document.getElementById("textareaspan1").innerHTML = info.lentextvalue;
        },
        error: function () {


        },
        complete: function () {

        }
    })
}


//afrog报告预览
function afrogreportfun() {
    window.open(ipvalue + ":15555/", "_blank");
}


//ceye dns记录
function ceyednsfunc() {
    window.open("/ceye_dns_record/", "_blank");
}

//ceye http记录
function ceyehttpfunc() {
    window.open("/ceye_http_record/", "_blank");
}


//fscan扫描结果预览
function fscanreprtfunc() {
    window.open("/fscanreportyulan/");
}


// fscan扫描参数值查看
function fscanportshowfunc() {
    var fscanpartname = $('select[name="fscanpartname"]').val();
    $('#myTextarea2').val(fscanpartname);
}


//shiro扫描结果预览
function shiroscanreprtfunc() {
    window.open("/shiro_report_show/");
}




//识别重点资产
function key_data_tiqu_func() {
    $.ajax({
        url: '/key_assets_withdraw/',
        method: 'GET',

        success: function (info) {
            alert(info.key_assets_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

// 系统管理调整为5秒自动请求1次
function openModal() {
    var modal = document.getElementById("modal");
    modal.style.display = "block";

    // 定义一个函数来处理AJAX请求
    function fetchData() {
        $.getJSON("/systemmanagement/",
            function (info) {


                // 运行状态显示绿色，停止状态显示红色
                document.getElementById("spp1").innerHTML = info.nmapstatus1;
                document.getElementById("spp1a").innerHTML = info.nmapstatus2;
                document.getElementById("spp2").innerHTML = info.nucleistatus1;
                document.getElementById("spp2a").innerHTML = info.nucleistatus2;
                document.getElementById("spp3").innerHTML = info.xraystatus1;
                document.getElementById("spp3a").innerHTML = info.xraystatus2;
                document.getElementById("spp4").innerHTML = info.radstatus1;
                document.getElementById("spp4a").innerHTML = info.radstatus2;
                document.getElementById("spp5").innerHTML = info.dirscanstatus1;
                document.getElementById("spp5a").innerHTML = info.dirscanstatus2;
                document.getElementById("spp6").innerHTML = info.weblogicstatus1;
                document.getElementById("spp6a").innerHTML = info.weblogicstatus2;
                document.getElementById("spp7").innerHTML = info.struts2status1;
                document.getElementById("spp7a").innerHTML = info.struts2status2;
                document.getElementById("spp8").innerHTML = info.bbscanstatus1;
                document.getElementById("spp8a").innerHTML = info.bbscanstatus2;
                document.getElementById("spp9").innerHTML = info.vulmapscanstatus1;
                document.getElementById("spp9a").innerHTML = info.vulmapscanstatus2;
                document.getElementById("spp10").innerHTML = info.afrogscanstatus1;
                document.getElementById("spp10a").innerHTML = info.afrogscanstatus2;
                document.getElementById("spp11").innerHTML = info.fscanstatus1;
                document.getElementById("spp11a").innerHTML = info.fscanstatus2;
                document.getElementById("spp12").innerHTML = info.shirostatus1;
                document.getElementById("spp12a").innerHTML = info.shirostatus2;
                document.getElementById("spp13").innerHTML = info.httpxstatus1;
                document.getElementById("spp13a").innerHTML = info.httpxstatus2;
                document.getElementById("spp14").innerHTML = info.url_file_num;
                document.getElementById("spp15").innerHTML = info.eholestatus1;
                document.getElementById("spp15a").innerHTML = info.eholestatus2;
                document.getElementById("spp16").innerHTML = info.shiro_num;
                document.getElementById("spp17").innerHTML = info.springboot_num;
                document.getElementById("spp18").innerHTML = info.weblogic_num;
                document.getElementById("spp19").innerHTML = info.baota_num;
                document.getElementById("spp20").innerHTML = info.ruoyi_num;
                document.getElementById("spp21").innerHTML = info.struts2_num;
                document.getElementById("spp22").innerHTML = info.WordPress_num;
                document.getElementById("spp23").innerHTML = info.cpuinfo;
                document.getElementById("spp24").innerHTML = info.memoryinfo;
                document.getElementById("spp25").innerHTML = info.jboss_num;
                document.getElementById("spp26").innerHTML = info.key_asset_rule;
                document.getElementById("spp27").innerHTML = info.current_key_asset_num;
                document.getElementById("spp28").innerHTML = info.springbootstatus1;
                document.getElementById("spp28a").innerHTML = info.springbootstatus2;
                document.getElementById("spp29").innerHTML = info.hydrastatus1;
                document.getElementById("spp29a").innerHTML = info.hydrastatus2;
                document.getElementById("spp30").innerHTML = info.urlfinderstatus1;
                document.getElementById("spp30a").innerHTML = info.urlfinderstatus2;
                document.getElementById("spp31").innerHTML = info.key_asset_rule_origin;
                document.getElementById("spp32").innerHTML = info.assets_status;
                document.getElementById("spp33").innerHTML = info.vuln_scan_status_shijianxian;
                document.getElementById("spp34").innerHTML = info.phpmyadmin_num;
                document.getElementById("spp35").innerHTML = info.disk_read;
                document.getElementById("spp36").innerHTML = info.disk_write;
                document.getElementById("spp37").innerHTML = info.infoinfostatus1;
                document.getElementById("spp37a").innerHTML = info.infoinfostatus2;
                document.getElementById("spp38").innerHTML = info.dirsub_sys_status1;
                document.getElementById("spp38a").innerHTML = info.dirsub_sys_status2;
                document.getElementById("spp39").innerHTML = info.xray_report_status1;
                document.getElementById("spp39a").innerHTML = info.xray_report_status2;
                document.getElementById("spp40").innerHTML = info.urlfinder_report_status1;
                document.getElementById("spp40a").innerHTML = info.urlfinder_report_status2;
                document.getElementById("spp41").innerHTML = info.afrog_report_status1;
                document.getElementById("spp41a").innerHTML = info.afrog_report_status2;
                document.getElementById("spp42").innerHTML = info.ThinkPHP_num;
                document.getElementById("spp43").innerHTML = info.thinkphpstatus1;
                document.getElementById("spp43a").innerHTML = info.thinkphpstatus2;
                document.getElementById("spp44").innerHTML = info.otx_status1;
                document.getElementById("spp44a").innerHTML = info.otx_status2;
                document.getElementById("spp45").innerHTML = info.crt_status1;
                document.getElementById("spp45a").innerHTML = info.crt_status2;
                document.getElementById("spp46").innerHTML = info.nacos_num;
                document.getElementById("spp47").innerHTML = info.fanwei_num;
                document.getElementById("spp52t").innerHTML = info.tomcat_num;
                document.getElementById("spp48").innerHTML = info.weaver_status1;
                document.getElementById("spp48a").innerHTML = info.weaver_status2;
                document.getElementById("spp49").innerHTML = info.es_unauthorized_status1;
                document.getElementById("spp49a").innerHTML = info.es_unauthorized_status2;
                document.getElementById("spp50").innerHTML = info.nacos_status1;
                document.getElementById("spp50a").innerHTML = info.nacos_status2;
                document.getElementById("spp51").innerHTML = info.tomcat_status1;
                document.getElementById("spp51a").innerHTML = info.tomcat_status2;
                document.getElementById("spp52").innerHTML = info.jndi_status1;
                document.getElementById("spp52a").innerHTML = info.jndi_status2;
                document.getElementById("spp53").innerHTML = info.jndi_python_status1;
                document.getElementById("spp53a").innerHTML = info.jndi_python_status2;
                document.getElementById("spp54").innerHTML = info.fastjson_status1;
                document.getElementById("spp54a").innerHTML = info.fastjson_status2;
                document.getElementById("spp55").innerHTML = info.waf_status1;
                document.getElementById("spp55a").innerHTML = info.waf_status2;
                document.getElementById("spp56").innerHTML = info.bypass_status1;
                document.getElementById("spp56a").innerHTML = info.bypass_status2;
                document.getElementById("spp57").innerHTML = info.crawlergo_status1;
                document.getElementById("spp57a").innerHTML = info.crawlergo_status2;
                document.getElementById("spp58").innerHTML = info.seeyonstatus1;
                document.getElementById("spp58a").innerHTML = info.seeyonstatus2;
                document.getElementById("spp59").innerHTML = info.yonsuite_status1;
                document.getElementById("spp59a").innerHTML = info.yonsuite_status2;
                document.getElementById("spp60").innerHTML = info.kingdee_status1;
                document.getElementById("spp60a").innerHTML = info.kingdee_status2;
                document.getElementById("spp1h2").innerHTML = info.finger_jindu;
                document.getElementById("successsp1").innerHTML = info.fofa_inter_num_success;
                document.getElementById("failsp1").innerHTML = info.fofa_inter_num_fail;
                document.getElementById("successsp2").innerHTML = info.shodan_inter_num_success;
                document.getElementById("failsp2").innerHTML = info.shodan_inter_num_fail;
                document.getElementById("successsp3").innerHTML = info.crt_inter_num_success;
                document.getElementById("failsp3").innerHTML = info.crt_inter_num_fail;
                document.getElementById("successsp4").innerHTML = info.icp_inter_num_success;
                document.getElementById("failsp4").innerHTML = info.icp_inter_num_fail;
                document.getElementById("successsp5").innerHTML = info.gd_inter_num_success;
                document.getElementById("failsp5").innerHTML = info.gd_inter_num_fail;
                document.getElementById("successsp6").innerHTML = info.otx_inter_num_success;
                document.getElementById("failsp6").innerHTML = info.otx_inter_num_fail;
                // 第三方接口额度查看
                document.getElementById("totalsp1").innerHTML = info.fofa_max_num;
                document.getElementById("totalsp2").innerHTML = info.shodan_max_num;
                document.getElementById("totalsp3").innerHTML = info.crt_max_num;
                document.getElementById("totalsp4").innerHTML = info.icp_max_num;
                document.getElementById("totalsp5").innerHTML = info.amap_max_num;
                document.getElementById("totalsp6").innerHTML = info.otx_max_num;
                // 第三方接口剩余额度查询
                document.getElementById("overtotalsp1").innerHTML = info.fofa_remaining_num;
                document.getElementById("overtotalsp2").innerHTML = info.shodan_remaining_num;
                document.getElementById("overtotalsp3").innerHTML = info.crt_remaining_num;
                document.getElementById("overtotalsp4").innerHTML = info.icp_remaining_num;
                document.getElementById("overtotalsp5").innerHTML = info.amap_remaining_num;
                document.getElementById("overtotalsp6").innerHTML = info.otx_remaining_num;
                document.getElementById("totalspp2").innerHTML = info.total_report_status_result2;
                document.getElementById("totalspp1").innerHTML = info.total_report_status_result1;
                // 扫描器耗时统计
                document.getElementById("diffnmapid").innerHTML = info.nmapcontime;
                document.getElementById("diffeholeid").innerHTML = info.eholecontime;
                document.getElementById("diffbbscanid").innerHTML = info.bbscancontime;
                document.getElementById("diffotxid").innerHTML = info.otxcontime;
                document.getElementById("diffcrtid").innerHTML = info.crtcontime;
                document.getElementById("diffwafid").innerHTML = info.wafcontime;
                document.getElementById("difffuzzid").innerHTML = info.bypasscontime;
                document.getElementById("diffcrawlergoid").innerHTML = info.crawlergocontime;
                document.getElementById("diffseeyonid").innerHTML = info.seeyoncontime;
                document.getElementById("diffyonsuiteid").innerHTML = info.yonsuitecontime;
                document.getElementById("diffkingdeeid").innerHTML = info.kingdeecontime;
                document.getElementById("diffstruts2id").innerHTML = info.struts2contime;
                document.getElementById("diffweblogicid").innerHTML = info.weblogiccontime;
                document.getElementById("diffshiroid").innerHTML = info.shirocontime;
                document.getElementById("diffspringbootid").innerHTML = info.springbootcontime;
                document.getElementById("diffthinkphpid").innerHTML = info.thinkphpcontime;
                document.getElementById("diffesid").innerHTML = info.esccontime;
                document.getElementById("diffnacosid").innerHTML = info.nacoscontime;
                document.getElementById("difftomcatid").innerHTML = info.tomcatcontime;
                document.getElementById("difffastjsonid").innerHTML = info.fastjsoncontime;
                document.getElementById("diffafrogid").innerHTML = info.afrogcontime;
                document.getElementById("difffscanid").innerHTML = info.fscancontime;
                document.getElementById("diffweakpassid").innerHTML = info.weakpasscontime;
                document.getElementById("diffapiscanid").innerHTML = info.apiintersacecontime;
                document.getElementById("diffvulmapid").innerHTML = info.vulmapcontime;
                document.getElementById("diffnucleiid").innerHTML = info.nucleicontime;
                document.getElementById("difffanweioaid").innerHTML = info.weavercontime;
                document.getElementById("diffhttpxscanid").innerHTML = info.httpxcontime;
                document.getElementById("diffxrayid").innerHTML = info.xraycontime;
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



// 关闭系统管理
function closeModal() {
    var modal = document.getElementById("modal");
    modal.style.display = "none";

}




// 查询fofa语法
function fofayufa() {
    var modal1 = document.getElementById("modal1");
    modal1.style.display = "block";

}

// 关闭查询语法
function closeModal1() {
    var modal1 = document.getElementById("modal1");
    modal1.style.display = "none";
}

// 关闭系统管理
function closesystemanager() {
    var modal = document.getElementById("modal");
    modal.style.display = "none";
}


// 打开扫描器配置页面
function startscanconfigpagefunc() {
    var modal2 = document.getElementById("modal2");
    modal2.style.display = "block";

}

function stopscanconfigpagefunc() {
    var modal2 = document.getElementById("modal2");
    modal2.style.display = "none";
}

// 弱口令扫描字典配置
function hydradictfunc() {
    var moda22 = document.getElementById("moda22");
    moda22.style.display = "block";

    // 打开口令配置文本框
    var divdictid1 = document.getElementById("divdictid1");
    divdictid1.style.display = "block";


    $.ajax({
        url: '/dict_mysql_edit/',
        method: 'GET',

        success: function (info) {
            // mysql相关
            // 账号展示
            // 假设info.textvalue是一个数组  
            var textAreaContent = ''; // 初始化一个空字符串来保存textarea的内容  

            // 遍历info.textvalue数组，为每个元素添加换行符并追加到textAreaContent  
            for (var i = 0; i < info.mysql_user_dict_list.length; i++) {
                textAreaContent += info.mysql_user_dict_list[i] + '\n'; // 追加元素和换行符  
            }

            // 将textAreaContent的内容赋值给textarea  
            $('#mysqltextarea1').val(textAreaContent); // 假设textarea的id是myTextarea  

            // 密码展示
            var textAreaContent1 = '';
            for (var i = 0; i < info.mysql_pass_dict_list.length; i++) {
                textAreaContent1 += info.mysql_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#mysqltextarea2').val(textAreaContent1);

            // ssh相关
            var textAreaContent2 = '';
            for (var i = 0; i < info.ssh_user_dict_list.length; i++) {
                textAreaContent2 += info.ssh_user_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#sshtextarea1').val(textAreaContent2);

            var textAreaContent3 = '';
            for (var i = 0; i < info.ssh_pass_dict_list.length; i++) {
                textAreaContent3 += info.ssh_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#sshtextarea2').val(textAreaContent3);

            // ftp相关
            var textAreaContent4 = '';
            for (var i = 0; i < info.ftp_user_dict_list.length; i++) {
                textAreaContent4 += info.ftp_user_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#ftptextarea1').val(textAreaContent4);

            var textAreaContent5 = '';
            for (var i = 0; i < info.ftp_pass_dict_list.length; i++) {
                textAreaContent5 += info.ftp_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#ftptextarea2').val(textAreaContent5);

            // redis相关
            var textAreaContent7 = '';
            for (var i = 0; i < info.redis_pass_dict_list.length; i++) {
                textAreaContent7 += info.redis_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#redistextarea2').val(textAreaContent7);

            // mssql相关
            var textAreaContent8 = '';
            for (var i = 0; i < info.mssql_user_dict_list.length; i++) {
                textAreaContent8 += info.mssql_user_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#mssqltextarea1').val(textAreaContent8);

            var textAreaContent9 = '';
            for (var i = 0; i < info.mssql_pass_dict_list.length; i++) {
                textAreaContent9 += info.mssql_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#mssqltextarea2').val(textAreaContent9);

            // tomcat相关
            var textAreaContent10 = '';
            for (var i = 0; i < info.tomcat_user_dict_list.length; i++) {
                textAreaContent10 += info.tomcat_user_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#tomcattextarea1').val(textAreaContent10);

            var textAreaContent11 = '';
            for (var i = 0; i < info.tomcat_pass_dict_list.length; i++) {
                textAreaContent11 += info.tomcat_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#tomcattextarea2').val(textAreaContent11);

            // nacos相关
            var textAreaContent11 = '';
            for (var i = 0; i < info.nacos_user_dict_list.length; i++) {
                textAreaContent11 += info.nacos_user_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#nacostextarea1').val(textAreaContent11);

            var textAreaContent12 = '';
            for (var i = 0; i < info.nacos_pass_dict_list.length; i++) {
                textAreaContent12 += info.nacos_pass_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#nacostextarea2').val(textAreaContent12);



        },
        error: function () {


        },
        complete: function () {

        }
    })


}
function closeModa22() {
    var moda22 = document.getElementById("moda22");
    moda22.style.display = "none";
    var divdictid1 = document.getElementById("divdictid1");
    divdictid1.style.display = "none";
}

// function openmysqldictfunc() {
//     var divdictid1 = document.getElementById("divdictid1");
//     divdictid1.style.display = "block";


// }




//nuclei查看poc yaml文件
function nuclei_poc_show_func() {
    var poc_dir = $('select[name="poc_dir"]').val();
    $.ajax({
        url: '/nuclei_poc_show/',
        method: 'POST',
        data: {
            poc_dir: poc_dir
        },
        success: function (info) {

            // 列表写入到textarea中
            // 假设info.textvalue是一个数组  
            var textAreaContent = ''; // 初始化一个空字符串来保存textarea的内容  

            // 遍历info.textvalue数组，为每个元素添加换行符并追加到textAreaContent  
            for (var i = 0; i < info.nuclei_poc_list_global.length; i++) {
                textAreaContent += info.nuclei_poc_list_global[i] + '\n'; // 追加元素和换行符  
            }

            // 将textAreaContent的内容赋值给textarea  
            $('#myTextarea3').val(textAreaContent); // 假设textarea的id是myTextarea  
            //  document.getElementById("textareaspan1").innerHTML = info.textarea_num;

            document.getElementById("nucleibyid2").innerHTML = info.nuclei_poc_list_len;

        },
        error: function () {

        },
        complete: function () {
        }
    })
}

// 资产管理展开
function assetmanagerzhankaifunc() {
    document.getElementById('assetid1').style.display = "block";
    document.getElementById('assetid3').style.display = "block";
    document.getElementById('assetid2').style.display = "none";
}


// 资产管理折叠
function assetmanagerzhediefunc() {
    document.getElementById('assetid1').style.display = "none";
    document.getElementById('assetid3').style.display = "none";
    document.getElementById('assetid2').style.display = "block";
}


// 漏洞管理展开
function vulnmanagerzhankaifunc() {
    document.getElementById('vulnid1').style.display = "block";
    document.getElementById('vulnid3').style.display = "block";
    document.getElementById('vulnid2').style.display = "none";
}


// 漏洞管理折叠
function vulnmanagerzhediefunc() {
    document.getElementById('vulnid1').style.display = "none";
    document.getElementById('vulnid3').style.display = "none";
    document.getElementById('vulnid2').style.display = "block";
}


//springboot报告预览
function springboot_report_show_func() {

    window.open("/springboot_report_show/");
}



//ajax异步关闭bbscan进程
function killbbscanfunc() {
    $.ajax({
        url: '/killbbscanprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_bbscan_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//通过fofa收集资产
function fofa_search_assets_func() {
    var part = document.getElementById("inputfofaid").value;
    var num_fofa = $('select[name="num_fofa"]').val();
    $.ajax({
        url: '/fofa_search_assets_service/',
        method: 'POST',
        data: {
            part: part,
            num_fofa: num_fofa
        },
        success: function (info) {
            // 当请求成功时调用  
            alert(info.asset_len_list);

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })

}


//hydra扫描报告预览
function hydra_report_show_func() {
    window.open("/hydra_report_show/", "_blank");
}




//总报告预览
function total_report_yulan_func() {
    window.open("/totalreportyulan/", "_blank");
}


// 登录接口
function login_interface_func() {
    var username = document.getElementById("user").value;
    var password = document.getElementById("pass").value;
    $.ajax({
        url: '/logininterface/',
        method: 'POST',
        data: {
            username: username,
            password: password
        },
        success: function (info) {
            if (confirm(info.loginstatus)) {
                window.location.href = info.redirect_url;
            } else {
                window.location.href = info.nologin;
            }
        },
        error: function () {
            alert('接口内部出错')
        },
        complete: function () {

        }
    })
}



// 重启服务接口
function restart_service_func() {

    $.ajax({
        url: '/restartsystemservice/',
        method: 'GET',

        success: function (info) {
            if (confirm(info.comfirm)) {
                info.infoscanstatus;
            }
        },
        // 重启服务中断会跳转到error处
        error: function (info) {
            alert("服务已重启相关配置已重新加载")
        },
        complete: function () {

        }
    })
}


// 弹出编辑筛选规则页面
function shuaixuanrule() {
    var idp1 = document.getElementById("idp1");
    idp1.style.display = "block";

}

// 隐藏编辑筛选规则页面
function fanhuishuaixuanrule() {
    var idp1 = document.getElementById("idp1");
    idp1.style.display = "none";

}


// 新增重点资产筛选规则
function add_rule_func() {
    var rule = document.getElementById("rule_input_id1").value;
    $.ajax({
        url: '/add_point_rule_interface/',
        method: 'POST',
        data: {
            rule: rule
        },
        success: function (info) {
            alert(info.result_rule)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })
}


// 通过规则名称删除重点资产筛选规则
function delete_rule_func() {
    var rule = document.getElementById("rule_input_id1").value;
    $.ajax({
        url: '/delete_point_rule_interface/',
        method: 'POST',
        data: {
            rule: rule,
            key: 1
        },
        success: function (info) {
            alert(info.delete_rule)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })
}


// 清空重点资产筛选规则表
function delete_rule_all_func() {
    var rule = document.getElementById("rule_input_id1").value;
    $.ajax({
        url: '/delete_point_rule_interface/',
        method: 'POST',
        data: {
            rule: rule,
            key: 2
        },
        success: function (info) {
            alert(info.delete_rule)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })
}




// 操作按钮提示语，延迟0.5秒显示和隐藏
function caozuo1func() {
    setTimeout(function () {
        var tishisp1 = document.getElementById("tishisp1");
        tishisp1.style.display = "block";
    }, 500);
}

function caozuo11func() {
    setTimeout(function () {
        var tishisp1 = document.getElementById("tishisp1");
        tishisp1.style.display = "none";
    }, 500);
}


function caozuo2func() {
    setTimeout(function () {
        var tishisp2 = document.getElementById("tishisp2");
        tishisp2.style.display = "block";
    }, 500);
}

function caozuo22func() {
    setTimeout(function () {
        var tishisp2 = document.getElementById("tishisp2");
        tishisp2.style.display = "none";
    }, 500);
}

function caozuo3func() {
    setTimeout(function () {
        var tishisp3 = document.getElementById("tishisp3");
        tishisp3.style.display = "block";
    }, 500);
}

function caozuo33func() {
    setTimeout(function () {
        var tishisp3 = document.getElementById("tishisp3");
        tishisp3.style.display = "none";
    }, 500);
}

function caozuo4func() {
    setTimeout(function () {
        var tishisp4 = document.getElementById("tishisp4");
        tishisp4.style.display = "block";
    }, 500);
}

function caozuo44func() {
    setTimeout(function () {
        var tishisp4 = document.getElementById("tishisp4");
        tishisp4.style.display = "none";
    }, 500);
}


function caozuo5func() {
    setTimeout(function () {
        var tishisp5 = document.getElementById("tishisp5");
        tishisp5.style.display = "block";
    }, 500);
}

function caozuo55func() {
    setTimeout(function () {
        var tishisp5 = document.getElementById("tishisp5");
        tishisp5.style.display = "none";
    }, 500);
}

function caozuo6func() {
    setTimeout(function () {
        var tishisp6 = document.getElementById("tishisp6");
        tishisp6.style.display = "block";
    }, 500);
}

function caozuo66func() {
    setTimeout(function () {
        var tishisp6 = document.getElementById("tishisp6");
        tishisp6.style.display = "none";
    }, 500);
}

function caozuo7func() {
    setTimeout(function () {
        var tishisp7 = document.getElementById("tishisp7");
        tishisp7.style.display = "block";
    }, 500);
}

function caozuo77func() {
    setTimeout(function () {
        var tishisp7 = document.getElementById("tishisp7");
        tishisp7.style.display = "none";
    }, 500);
}

function caozuo8func() {
    setTimeout(function () {
        var tishisp8 = document.getElementById("tishisp8");
        tishisp8.style.display = "block";
    }, 500);
}

function caozuo88func() {
    setTimeout(function () {
        var tishisp8 = document.getElementById("tishisp8");
        tishisp8.style.display = "none";
    }, 500);
}


function caozuo9func() {
    setTimeout(function () {
        var tishisp9 = document.getElementById("tishisp9");
        tishisp9.style.display = "block";
    }, 500);
}

function caozuo99func() {
    setTimeout(function () {
        var tishisp9 = document.getElementById("tishisp9");
        tishisp9.style.display = "none";
    }, 500);
}


function caozuo9afunc() {
    setTimeout(function () {
        var tishisp9a = document.getElementById("tishisp9a");
        tishisp9a.style.display = "block";
    }, 500);
}

function caozuo99afunc() {
    setTimeout(function () {
        var tishisp9a = document.getElementById("tishisp9a");
        tishisp9a.style.display = "none";
    }, 500);
}


function caozuo9bfunc() {
    setTimeout(function () {
        var tishisp9b = document.getElementById("tishisp9b");
        tishisp9b.style.display = "block";
    }, 500);
}

function caozuo99bfunc() {
    setTimeout(function () {
        var tishisp9b = document.getElementById("tishisp9b");
        tishisp9b.style.display = "none";
    }, 500);
}


function caozuo99cfunc() {
    setTimeout(function () {
        var tishisp9c = document.getElementById("tishisp9c");
        tishisp9c.style.display = "none";
    }, 500);
}

// 文本框重置
function textareachongzhifunc() {
    var myTextarea = document.getElementById("myTextarea");
    myTextarea.value = "";
}



//thinkphp报告预览
function thinkphp_report_show_func() {

    window.open("/thinkphp_poc_report/");
}



//weaver扫描结果预览
function weaverscanfunc() {

    window.open("/weaverresultshow/");
}



// 漏洞扫描集合选中扫描
function vulnxuanzhongscan() {

    const checkboxes = document.querySelectorAll('input[name="option"]:checked');
    const vuln_front_list = [];

    if (checkboxes.length === 0) {
        alert('请至少选择一个选项');
        return;
    }

    checkboxes.forEach((checkbox) => {
        vuln_front_list.push(checkbox.value);
    });
    // fscan前端需要传递到后端的参数
    var fscanpartname = $('select[name="fscanpartname"]').val();
    // hydra弱口令前端需要传递到后端的参数
    var hydrapart = $('select[name="hydrapart"]').val();
    // vulmap前端需要传递到后端的参数
    var vulnname = $('select[name="vulnname"]').val();
    // nuclei前端需要传递到后端的参数
    var poc_dir = $('select[name="poc_dir"]').val();
    $.ajax({
        url: '/vulnscan_check_back/',
        method: 'POST',
        // JSON格式数据传递给后端
        data: JSON.stringify({ vuln_front_list: vuln_front_list, fscanpartname: fscanpartname, hydrapart: hydrapart, vulnname: vulnname, poc_dir: poc_dir }),
        // 告诉服务器发送的数据是 JSON 格式
        contentType: 'application/json',
        // 期望服务器返回的数据类型
        dataType: 'json',
        success: function (info) {
            alert(info.struts2status_result + "\n" + info.weblogic_status_result + "\n" + info.shiro_status_result + "\n" + info.springboot_scan_status_result + "\n" + info.thinkphp_status_result + "\n" + info.start_afrog_result + "\n" + info.fscan_status_result + "\n" + info.hydra_scan_result + "\n" + info.urlfinder_status_result + "\n" + info.vummap_scan_result + "\n" + info.nuclei_status_result + "\n" + info.weaver_status_result + "\n" + info.point_all_result + "\n" + info.es_status_result + "\n" + info.nacos_status_result + "\n" + info.tomcat_status_result + "\n" + info.jndi_status_result + "\n" + info.fastjson_status_result + "\n" + info.xray_status_result+"\n"+info.seeyon_status_result+"\n"+info.yonsuite_status_result+"\n"+info.kingdee_status_result)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })

}



// 信息收集集合复选框选中开启扫描
function infoxuanzhongscan() {

    const checkboxes = document.querySelectorAll('input[name="info_option"]:checked');
    const info_front_list = [];

    if (checkboxes.length === 0) {
        alert('请至少选择一个选项');
        return;
    }

    checkboxes.forEach((checkbox) => {
        info_front_list.push(checkbox.value);
    });
    // 端口扫描传递给后端的参数：指定扫描端口
    var portscan_part = $('select[name="portscan_part"]').val();
    // 爬虫扫描传递给后端的参数
    var pachongselectpart = $('select[name="pachongselectpart"]').val();
    $.ajax({
        url: '/infoscan_check_back/',
        method: 'POST',
        data: JSON.stringify({ info_front_list: info_front_list, portscan_part: portscan_part, pachongselectpart: pachongselectpart }), // 发送 JSON 字符串
        contentType: 'application/json', // 告诉服务器发送的数据是 JSON 格式
        dataType: 'json', // 期望服务器返回的数据类型
        // data: JSON.stringify({ info_front_list: info_front_list }),
        success: function (info) {
            alert(info.dictkey1 + "\n" + info.dictkey2 + "\n" + info.dictkey3 + "\n" + info.dictkey4 + "\n" + info.dictkey5 + "\n" + info.dictkey6 + "\n" + info.dictkey7 + "\n" + info.dictkey8)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })

    // 定义一个函数来处理AJAX请求
    function fetchData() {

    }

}

// 确保在页面卸载或组件销毁时清除定时器，以防止内存泄漏
window.addEventListener("beforeunload", function () {
    clearInterval(intervalId);
});



// 信息收集集合复选框选中报告预览
function infoxuanzhongreportyulan() {

    const checkboxes = document.querySelectorAll('input[name="info_option"]:checked');
    const info_front_list = [];

    if (checkboxes.length === 0) {
        alert('请至少选择一个选项');
        return;
    }

    checkboxes.forEach((checkbox) => {
        info_front_list.push(checkbox.value);
    });

    // 遍历列表并判断然后跳转到对应的报告
    for (let i = 0; i < info_front_list.length; i++) {
        if (info_front_list[i] == '1') {
            window.open("/showbbscanreport/", "_blank");
        } else if (info_front_list[i] == '2') {
            window.open("/ehole_finger_report/", "_blank");
        } else if (info_front_list[i] == '3') {
            window.open("/previewhistoryurl/", "_blank");
        } else if (info_front_list[i] == '4') {
            window.open("/showsubdomainreport/", "_blank");
        } else if (info_front_list[i] == '5') {
            window.open("/nmapresultshow/", "_blank");
        } else if (info_front_list[i] == '6') {
            window.open("/waf_report_show/", "_blank");
        } else if (info_front_list[i] == '7') {
            window.open("/bypass_report_show/", "_blank");
        } else if (info_front_list[i] == '8') {
            window.open("/crawlergo_report_show/", "_blank");
        }
    }
}

// 信息收集集合复选框选中关闭扫描
function infoxuanzhongstopscanfunc() {
    const checkboxes = document.querySelectorAll('input[name="info_option"]:checked');
    const info_front_list = [];

    if (checkboxes.length === 0) {
        alert('请至少选择一个选项');
        return;
    }

    checkboxes.forEach((checkbox) => {
        info_front_list.push(checkbox.value);
    });

    $.ajax({
        url: '/stop_infoscan_back/',
        method: 'POST',
        data: JSON.stringify({ info_front_list: info_front_list }), // 发送 JSON 字符串
        contentType: 'application/json', // 告诉服务器发送的数据是 JSON 格式
        dataType: 'json', // 期望服务器返回的数据类型
        // data: JSON.stringify({ info_front_list: info_front_list }),
        success: function (info) {
            alert(info.dictkey11 + "\n" + info.dictkey21 + "\n" + info.dictkey31 + "\n" + info.dictkey41 + "\n" + info.dictkey51 + "\n" + info.dictkey61 + "\n" + info.dictkey71 + "\n" + info.dictkey81)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })
}


// 漏洞扫描集合复选框选中关闭扫描
function vulnxuanzhongstopscanfunc() {
    const checkboxes = document.querySelectorAll('input[name="option"]:checked');
    const vuln_front_list = [];

    if (checkboxes.length === 0) {
        alert('请至少选择一个选项');
        return;
    }

    checkboxes.forEach((checkbox) => {
        vuln_front_list.push(checkbox.value);
    });

    $.ajax({
        url: '/stop_vulnscan_back/',
        method: 'POST',
        // 发送 JSON 字符串
        data: JSON.stringify({ vuln_front_list: vuln_front_list }),
        // 告诉服务器发送的数据是 JSON 格式
        contentType: 'application/json',
        // 期望服务器返回的数据类型
        dataType: 'json',
        success: function (info) {
            alert(info.kill_struts2_result + "\n" + info.kill_weblogic_result + "\n" + info.kill_shiro_result + "\n" + info.kill_springboot_result + "\n" + info.kill_thinkphp_result + "\n" + info.kill_afrog_result + "\n" + info.kill_fscan_result + "\n" + info.kill_hydra_result + "\n" + info.kill_urlfinder_result + "\n" + info.kill_vulmap_result + "\n" + info.kill_nuclei_result + "\n" + info.kill_weaver_result + "\n" + info.kill_point_assset_result + "\n" + info.kill_es_result + "\n" + info.kill_nacos_result + "\n" + info.kill_tomcat_result + "\n" + info.kill_jndi_result + "\n" + info.kill_fastjson_result+"\n"+info.kill_seeyon_result+"\n"+info.kill_yonsuite_result+"\n"+info.kill_kingdee_result)
        },

        error: function (info) {
            alert("内部出错")
        },
        complete: function () {

        }
    })
}




// 信息收集复选框全选和取消
function selectAll() {
    // 获取所有具有相同名称的复选框
    var checkboxes = document.querySelectorAll('input[name="info_option"]');

    // 遍历所有复选框，并设置为选中状态
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = true;
    }
}

function unSelection() {
    // 获取所有具有相同名称的复选框
    var checkboxes = document.querySelectorAll('input[name="info_option"]');

    // 遍历所有复选框，并取反选中状态
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = !checkboxes[i].checked;
    }
}

// 漏洞扫描复选框全选和取消
function vulnselectAll() {
    // 获取所有具有相同名称的复选框
    var checkboxes = document.querySelectorAll('input[name="option"]');

    // 遍历所有复选框，并设置为选中状态
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = true;
    }
}

function vulnunSelection() {
    // 获取所有具有相同名称的复选框
    var checkboxes = document.querySelectorAll('input[name="option"]');

    // 遍历所有复选框，并取反选中状态
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = !checkboxes[i].checked;
    }
}


// 漏洞扫描集合复选框选中批量打开报告预览
function vulnscanxuanzhongreportyulan() {

    const checkboxes = document.querySelectorAll('input[name="option"]:checked');
    const vuln_front_list = [];

    if (checkboxes.length === 0) {
        alert('请至少选择一个选项');
        return;
    }

    checkboxes.forEach((checkbox) => {
        vuln_front_list.push(checkbox.value);
    });

    // 遍历列表并判断然后跳转到对应的报告
    for (let i = 0; i < vuln_front_list.length; i++) {
        if (vuln_front_list[i] == '1') {
            window.open("/struts2_poc_report/", "_blank");
        } else if (vuln_front_list[i] == '2') {
            window.open("/weblogic_poc_report/", "_blank");
        } else if (vuln_front_list[i] == '3') {
            window.open("/shiro_report_show/", "_blank");
        } else if (vuln_front_list[i] == '4') {
            window.open("/springboot_report_show/", "_blank");
        } else if (vuln_front_list[i] == '5') {
            window.open("/thinkphp_poc_report/", "_blank");
        } else if (vuln_front_list[i] == '6') {
            window.open(ipvalue + ":15555/", "_blank");
        } else if (vuln_front_list[i] == '7') {
            window.open("/fscanreportyulan/", "_blank");
        } else if (vuln_front_list[i] == '8') {
            window.open("/hydra_report_show/", "_blank");
        } else if (vuln_front_list[i] == '9') {
            window.open(ipvalue + ":16666/", "_blank");
        } else if (vuln_front_list[i] == 'a') {
            window.open("/vulmapscanreport/", "_blank");
        } else if (vuln_front_list[i] == 'b') {
            window.open("/nucleiresultshow/", "_blank");
        } else if (vuln_front_list[i] == 'c') {
            window.open("/weaverresultshow/", "_blank");
        } else if (vuln_front_list[i] == 'd') {
            window.open("/shiro_report_show/", "_blank");
            window.open("/springboot_report_show/", "_blank");
            window.open("/struts2_poc_report/", "_blank");
            window.open("/weblogic_poc_report/", "_blank");
        } else if (vuln_front_list[i] == 'e') {
            window.open("/es_unauthorized_report/", "_blank");
        } else if (vuln_front_list[i] == 'f') {
            window.open("/nacos_scan_report/", "_blank");
        } else if (vuln_front_list[i] == 'g') {
            window.open("/tomcat_scan_report/", "_blank");
        } else if (vuln_front_list[i] == 'h') {
            window.open("/jndi_report_show/", "_blank");
        } else if (vuln_front_list[i] == 'i') {
            window.open("/fastjson_report_show/", "_blank");
        } else if (vuln_front_list[i] == 'j') {
            window.open(ipvalue + ":18888/", "_blank");
        }else if (vuln_front_list[i] == 'k') {
            window.open("/seeyonreportyulan/", "_blank");
        }else if (vuln_front_list[i] == 'l') {
            window.open("/yonsuitereportyulan/", "_blank");
        }
        else if (vuln_front_list[i] == 'm') {
            window.open("/kingdeereportyulan/", "_blank");
        }

    }
}


// 端口扫描参数值查看
function nmapportshowfunc() {
    var portscan_part = $('select[name="portscan_part"]').val();
    $('#myTextarea1').val(portscan_part);
}


//资产项目管理
function assetmanagerfunc() {
    var assetmanagerid1 = $('select[name="assetmanagerid1"]').val();
    $.ajax({
        url: '/assetmanager_textarea_show/',
        method: 'POST',
        data: {
            assetmanagerid1: assetmanagerid1
        },
        success: function (info) {
            // 假设info.textvalue是一个数组  
            var textAreaContent = ''; // 初始化一个空字符串来保存textarea的内容  

            // 遍历info.textvalue数组，为每个元素添加换行符并追加到textAreaContent  
            for (var i = 0; i < info.url_list.length; i++) {
                textAreaContent += info.url_list[i] + '\n'; // 追加元素和换行符  
            }

            // 将textAreaContent的内容赋值给textarea  
            $('#myTextarea').val(textAreaContent); // 假设textarea的id是myTextarea  
            document.getElementById("textareaspan1").innerHTML = info.textarea_num;
        },
        error: function () {


        },
        complete: function () {

        }
    })
}


//清空fofa查询日志
function clearfofashowlogfunc() {
    $.ajax({
        url: '/clearshowfofalog/',
        method: 'GET',
        success: function (info) {
            alert(info.assets_file_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


// 弱口令扫描字典配置
function hydra_dict_submit_func() {
    // 获取textarea的值  
    const mysqltextarea1 = document.getElementById('mysqltextarea1').value;
    const mysqltextarea2 = document.getElementById('mysqltextarea2').value;
    const sshtextarea1 = document.getElementById('sshtextarea1').value;
    const sshtextarea2 = document.getElementById('sshtextarea2').value;
    const ftptextarea1 = document.getElementById('ftptextarea1').value;
    const ftptextarea2 = document.getElementById('ftptextarea2').value;
    const redistextarea2 = document.getElementById('redistextarea2').value;
    const mssqltextarea1 = document.getElementById('mssqltextarea1').value;
    const mssqltextarea2 = document.getElementById('mssqltextarea2').value;
    const tomcattextarea1 = document.getElementById('tomcattextarea1').value;
    const tomcattextarea2 = document.getElementById('tomcattextarea2').value;
    const nacostextarea1 = document.getElementById('nacostextarea1').value;
    const nacostextarea2 = document.getElementById('nacostextarea2').value;
    // 按换行符分割文本为数组  
    const line_mysqltextarea1 = mysqltextarea1.split('\n');
    const line_mysqltextarea2 = mysqltextarea2.split('\n');
    const line_sshtextarea1 = sshtextarea1.split('\n');
    const line_sshtextarea2 = sshtextarea2.split('\n');
    const line_ftptextarea1 = ftptextarea1.split('\n');
    const line_ftptextarea2 = ftptextarea2.split('\n');
    const line_redistextarea2 = redistextarea2.split('\n');
    const line_mssqltextarea1 = mssqltextarea1.split('\n');
    const line_mssqltextarea2 = mssqltextarea2.split('\n');
    const line_tomcattextarea1 = tomcattextarea1.split('\n');
    const line_tomcattextarea2 = tomcattextarea2.split('\n');
    const line_nacostextarea1 = nacostextarea1.split('\n');
    const line_nacostextarea2 = nacostextarea2.split('\n');
    // 使用jQuery的$.ajax方法发送POST请求到Flask后端  
    $.ajax({
        url: '/hydradictconfig/',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ line_mysqltextarea1: line_mysqltextarea1, line_mysqltextarea2: line_mysqltextarea2, line_sshtextarea1: line_sshtextarea1, line_sshtextarea2: line_sshtextarea2, line_ftptextarea1: line_ftptextarea1, line_ftptextarea2: line_ftptextarea2, line_redistextarea2: line_redistextarea2, line_mssqltextarea1: line_mssqltextarea1, line_mssqltextarea2: line_mssqltextarea2, line_tomcattextarea1: line_tomcattextarea1, line_tomcattextarea2: line_tomcattextarea2, line_nacostextarea1: line_nacostextarea1, line_nacostextarea2: line_nacostextarea2 }),
        dataType: 'json',
        success: function (info) {
            alert(info.mysql_dict_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    });
}


// fscan参数配置鼠标悬停变大
function fscantextarea_onhover() {
    var myTextarea2 = document.getElementById('myTextarea2');
    myTextarea2.rows = 15;
    myTextarea2.cols = 80;
}

// fscan参数配置鼠标移出变小
function fscantextarea_onout() {
    var myTextarea2 = document.getElementById('myTextarea2');
    myTextarea2.rows = 3;
    myTextarea2.cols = 80;
}


// nuclei参数配置鼠标悬停变大
function nucleitextarea_onhover() {
    var myTextarea3 = document.getElementById('myTextarea3');
    myTextarea3.rows = 15;
    myTextarea3.cols = 80;


}

// nuclei参数配置鼠标移出变小
function nucleitextarea_onout() {
    var myTextarea3 = document.getElementById('myTextarea3');
    myTextarea3.rows = 3;
    myTextarea3.cols = 80;
}

// 端口扫描参数配置鼠标悬停变大
function nmaptextarea_onhover() {
    var myTextarea1 = document.getElementById('myTextarea1');
    myTextarea1.rows = 15;
    myTextarea1.cols = 80;
}

// 端口扫描参数配置鼠标移出变小
function nmaptextarea_onout() {
    var myTextarea1 = document.getElementById('myTextarea1');
    myTextarea1.rows = 3;
    myTextarea1.cols = 80;
}


// 爬虫扫描参数详情
function crawlergo_part_show() {
    var pachongselectpart = $('select[name="pachongselectpart"]').val();
    if (pachongselectpart == 1) {
        document.getElementById("crawlergo_part_show_part2").innerHTML = "";
        document.getElementById("crawlergo_part_show_part1").innerHTML = "爬虫流量不转发给被动流量扫描器";
    } else if (pachongselectpart == 2) {
        document.getElementById("crawlergo_part_show_part1").innerHTML = "";
        document.getElementById("crawlergo_part_show_part2").innerHTML = "爬虫流量已转发给xray,扫描前需先开启xray被动监听";
    }
}



// 打开删除报告二次验证弹窗
function startverifychearlogfunc(dataToSet) {
    var modal3 = document.getElementById("modal3");
    modal3.style.display = "block";
    var inputmodel1 = document.getElementById("inputmodel1");
    inputmodel1.value = "";
    var inputmodel2 = document.getElementById("inputmodel2");
    inputmodel2.value = "";
    var inputmodel3 = document.getElementById("inputmodel3");
    inputmodel3.value = "";
    // 获取input元素
    var inputmodel3 = document.getElementById('inputmodel3');
    // 为input元素赋值
    inputmodel3.value = dataToSet;
}


// 关闭删除报告二次验证弹窗
function stopverifychearlogfunc() {
    var modal3 = document.getElementById("modal3");
    modal3.style.display = "none";
}

// 确认删除报告
function comfirmclearlogfunc() {
    var inputmodel1 = document.getElementById('inputmodel1').value;
    var inputmodel2 = document.getElementById('inputmodel2').value;
    var inputmodel3 = document.getElementById('inputmodel3').value;
    $.ajax({
        url: '/comfirmclearloginterface/',
        method: 'POST',
        data: {
            inputmodel1: inputmodel1,
            inputmodel2: inputmodel2,
            inputmodel3: inputmodel3
        },
        success: function (info) {
            alert(info.recheck_result)
        },
        error: function () {

        },
        complete: function () {

        }
    })
    var modal3 = document.getElementById("modal3");
    modal3.style.display = "none";
}

// 计算扫描器运行时间,网页加载会自动加载
window.onload = function () {
    // alert("11")
};

// 打开关键字检索文本框
function asssets_jiansuo() {
    var divjiansuo1 = document.getElementById("divjiansuo1");
    divjiansuo1.style.display = "block";




}

function stop_asssets_jiansuo() {
    var divjiansuo1 = document.getElementById("divjiansuo1");
    divjiansuo1.style.display = "none";

}

// 通过关键字检索资产
function assets_key_jiansuo() {
    var myinputid = document.getElementById("my-input-id").value;
    $.ajax({
        url: '/searchassetsbykey/',
        method: 'POST',
        data: {
            myinputid: myinputid
        },
        success: function (info) {
            // 当请求成功时调用  
            alert(info.search_result);
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


// 通过关键字检索资产
function excude_assets_key_jiansuo() {
    var myinputid = document.getElementById("my-input-id").value;
    $.ajax({
        url: '/excludesearchassetsbykey/',
        method: 'POST',
        data: {
            myinputid: myinputid
        },
        success: function (info) {
            // 当请求成功时调用  
            alert(info.search_result);
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//资产下载
function assetdownloadfunc() {
    window.open("/assetsdownload/", "_blank");
}
