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
    var myModa6 = document.getElementById("myModa6");
    myModa6.style.display = "block";
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
            document.getElementById('vulnscan5').innerHTML = info.file_line;
        },
        error: function () {
            document.getElementById('vulnscan5').innerHTML = "内部错误"
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
    var button20 = document.getElementById("button20");
    button20.disabled = false;
    var button24 = document.getElementById("button24");
    button24.disabled = false;
    var button25 = document.getElementById("button25");
    button25.disabled = false;
    var button26 = document.getElementById("button26");
    button26.disabled = false;
    var button27 = document.getElementById("button27");
    button27.disabled = false;
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
    var button20 = document.getElementById("button20");
    button20.disabled = true;
    var button24 = document.getElementById("button24");
    button24.disabled = true;
    var button25 = document.getElementById("button25");
    button25.disabled = true;
    var button26 = document.getElementById("button26");
    button26.disabled = true;
    var button27 = document.getElementById("button27");
    button27.disabled = true;
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



//存活检测
function filterstatuscodefunc() {
    $.ajax({
        url: '/filterstatuscodebyhttpx/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan7').innerHTML = info.httpx_status_result;
        },
        error: function () {

            document.getElementById('vulnscan7').innerHTML = "内部错误"
        },
        complete: function () {

        }
    })
}

// 关闭存活检测
function stopfilterstatuscodefunc() {
    $.ajax({
        url: '/stopfilterstatuscodebyhttpx/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan7').innerHTML = info.stop_httpx_status_result;
        },
        error: function () {
            document.getElementById('vulnscan7').innerHTML = "内部错误"
        },
        complete: function () {

        }
    })
}

// 关闭资产扩展
function stopassetextendfunc() {
    $.ajax({
        url: '/stopassetextendinterface/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan9').innerHTML = info.stop_extend_status_result;
        },
        error: function () {
            document.getElementById('vulnscan9').innerHTML = "内部错误"
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


//开启CDN检测
function filtercdndatafunc() {
    $.ajax({
        url: '/cdn_service_recogize/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan8').innerHTML = info.cdn_status_result;

        },
        error: function () {
            document.getElementById('vulnscan8').innerHTML = "内部错误";
        },
        complete: function () {

        }
    })
}


// 关闭CDN检测
function stopcdndetectionfunc() {
    $.ajax({
        url: '/stopcdndetection/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan8').innerHTML = info.stop_cdn_status_result;
        },
        error: function () {
            document.getElementById('vulnscan8').innerHTML = "内部错误"
        },
        complete: function () {

        }
    })
}



//资产回退
function assetsbackspacefunc() {
    var myModa12 = document.getElementById("myModa12");
    myModa12.style.display = "block";
    $.ajax({
        url: '/assetsbackspaceinterface/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan12').innerHTML = info.returnresult;
        },
        error: function () {
            document.getElementById('vulnscan12').innerHTML = "内部错误"
        },
        complete: function () {

        }
    })
}

// 关闭资产回退弹窗
function closevulnscan11() {
    var myModa12 = document.getElementById("myModa12");
    myModa12.style.display = "none";

}

// 关闭系统提示窗口
function closesystemshow() {
    var systemshowid1 = document.getElementById("systemshowid1");
    systemshowid1.style.display = "none";
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
            document.getElementById('vulnscan13').innerHTML = info.total_result;
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
    var myModa11 = document.getElementById("myModa11");
    myModa11.style.display = "block";
    $.ajax({
        url: '/key_assets_withdraw/',
        method: 'GET',

        success: function (info) {
            document.getElementById('vulnscan11').innerHTML = info.key_assets_result;
        },
        error: function () {
            document.getElementById('vulnscan11').innerHTML = "内部出错"
        },
        complete: function () {

        }
    })
}

// 关闭识别重点资产弹窗
function closevulnscan10() {
    var myModa11 = document.getElementById("myModa11");
    myModa11.style.display = "none";

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

// DNS日志查询
function dnslogfunc() {
    var modal4 = document.getElementById("modal4");
    modal4.style.display = "block";
    // 清空表格体中的所有行
    const tableBody = document.querySelector('#data-table tbody');
    tableBody.innerHTML = '';

    $.ajax({
        url: '/ceye_dns_record/',
        method: 'GET',
        success: function (info) {
            const tableBody = document.querySelector('#data-table tbody');
            document.getElementById('dnslogkeyid').value = info.dnslog_key;
            document.getElementById("dnslogkeyid6").innerHTML = info.dnslog_key;
            document.getElementById("dnslogkeyid7").innerHTML = info.dnslog_key;
            document.getElementById("dnslogkeyid8").innerHTML = info.dnslog_key;
            info.resultdict.forEach(item => {
                const row = document.createElement('tr'); // 创建新的行

                // 创建单元格并填充数据
                const idCell = document.createElement('td');
                idCell.textContent = item.id;
                row.appendChild(idCell);

                const nameCell = document.createElement('td');
                nameCell.textContent = item.name;
                row.appendChild(nameCell);

                const addrCell = document.createElement('td');
                addrCell.textContent = item.remote_addr;
                row.appendChild(addrCell);

                const dateCell = document.createElement('td');
                dateCell.textContent = item.created_at;
                row.appendChild(dateCell);

                tableBody.appendChild(row); // 将行添加到表格体中
            });

        },
        error: function () {


        },
        complete: function () {

        }
    })

}

// 关闭dns日志
function closeModal4() {
    var modal4 = document.getElementById("modal4");
    modal4.style.display = "none";
    var dnslogkeyid3 = document.getElementById("dnslogkeyid3");
    dnslogkeyid3.style.display = "none";
    var dnslogkeyid4 = document.getElementById("dnslogkeyid4");
    dnslogkeyid4.style.display = "none";
    document.getElementById("dnslogkeyid2").innerHTML = "";
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

    // 获取input元素
    var sessionid1 = document.getElementById('sessionid1');
    var sessionid2 = document.getElementById('sessionid2');
    var sessionid3 = document.getElementById('sessionid3');
    var sessionid4 = document.getElementById('sessionid4');
    var sessionid5 = document.getElementById('sessionid5');
    var sessionid6 = document.getElementById('sessionid6');

    $.ajax({
        url: '/system_config_data/',
        method: 'GET',
        success: function (info) {
            // 为input元素赋值
            sessionid1.value = info.search_result;
            sessionid2.value = info.fofa_email;
            sessionid3.value = info.fofa_key;
            sessionid4.value = info.shodan_key;
            sessionid5.value = info.amap_key;
            sessionid6.value = info.ceye_key;

            // 自定义额度查询
            document.getElementById("customizelimitid1").value = info.fofa_remaining_num;
            document.getElementById("customizelimitid2").value = info.shodan_remaining_num;
            document.getElementById("customizelimitid3").value = info.crt_remaining_num;
            document.getElementById("customizelimitid4").value = info.icp_remaining_num;
            document.getElementById("customizelimitid5").value = info.amap_remaining_num;
            document.getElementById("customizelimitid6").value = info.otx_remaining_num;

            // jndi服务状态
            const statusElement = document.getElementById('jndistatusid1');
            const status = info.jndistatus;

            // 清除所有可能的状态类
            statusElement.className = 'status-circle';

            // 根据状态添加对应样式
            if (status === '开启') {
                statusElement.classList.add('status-running');
            } else if (status === '关闭') {
                statusElement.classList.add('status-stopped');
            } else {
                statusElement.classList.add('status-error');
            }

            // 资产校验开关状态
            const statusElement1 = document.getElementById('assetsjiaoyanstatusid1');
            const status1 = info.assets_jiaoyan_status;

            // 根据状态添加对应样式
            if (status1 === '已开启校验') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启校验') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }

        },
        error: function () {
            const statusElement = document.getElementById('jndistatusid1');
            statusElement.className = 'status-circle status-error';
        }
    })

}

function stopscanconfigpagefunc() {
    var modal2 = document.getElementById("modal2");
    modal2.style.display = "none";
    document.getElementById("filterruleid1").innerHTML = "";
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

            // bcrypt相关
            var textAreaContent13 = '';
            for (var i = 0; i < info.bcrypt_dict_list.length; i++) {
                textAreaContent13 += info.bcrypt_dict_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#bcrypttextarea1').val(textAreaContent13);

            var textAreaContent14 = '';
            for (var i = 0; i < info.bcrypt_passwd_list.length; i++) {
                textAreaContent14 += info.bcrypt_passwd_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#bcrypttextarea2').val(textAreaContent14);

            // JWT相关
            var textAreaContent15 = '';
            for (var i = 0; i < info.jwt_pass_list.length; i++) {
                textAreaContent15 += info.jwt_pass_list[i] + '\n'; // 追加元素和换行符  

            }
            $('#jwttextarea1').val(textAreaContent15);


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
            document.getElementById("routestatus3").innerHTML = info.asset_len_list;

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }

    })



    // 路由状态查询
    function routestatus() {
        $.getJSON("/inter_route_status/",
            function (info) {
                document.getElementById("routestatus1").innerHTML = info.fofa_status1;
                document.getElementById("routestatus2").innerHTML = info.fofa_status2;

            });
    }
    // 调用routestatus函数初始化显示
    routestatus();

    // 设置定时器，每5000毫秒（5秒）执行一次fetchData函数
    var intervalId = setInterval(routestatus, 1000);

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



// 初始状态
function yincangtishifun() {
    var routestatus1 = document.getElementById("routestatus1");
    routestatus1.style.display = "none";
    var routestatus2 = document.getElementById("routestatus2");
    routestatus2.style.display = "none";
    var routestatus3 = document.getElementById("routestatus3");
    routestatus3.style.display = "none";

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
            document.getElementById("filterruleid1").innerHTML = info.delete_rule;
        },

        error: function (info) {
            // alert("内部出错")
            document.getElementById("filterruleid1").innerHTML = "内部出错";
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

    var myModal = document.getElementById("myModal");
    myModal.style.display = "block";

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
    var fscanpartname1 = $('select[name="fscanpartname1"]').val();
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
        data: JSON.stringify({ vuln_front_list: vuln_front_list, fscanpartname: fscanpartname, fscanpartname1: fscanpartname1, hydrapart: hydrapart, vulnname: vulnname, poc_dir: poc_dir }),
        // 告诉服务器发送的数据是 JSON 格式
        contentType: 'application/json',
        // 期望服务器返回的数据类型
        dataType: 'json',
        success: function (info) {

            var message = info.struts2status_result + "struts2_" + info.struts2status + "\n" + info.weblogic_status_result + "weblogic_" + info.weblogicstatus + "\n" + info.shiro_status_result + "shiro_" + info.shirostatus + "\n" + info.springboot_scan_status_result + "springboot_" + info.springbootstatus + "\n" + info.thinkphp_status_result + "thinkphp_" + info.thinkphpstatus + "\n" + info.start_afrog_result + "afrog_" + info.afrogscanstatus +
                "\n" + info.fscan_status_result + "fscan_" + info.fscanstatus + "\n" + info.hydra_scan_result + "hydra_" + info.hydrastatus + "\n" + info.urlfinder_status_result + "urlfinder_" + info.urlfinderstatus + "\n" + info.vummap_scan_result + "vulmap_" + info.vulmapscanstatus + "\n" + info.nuclei_status_result + "nuclei_" + info.nucleistatus + "\n" + info.weaver_status_result + "weaver_" + info.weaver_status + "\n" + info.es_status_result + "esall_" + info.es_status +
                "\n" + info.nacos_status_result + "nacos_" + info.nacos_status + "\n" + info.tomcat_status_result + "tomcat_" + info.tomcat_status + "\n" + info.jndi_status_result + "jndi_" + info.jndi_status + "\n" + info.fastjson_status_result + "fastjson_" + info.fastjson_status + "\n" + info.xray_status_result + "xray_" + info.xray_status + "\n" + info.seeyon_status_result + "seeyon_" + info.seeyonstatus + "\n" + info.yonsuite_status_result + "yonsuite_" + info.yonsuite_status +
                "\n" + info.kingdee_status_result + "kingdee_" + info.kingdee_status + "\n" + info.wanhu_status_result + "wanhu_" + info.wanhu_status + "\n" + info.redis_status_result + "redis_" + info.redis_status + "\n" + info.mongodb_status_result + "mongodb_" + info.mongodb_status + "\n" + info.memcached_status_result + "memcached_" + info.memcached_status + "\n" + info.zookeeper_status_result + "zookeeper_" + info.zookeeper_status + "\n" + info.ftp_status_result + "ftp_" + info.ftp_status +
                "\n" + info.couchdb_status_result + "couchdb_" + info.couchdb_status + "\n" + info.docker_status_result + "docker_" + info.docker_status + "\n" + info.hadoop_status_result + "hadoop_" + info.hadoop_status + "\n" + info.nfs_status_result + "nfs_" + info.nfs_status + "\n" + info.rsync_status_result + "rsync_" + info.rsync_status + "\n" + info.unes_status_result + "unes_" + info.unes1_status + "\n" + info.bcrypt_status_result + "bcrypt_" + info.bcrypt_status;

            document.getElementById('vulnscan1').innerText = message;

        },

        error: function () {
            document.getElementById('vulnscan1').innerText = "内部错误";
        },
        complete: function () {

        }
    })

}


// 关闭漏洞扫描弹窗
function closevulnscan() {
    var myModal = document.getElementById("myModal");
    myModal.style.display = "none";

}

function closevulnscan1() {
    var myModa2 = document.getElementById("myModa2");
    myModa2.style.display = "none";

}

// 关闭信息收集弹窗
function closevulnscan2() {
    var myModa3 = document.getElementById("myModa3");
    myModa3.style.display = "none";

}
function closevulnscan3() {
    var myModa4 = document.getElementById("myModa4");
    myModa4.style.display = "none";

}

function closevulnscan4() {
    var myModa5 = document.getElementById("myModa5");
    myModa5.style.display = "none";

}

function closevulnscan5() {
    var myModa6 = document.getElementById("myModa6");
    myModa6.style.display = "none";

}



// 信息收集集合复选框选中开启扫描
function infoxuanzhongscan() {

    const checkboxes = document.querySelectorAll('input[name="info_option"]:checked');
    const info_front_list = [];

    var myModa3 = document.getElementById("myModa3");
    myModa3.style.display = "block";
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

        success: function (info) {

            var message2 = info.dictkey1 + "bbscan_" + info.dictkey10 + "\n" + info.dictkey2 + "ehole_" + info.dictkey9 +
                "\n" + info.dictkey3 + "otx_" + info.dictkey11 + "\n" + info.dictkey4 + "crt_" + info.dictkey12 + "\n" + info.dictkey5 + "nmap_" + info.dictkey13 +
                "\n" + info.dictkey6 + "waf_" + info.dictkey14 + "\n" + info.dictkey7 + "fuzz_" + info.dictkey15 + "\n" + info.dictkey8 + "crawlergo_" + info.dictkey16;
            document.getElementById('vulnscan3').innerText = message2;
        },

        error: function () {
            document.getElementById('vulnscan3').innerText = "内部错误";
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
    var myModa4 = document.getElementById("myModa4");
    myModa4.style.display = "block";
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
        success: function (info) {
            // alert(info.dictkey11 + "\n" + info.dictkey21 + "\n" + info.dictkey31 + "\n" + info.dictkey41 + "\n" + info.dictkey51 + "\n" + info.dictkey61 + "\n" + info.dictkey71 + "\n" + info.dictkey81)
            var message3 = info.dictkey11 + "\n" + info.dictkey21 + "\n" + info.dictkey31 + "\n" + info.dictkey41 + "\n" + info.dictkey51 + "\n" + info.dictkey61 + "\n" + info.dictkey71 + "\n" + info.dictkey81;
            document.getElementById('vulnscan4').innerText = message3;
        },

        error: function () {
            document.getElementById('vulnscan4').innerText = "内部错误";
        },
        complete: function () {

        }
    })
}


// 漏洞扫描集合复选框选中关闭扫描
function vulnxuanzhongstopscanfunc() {
    const checkboxes = document.querySelectorAll('input[name="option"]:checked');
    const vuln_front_list = [];

    var myModa2 = document.getElementById("myModa2");
    myModa2.style.display = "block";
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

            var message1 = info.kill_struts2_result + "\n" + info.kill_weblogic_result + "\n" + info.kill_shiro_result +
                "\n" + info.kill_springboot_result + "\n" + info.kill_thinkphp_result +
                "\n" + info.kill_afrog_result + "\n" + info.kill_fscan_result + "\n" + info.kill_hydra_result +
                "\n" + info.kill_urlfinder_result + "\n" + info.kill_vulmap_result + "\n" + info.kill_nuclei_result +
                "\n" + info.kill_weaver_result + "\n" + info.kill_es_result +
                "\n" + info.kill_nacos_result + "\n" + info.kill_tomcat_result + "\n" + info.kill_jndi_result +
                "\n" + info.kill_fastjson_result + "\n" + info.kill_seeyon_result + "\n" + info.kill_yonsuite_result +
                "\n" + info.kill_kingdee_result + "\n" + info.kill_wanhu_result + "\n" + info.kill_redis_result + "\n" + info.kill_mongodb_result +
                "\n" + info.kill_memcached_result + "\n" + info.kill_zookeeper_result + "\n" + info.kill_ftp_result +
                "\n" + info.kill_couchdb_result + "\n" + info.kill_docker_result + "\n" + info.kill_hadoop_result +
                "\n" + info.kill_nfs_result + "\n" + info.kill_rsync_result + "\n" + info.kill_es1_result + "\n" + info.kill_bcrypt_result;

            document.getElementById('vulnscan2').innerText = message1;
        },


        error: function () {
            document.getElementById('vulnscan2').innerText = "内部错误";
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
        } else if (vuln_front_list[i] == 'k') {
            window.open("/seeyonreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'l') {
            window.open("/yonsuitereportyulan/", "_blank");
        }
        else if (vuln_front_list[i] == 'm') {
            window.open("/kingdeereportyulan/", "_blank");
        }
        else if (vuln_front_list[i] == 'n') {
            window.open("/wanhureportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'o') {
            window.open("/unredisreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'p') {
            window.open("/unmongodbreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'q') {
            window.open("/unmemcachedreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'r') {
            window.open("/unzookeeperreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 's') {
            window.open("/unftpreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 't') {
            window.open("/uncouchdbreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'u') {
            window.open("/undockerreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'v') {
            window.open("/unhadoopreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'w') {
            window.open("/unnfsreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'x') {
            window.open("/unrsyncreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'y') {
            window.open("/unelasticsearchreportyulan/", "_blank");
        } else if (vuln_front_list[i] == 'z') {
            window.open("/decryptreportyulan/", "_blank");
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
    const bcrypttextarea1 = document.getElementById('bcrypttextarea1').value;
    const bcrypttextarea2 = document.getElementById('bcrypttextarea2').value;
    const jwttextarea1 = document.getElementById('jwttextarea1').value;

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
    const line_bcrypttextarea1 = bcrypttextarea1.split('\n');
    const line_bcrypttextarea2 = bcrypttextarea2.split('\n');
    const line_jwttextarea1 = jwttextarea1.split('\n');

    // 使用jQuery的$.ajax方法发送POST请求到Flask后端  
    $.ajax({
        url: '/hydradictconfig/',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ line_mysqltextarea1: line_mysqltextarea1, line_mysqltextarea2: line_mysqltextarea2, 
            line_sshtextarea1: line_sshtextarea1, line_sshtextarea2: line_sshtextarea2, line_ftptextarea1: line_ftptextarea1, 
            line_ftptextarea2: line_ftptextarea2, line_redistextarea2: line_redistextarea2, line_mssqltextarea1: line_mssqltextarea1, 
            line_mssqltextarea2: line_mssqltextarea2, line_tomcattextarea1: line_tomcattextarea1, line_tomcattextarea2: line_tomcattextarea2, 
            line_nacostextarea1: line_nacostextarea1, line_nacostextarea2: line_nacostextarea2, line_bcrypttextarea1: line_bcrypttextarea1,
            line_bcrypttextarea2: line_bcrypttextarea2, line_jwttextarea1:line_jwttextarea1}),
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
    // 返回结果滞空
    document.getElementById("filterruleid1").innerHTML = "";

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

// 复核
function comfirmclearlogfunc() {
    var inputmodel1 = document.getElementById('inputmodel1').value;
    var inputmodel2 = document.getElementById('inputmodel2').value;
    var inputmodel3 = document.getElementById('inputmodel3').value;
    var sessionid1 = document.getElementById('sessionid1').value;
    var sessionid2 = document.getElementById('sessionid2').value;
    var sessionid3 = document.getElementById('sessionid3').value;
    var sessionid4 = document.getElementById('sessionid4').value;
    var sessionid5 = document.getElementById('sessionid5').value;
    var sessionid6 = document.getElementById('sessionid6').value;
    var rule_input_id1 = document.getElementById('rule_input_id1').value;
    // 获取自定义接口额度文本框数据
    var customizelimitid1 = document.getElementById('customizelimitid1').value;
    var customizelimitid2 = document.getElementById('customizelimitid2').value;
    var customizelimitid3 = document.getElementById('customizelimitid3').value;
    var customizelimitid4 = document.getElementById('customizelimitid4').value;
    var customizelimitid5 = document.getElementById('customizelimitid5').value;
    var customizelimitid6 = document.getElementById('customizelimitid6').value;

    $.ajax({
        url: '/comfirmclearloginterface/',
        method: 'POST',
        data: {
            inputmodel1: inputmodel1,
            inputmodel2: inputmodel2,
            inputmodel3: inputmodel3,
            sessionid1: sessionid1,
            sessionid2: sessionid2,
            sessionid3: sessionid3,
            sessionid4: sessionid4,
            sessionid5: sessionid5,
            sessionid6: sessionid6,
            rule_input_id1: rule_input_id1,
            customizelimitid1: customizelimitid1,
            customizelimitid2: customizelimitid2,
            customizelimitid3: customizelimitid3,
            customizelimitid4: customizelimitid4,
            customizelimitid5: customizelimitid5,
            customizelimitid6: customizelimitid6
        },
        success: function (info) {
            document.getElementById("filterruleid1").innerHTML = info.recheck_result;
        },
        error: function (info) {
            document.getElementById("filterruleid1").innerHTML = "内部错误";
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
    var myModa5 = document.getElementById("myModa5");
    myModa5.style.display = "block";


}

// 打开资产存活检测弹窗
function openassetalive() {
    var myModa7 = document.getElementById("myModa7");
    myModa7.style.display = "block";
}

// 关闭存活检测弹窗
function closevulnscan6() {
    var myModa7 = document.getElementById("myModa7");
    myModa7.style.display = "none";

}

// 打开CDN检测弹窗
function opencdnjiancefunc() {
    var myModa8 = document.getElementById("myModa8");
    myModa8.style.display = "block";
}

function closevulnscan7() {
    var myModa8 = document.getElementById("myModa8");
    myModa8.style.display = "none";

}

// 打开资产扩展弹窗
function openassetjiancefunc() {
    var myModa9 = document.getElementById("myModa9");
    myModa9.style.display = "block";
}
function closevulnscan8() {
    var myModa9 = document.getElementById("myModa9");
    myModa9.style.display = "none";

}

// 打开报告管理
function reportmanagerfunc() {
    var myModa13 = document.getElementById("myModa13");
    myModa13.style.display = "block";
}
function closevulnscan12() {
    var myModa13 = document.getElementById("myModa13");
    myModa13.style.display = "none";

}


// 打开资产收集弹窗
function openassetcollectfunc() {
    var myModa10 = document.getElementById("myModa10");
    myModa10.style.display = "block";
}
function closevulnscan9() {
    var myModa10 = document.getElementById("myModa10");
    myModa10.style.display = "none";
    document.getElementById("routestatus1").innerHTML = "";
    document.getElementById("routestatus2").innerHTML = "";

}

// 通过关键字检索资产
function assets_key_jiansuo() {
    document.getElementById('assetfilterid2').innerHTML = "";
    document.getElementById('assetfilterid3').innerHTML = "";
    var myinputid = document.getElementById("my-input-id").value;
    $.ajax({
        url: '/searchassetsbykey/',
        method: 'POST',
        data: {
            myinputid: myinputid
        },
        success: function (info) {
            document.getElementById('assetfilterid1').innerHTML = info.search_result;

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


// 通过关键字过滤资产
function excude_assets_key_jiansuo() {
    document.getElementById('assetfilterid2').innerHTML = "";
    document.getElementById('assetfilterid3').innerHTML = "";
    var myinputid = document.getElementById("my-input-id").value;
    $.ajax({
        url: '/excludesearchassetsbykey/',
        method: 'POST',
        data: {
            myinputid: myinputid
        },
        success: function (info) {
            // 当请求成功时调用
            document.getElementById('assetfilterid1').innerHTML = info.search_result;

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

// 过滤内网IP
function filterprivateipfunc() {
    document.getElementById('assetfilterid1').innerHTML = ""
    $.ajax({
        url: '/filterprivateip/',
        method: 'GET',
        success: function (info) {
            // 当请求成功时调用
            document.getElementById('assetfilterid2').innerHTML = info.filterstatus;
            document.getElementById('assetfilterid3').innerHTML = info.peivatenum;
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


// 提取URL地址
function withdrawurllocationfunc() {
    document.getElementById('assetfilterid1').innerHTML = ""
    document.getElementById('assetfilterid3').innerHTML = "";
    $.ajax({
        url: '/withdrawurllocation/',
        method: 'GET',
        success: function (info) {
            // 当请求成功时调用
            document.getElementById('assetfilterid2').innerHTML = info.filterurlresult;
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

// 资产去重
function assetslocationuniqfunc() {
    document.getElementById('assetfilterid1').innerHTML = ""
    document.getElementById('assetfilterid3').innerHTML = "";
    $.ajax({
        url: '/assetslocationuniq/',
        method: 'GET',
        success: function (info) {
            // 当请求成功时调用
            document.getElementById('assetfilterid2').innerHTML = info.uniqfilterurlresult;
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

// 提取IP地址
function withdrawiplocationfunc() {
    document.getElementById('assetfilterid1').innerHTML = ""
    document.getElementById('assetfilterid3').innerHTML = "";
    $.ajax({
        url: '/withdrawiplocation/',
        method: 'GET',
        success: function (info) {
            // 当请求成功时调用
            document.getElementById('assetfilterid2').innerHTML = info.withdrawipresult;
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


//资产扩展程序
function assets_extend_func() {
    $.ajax({
        url: '/assets_extend/',
        method: 'GET',
        success: function (info) {
            document.getElementById('vulnscan9').innerHTML = info.assets_extend_status;
        },
        error: function () {
            document.getElementById('vulnscan9').innerHTML = "内部错误"
        },
        complete: function () {

        }
    })
}


// 图标hash计算
function fofahashfunc() {
    var hashurl = document.getElementById("hashurl").value;
    $.ajax({
        url: '/fofa_icon_hash/',
        method: 'POST',
        data: {
            hashurl: hashurl
        },
        success: function (info) {
            // 当请求成功时调用  
            var inputfofaid = document.getElementById('inputfofaid');
            inputfofaid.value = info.hash_result;


        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }

    })
}

// 生成社工字典
function gendictfunc() {
    var gendict1 = document.getElementById("gendict1").value;
    var gendict2 = document.getElementById("gendict2").value;
    var gendict3 = document.getElementById("gendict3").value;
    var gendict4 = document.getElementById("gendict4").value;
    var gendict5 = document.getElementById("gendict5").value;
    var gendict6 = document.getElementById("gendict6").value;
    var gendict7 = document.getElementById("gendict7").value;
    var gendict8 = document.getElementById("gendict8").value;
    var gendict9 = document.getElementById("gendict9").value;
    var gendict10 = document.getElementById("gendict10").value;
    var gendict11 = document.getElementById("gendict11").value;
    var gendict12 = document.getElementById("gendict12").value;
    var gendict13 = document.getElementById("gendict13").value;
    var gendict14 = document.getElementById("gendict14").value;
    $.ajax({
        url: '/social_worker_dictionary/',
        method: 'POST',
        data: {
            gendict1: gendict1,
            gendict2: gendict2,
            gendict3: gendict3,
            gendict4: gendict4,
            gendict5: gendict5,
            gendict6: gendict6,
            gendict7: gendict7,
            gendict8: gendict8,
            gendict9: gendict9,
            gendict10: gendict10,
            gendict11: gendict11,
            gendict12: gendict12,
            gendict13: gendict13,
            gendict14: gendict14
        },
        success: function (info) {
            document.getElementById('dictresult').innerHTML = info.gendictresult;
        },
        error: function () {
            document.getElementById('dictresult').innerHTML = "内部出错";
        },
        complete: function () {

        }

    })

}


// 社工字典预览
function gendictreportfunc() {
    $.ajax({
        url: '/social_worker_dictionary_report/',
        method: 'GET',

        success: function (info) {
            // 当请求成功时调用
            var resultDiv = document.getElementById('dictresult');
            resultDiv.innerHTML = ''; // 清空原有内容
            info.gendictreport.forEach(function (item) {
                var itemDiv = document.createElement('div'); // 创建一个新的div元素
                itemDiv.textContent = item; // 设置文本内容
                resultDiv.appendChild(itemDiv); // 将新的div元素添加到结果div中
            });


        },
        error: function () {
            document.getElementById('dictresult').innerHTML = "内部出错";
        },
        complete: function () {

        }

    })
}

// 关闭字典生成
function stopgendictreportfunc() {
    $.ajax({
        url: '/stop_social_worker_dictionary/',
        method: 'GET',

        success: function (info) {
            document.getElementById('dictresult').innerHTML = info.stop_dict_status_result;
        },
        error: function () {
            document.getElementById('dictresult').innerHTML = "内部错误"
        },
        complete: function () {

        }
    })
}


// 网站导航模块
// 谷歌语法
function GoogledisplayText() {
    // 获取输入框的值
    var GoogleinputText = document.getElementById('GoogleinputText');
    // 获取显示的值
    var displayElement1 = document.getElementById('GoogledisplayText1');
    var displayElement2 = document.getElementById('GoogledisplayText2');
    var displayElement3 = document.getElementById('GoogledisplayText3');
    var displayElement4 = document.getElementById('GoogledisplayText4');
    var displayElement5 = document.getElementById('GoogledisplayText5');
    var displayElement6 = document.getElementById('GoogledisplayText6');
    var displayElement7 = document.getElementById('GoogledisplayText7');
    var displayElement8 = document.getElementById('GoogledisplayText8');
    var displayElement9 = document.getElementById('GoogledisplayText9');
    var displayElement10 = document.getElementById('GoogledisplayText10');
    var displayElement11 = document.getElementById('GoogledisplayText11');
    var displayElement12 = document.getElementById('GoogledisplayText12');
    var displayElement13 = document.getElementById('GoogledisplayText13');
    var displayElement14 = document.getElementById('GoogledisplayText14');
    var displayElement15 = document.getElementById('GoogledisplayText15');
    var displayElement16 = document.getElementById('GoogledisplayText16');
    var displayElement17 = document.getElementById('GoogledisplayText17');
    var displayElement18 = document.getElementById('GoogledisplayText18');
    var displayElement19 = document.getElementById('GoogledisplayText19');
    var displayElement20 = document.getElementById('GoogledisplayText20');


    displayElement1.textContent = GoogleinputText.value;
    displayElement2.textContent = GoogleinputText.value;
    displayElement3.textContent = GoogleinputText.value;
    displayElement4.textContent = GoogleinputText.value;
    displayElement5.textContent = GoogleinputText.value;
    displayElement6.textContent = GoogleinputText.value;
    displayElement7.textContent = GoogleinputText.value;
    displayElement8.textContent = GoogleinputText.value;
    displayElement9.textContent = GoogleinputText.value;
    displayElement10.textContent = GoogleinputText.value;
    displayElement11.textContent = GoogleinputText.value;
    displayElement12.textContent = GoogleinputText.value;
    displayElement13.textContent = GoogleinputText.value;
    displayElement14.textContent = GoogleinputText.value;
    displayElement15.textContent = GoogleinputText.value;
    displayElement16.textContent = GoogleinputText.value;
    displayElement17.textContent = GoogleinputText.value;
    displayElement18.textContent = GoogleinputText.value;
    displayElement19.textContent = GoogleinputText.value;
    displayElement20.textContent = GoogleinputText.value;
}

// Github搜索
function githubdisplayText() {
    // 获取输入框的值
    var githubinputText = document.getElementById('githubinputText');
    // 获取显示的值
    var displayElement1 = document.getElementById('githubdisplayText1');
    var displayElement2 = document.getElementById('githubdisplayText2');
    var displayElement3 = document.getElementById('githubdisplayText3');
    var displayElement4 = document.getElementById('githubdisplayText4');
    var displayElement5 = document.getElementById('githubdisplayText5');
    var displayElement6 = document.getElementById('githubdisplayText6');
    var displayElement7 = document.getElementById('githubdisplayText7');
    var displayElement8 = document.getElementById('githubdisplayText8');
    var displayElement9 = document.getElementById('githubdisplayText9');
    var displayElement10 = document.getElementById('githubdisplayText10');
    var displayElement11 = document.getElementById('githubdisplayText11');
    var displayElement12 = document.getElementById('githubdisplayText12');
    var displayElement13 = document.getElementById('githubdisplayText13');
    var displayElement14 = document.getElementById('githubdisplayText14');
    var displayElement15 = document.getElementById('githubdisplayText15');
    var displayElement16 = document.getElementById('githubdisplayText16');
    var displayElement17 = document.getElementById('githubdisplayText17');
    var displayElement18 = document.getElementById('githubdisplayText18');
    var displayElement19 = document.getElementById('githubdisplayText19');
    var displayElement20 = document.getElementById('githubdisplayText20');
    var displayElement21 = document.getElementById('githubdisplayText21');
    var displayElement22 = document.getElementById('githubdisplayText22');
    var displayElement23 = document.getElementById('githubdisplayText23');
    var displayElement24 = document.getElementById('githubdisplayText24');
    var displayElement25 = document.getElementById('githubdisplayText25');
    var displayElement26 = document.getElementById('githubdisplayText26');
    var displayElement27 = document.getElementById('githubdisplayText27');
    var displayElement28 = document.getElementById('githubdisplayText28');
    var displayElement29 = document.getElementById('githubdisplayText29');
    var displayElement30 = document.getElementById('githubdisplayText30');
    var displayElement31 = document.getElementById('githubdisplayText31');
    var displayElement32 = document.getElementById('githubdisplayText32');
    var displayElement33 = document.getElementById('githubdisplayText33');
    var displayElement34 = document.getElementById('githubdisplayText34');

    displayElement1.textContent = githubinputText.value;
    displayElement2.textContent = githubinputText.value;
    displayElement3.textContent = githubinputText.value;
    displayElement4.textContent = githubinputText.value;
    displayElement5.textContent = githubinputText.value;
    displayElement6.textContent = githubinputText.value;
    displayElement7.textContent = githubinputText.value;
    displayElement8.textContent = githubinputText.value;
    displayElement9.textContent = githubinputText.value;
    displayElement10.textContent = githubinputText.value;
    displayElement11.textContent = githubinputText.value;
    displayElement12.textContent = githubinputText.value;
    displayElement13.textContent = githubinputText.value;
    displayElement14.textContent = githubinputText.value;
    displayElement15.textContent = githubinputText.value;
    displayElement16.textContent = githubinputText.value;
    displayElement17.textContent = githubinputText.value;
    displayElement18.textContent = githubinputText.value;
    displayElement19.textContent = githubinputText.value;
    displayElement20.textContent = githubinputText.value;
    displayElement21.textContent = githubinputText.value;
    displayElement22.textContent = githubinputText.value;
    displayElement23.textContent = githubinputText.value;
    displayElement24.textContent = githubinputText.value;
    displayElement25.textContent = githubinputText.value;
    displayElement26.textContent = githubinputText.value;
    displayElement27.textContent = githubinputText.value;
    displayElement28.textContent = githubinputText.value;
    displayElement29.textContent = githubinputText.value;
    displayElement30.textContent = githubinputText.value;
    displayElement31.textContent = githubinputText.value;
    displayElement32.textContent = githubinputText.value;
    displayElement33.textContent = githubinputText.value;
    displayElement34.textContent = githubinputText.value;
}

// 文件传输
function msfdisplayText() {
    // 获取输入框的值
    var inputElement = document.getElementById('msfinputText');
    var inputElement1 = document.getElementById('msfinputText1');


    var displayElement = document.getElementById('msfdisplayText');
    var displayElement1 = document.getElementById('msfdisplayText1');
    var displayElement2 = document.getElementById('msfdisplayText2');
    var displayElement3 = document.getElementById('msfdisplayText3');
    var displayElement4 = document.getElementById('msfdisplayText4');
    var displayElement5 = document.getElementById('msfdisplayText5');
    var displayElement6 = document.getElementById('msfdisplayText6');
    var displayElement7 = document.getElementById('msfdisplayText7');
    var displayElement8 = document.getElementById('msfdisplayText8');
    var displayElement9 = document.getElementById('msfdisplayText9');
    var displayElement10 = document.getElementById('msfdisplayText10');
    var displayElement11 = document.getElementById('msfdisplayText11');
    var displayElement12 = document.getElementById('msfdisplayText12');
    var displayElement13 = document.getElementById('msfdisplayText13');
    var displayElement14 = document.getElementById('msfdisplayText14');
    var displayElement15 = document.getElementById('msfdisplayText15');
    var displayElement16 = document.getElementById('msfdisplayText16');
    var displayElement17 = document.getElementById('msfdisplayText17');
    var displayElement18 = document.getElementById('msfdisplayText18');
    var displayElement19 = document.getElementById('msfdisplayText19');
    var displayElement20 = document.getElementById('msfdisplayText20');
    var displayElement21 = document.getElementById('msfdisplayText21');
    var displayElement22 = document.getElementById('msfdisplayText22');
    var displayElement23 = document.getElementById('msfdisplayText23');
    var displayElement24 = document.getElementById('msfdisplayText24');
    var displayElement25 = document.getElementById('msfdisplayText25');
    var displayElement26 = document.getElementById('msfdisplayText26');
    var displayElement27 = document.getElementById('msfdisplayText27');
    var displayElement28 = document.getElementById('msfdisplayText28');
    var displayElement29 = document.getElementById('msfdisplayText29');
    var displayElement30 = document.getElementById('msfdisplayText30');
    var displayElement31 = document.getElementById('msfdisplayText31');
    var displayElement32 = document.getElementById('msfdisplayText32');
    var displayElement33 = document.getElementById('msfdisplayText33');

    displayElement.textContent = inputElement.value;
    displayElement1.textContent = inputElement1.value;
    displayElement2.textContent = inputElement.value;
    displayElement3.textContent = inputElement1.value;
    displayElement4.textContent = inputElement.value;
    displayElement5.textContent = inputElement1.value;
    displayElement6.textContent = inputElement.value;
    displayElement7.textContent = inputElement1.value;
    displayElement8.textContent = inputElement.value;
    displayElement9.textContent = inputElement1.value;
    displayElement10.textContent = inputElement.value;
    displayElement11.textContent = inputElement1.value;
    displayElement12.textContent = inputElement.value;
    displayElement13.textContent = inputElement1.value;
    displayElement14.textContent = inputElement.value;
    displayElement15.textContent = inputElement1.value;
    displayElement16.textContent = inputElement.value;
    displayElement17.textContent = inputElement1.value;
    displayElement18.textContent = inputElement.value;
    displayElement19.textContent = inputElement1.value;
    displayElement20.textContent = inputElement.value;
    displayElement21.textContent = inputElement1.value;
    displayElement22.textContent = inputElement.value;
    displayElement23.textContent = inputElement1.value;
    displayElement24.textContent = inputElement.value;
    displayElement25.textContent = inputElement1.value;
    displayElement26.textContent = inputElement.value;
    displayElement27.textContent = inputElement1.value;
    displayElement28.textContent = inputElement.value;
    displayElement29.textContent = inputElement1.value;
    displayElement30.textContent = inputElement.value;
    displayElement31.textContent = inputElement1.value;
    displayElement32.textContent = inputElement.value;
    displayElement33.textContent = inputElement1.value;


}

// msfbuilder
function msfbuilderdisplayText() {
    var inputElement = document.getElementById('msfbuilderinputText');
    var inputElement1 = document.getElementById('msfbuilderinputText1');
    var inputElement2 = document.getElementById('msfbuilderinputText2');
    var inputElement3 = document.getElementById('msfbuilderinputText3');
    var inputElement4 = document.getElementById('msfbuilderinputText4');
    var inputElement5 = document.getElementById('msfbuilderinputText5');
    var inputElement6 = document.getElementById('msfbuilderinputText6');
    var inputElement7 = document.getElementById('msfbuilderinputText7');
    var inputElement8 = document.getElementById('msfbuilderinputText8');
    var inputElement9 = document.getElementById('msfbuilderinputText9');

    var displayElement = document.getElementById('msfbuilderdisplayText');
    var displayElement1 = document.getElementById('msfbuilderdisplayText1');
    var displayElement2 = document.getElementById('msfbuilderdisplayText2');
    var displayElement3 = document.getElementById('msfbuilderdisplayText3');
    var displayElement4 = document.getElementById('msfbuilderdisplayText4');
    var displayElement5 = document.getElementById('msfbuilderdisplayText5');
    var displayElement6 = document.getElementById('msfbuilderdisplayText6');
    var displayElement7 = document.getElementById('msfbuilderdisplayText7');
    var displayElement8 = document.getElementById('msfbuilderdisplayText8');
    var displayElement9 = document.getElementById('msfbuilderdisplayText9');
    var displayElement10 = document.getElementById('msfbuilderdisplayText10');
    var displayElement11 = document.getElementById('msfbuilderdisplayText11');
    var displayElement12 = document.getElementById('msfbuilderdisplayText12');
    var displayElement13 = document.getElementById('msfbuilderdisplayText13');
    var displayElement14 = document.getElementById('msfbuilderdisplayText14');
    var displayElement15 = document.getElementById('msfbuilderdisplayText15');



    displayElement.textContent = inputElement.value;
    displayElement1.textContent = inputElement1.value;
    displayElement2.textContent = inputElement2.value;
    displayElement3.textContent = inputElement3.value;
    displayElement4.textContent = inputElement4.value;
    displayElement5.textContent = inputElement5.value;
    displayElement6.textContent = inputElement6.value;
    displayElement7.textContent = inputElement7.value;
    displayElement8.textContent = inputElement8.value;
    displayElement9.textContent = inputElement9.value;
    displayElement10.textContent = inputElement.value;
    displayElement11.textContent = inputElement1.value;
    displayElement12.textContent = inputElement2.value;
    displayElement13.textContent = inputElement.value;
    displayElement14.textContent = inputElement1.value;
    displayElement15.textContent = inputElement2.value;
}


function showContent(contentId) {
    var contents = document.querySelectorAll('.content-item');
    for (var i = 0; i < contents.length; i++) {
        contents[i].classList.remove('active');
    }
    document.getElementById(contentId).classList.add('active');
    if (contentId === "content15") {
        $.ajax({
            url: '/dictsize/',
            method: 'GET',

            success: function (info) {
                document.getElementById('dictresult').innerHTML = info.sizenum;
            },
            error: function () {
                document.getElementById('dictresult').innerHTML = "内部错误"
            },
            complete: function () {

            }
        })
    }
}

// 反弹shell
function displayText() {
    // 获取输入框的值
    var inputElement = document.getElementById('inputText');
    var inputElement1 = document.getElementById('inputText1');

    var displayElement = document.getElementById('displayText');
    var displayElement1 = document.getElementById('displayText1');

    var displayElement2 = document.getElementById('displayText2');
    var displayElement3 = document.getElementById('displayText3');

    var displayElement4 = document.getElementById('displayText4');
    var displayElement5 = document.getElementById('displayText5');

    var displayElement6 = document.getElementById('displayText6');
    var displayElement7 = document.getElementById('displayText7');

    var displayElement8 = document.getElementById('displayText8');
    var displayElement9 = document.getElementById('displayText9');

    var displayElement10 = document.getElementById('displayText10');
    var displayElement11 = document.getElementById('displayText11');

    var displayElement12 = document.getElementById('displayText12');
    var displayElement13 = document.getElementById('displayText13');

    var displayElement14 = document.getElementById('displayText14');
    var displayElement15 = document.getElementById('displayText15');

    var displayElement16 = document.getElementById('displayText16');
    var displayElement17 = document.getElementById('displayText17');


    // 将输入框的值设置到显示区域
    displayElement.textContent = inputElement.value;
    displayElement1.textContent = inputElement1.value;

    displayElement2.textContent = inputElement.value;
    displayElement3.textContent = inputElement1.value;

    displayElement4.textContent = inputElement.value;
    displayElement5.textContent = inputElement1.value;

    displayElement6.textContent = inputElement.value;
    displayElement7.textContent = inputElement1.value;

    displayElement8.textContent = inputElement.value;
    displayElement9.textContent = inputElement1.value;

    displayElement10.textContent = inputElement.value;
    displayElement11.textContent = inputElement1.value;

    displayElement12.textContent = inputElement.value;
    displayElement13.textContent = inputElement1.value;

    displayElement14.textContent = inputElement.value;
    displayElement15.textContent = inputElement1.value;

    displayElement16.textContent = inputElement.value;
    displayElement17.textContent = inputElement1.value;

}

//字典下载
function passdictdownloadfunc() {
    window.open("/passworddictdownload/", "_blank");
}

// 通过shodan获取资产
function shodan_search_assets_func() {
    var inputshodanid = document.getElementById("inputshodanid").value;
    var start_num_shodan = $('select[name="start_num_shodan"]').val();
    var end_num_shodan = $('select[name="end_num_shodan"]').val();
    $.ajax({
        url: '/assets_byshodan/',
        method: 'POST',
        data: {
            inputshodanid: inputshodanid,
            start_num_shodan: start_num_shodan,
            end_num_shodan: end_num_shodan
        },
        success: function (info) {
            // 当请求成功时调用  
            document.getElementById("shodanreturnresult1").innerHTML = info.shodan_status_result;

        },
        error: function () {
            document.getElementById("shodanreturnresult1").innerHTML = "内部错误";
        },
        complete: function () {

        }

    })
}

// 打开设备口令窗口
function opendevicepasswordfunc() {
    var modal5 = document.getElementById("modal5");
    modal5.style.display = "block";
    // 清空表格体中的所有行
    const tableBody = document.querySelector('#data-table11 tbody');
    tableBody.innerHTML = '';
    $.ajax({
        url: '/showdevicepassword/',
        method: 'GET',
        success: function (info) {
            document.getElementById("deviceid1").innerHTML = info.device_dict_len;
            document.getElementById("deviceid2").innerHTML = info.device_dict;

        },
        error: function () {


        },
        complete: function () {

        }
    })
}

// 关闭设备口令
function closeModal5() {
    var modal5 = document.getElementById("modal5");
    modal5.style.display = "none";
}

// 通过关键字检索设备口令
function opendevicepasswordbykeyfunc() {
    var devicekeyvalue = document.getElementById("devicekeyvalue").value;
    // 清空表格体中的所有行
    const tableBody = document.querySelector('#data-table11 tbody');
    tableBody.innerHTML = '';
    document.getElementById("deviceid2").innerHTML = "";
    $.ajax({
        url: '/showdevicepasswordbykey/',
        method: 'POST',
        data: {
            devicekeyvalue: devicekeyvalue
        },
        success: function (info) {
            document.getElementById("deviceid1").innerHTML = info.device_new_list_len;

            const tableBody = document.querySelector('#data-table11 tbody');

            info.device_new_list.forEach(item => {
                const row = document.createElement('tr'); // 创建新的行

                // 创建单元格并填充数据
                const idCell = document.createElement('td');
                idCell.textContent = item.company;
                row.appendChild(idCell);

                const nameCell = document.createElement('td');
                nameCell.textContent = item.username;
                row.appendChild(nameCell);

                const addrCell = document.createElement('td');
                addrCell.textContent = item.password;
                row.appendChild(addrCell);

                tableBody.appendChild(row); // 将行添加到表格体中
            });

        },
        error: function () {


        },
        complete: function () {

        }
    })
}

// 杀软识别查询所有
function openantivsoftallfunc() {
    var modal6 = document.getElementById("modal6");
    modal6.style.display = "block";

    // 清空表格体中的所有行
    const tableBody = document.querySelector('#data-table22 tbody');
    tableBody.innerHTML = '';
    $.ajax({
        url: '/antivirus_soft_show_interface/',
        method: 'GET',
        success: function (info) {
            document.getElementById("sharuanid1").innerHTML = info.antivirus_dict_len;
            document.getElementById("sharuanid2").innerHTML = info.antivirus_dict;
        },
        error: function () {


        },
        complete: function () {

        }
    })
}

// 关闭杀软识别
function closeModal6() {
    var modal6 = document.getElementById("modal6");
    modal6.style.display = "none";
}


// 通过关键字查询杀软
function openantivsoftbykeyfunc() {
    var modal6 = document.getElementById("modal6");
    modal6.style.display = "block";
    document.getElementById("sharuanid2").innerHTML = "";
    // 获取textarea的值  
    const text = document.getElementById('antivirusTextarea').value;
    // 按换行符分割文本为数组  
    const antiviruslines = text.split('\n');
    // 清空表格体中的所有行
    const tableBody = document.querySelector('#data-table22 tbody');
    tableBody.innerHTML = '';
    $.ajax({
        url: '/antivirus_soft_show_interface_bykey/',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ antiviruslines: antiviruslines }),
        dataType: 'json',
        success: function (info) {
            document.getElementById("sharuanid1").innerHTML = info.antivirus_dict_len;

            const tableBody = document.querySelector('#data-table22 tbody');

            info.antivirus_dict.forEach(item => {
                const row = document.createElement('tr'); // 创建新的行

                // 创建单元格并填充数据
                const idCell = document.createElement('td');
                idCell.textContent = item.antivirus_name;
                row.appendChild(idCell);

                const nameCell = document.createElement('td');
                nameCell.textContent = item.antivirus_decrib;
                row.appendChild(nameCell);

                tableBody.appendChild(row); // 将行添加到表格体中
            });

        },
        error: function () {


        },
        complete: function () {

        }
    })
}


// 系统服务重启
function systemrebootfunc() {
    var myModa14 = document.getElementById("myModa14");
    myModa14.style.display = "block";
    $.ajax({
        url: '/restartsystemserviceinterface/',
        method: 'GET',
    })
    function fetchData() {
        $.getJSON("/restartsystemservice/",
            function (info) {
                document.getElementById('rebootid1').innerHTML = info.infoscanstatus;
            });
    }

    // 调用fetchData函数初始化显示
    fetchData();

    // 设置定时器，每5000毫秒（5秒）执行一次fetchData函数
    var intervalId = setInterval(fetchData, 1000);
    // 确保在页面卸载或组件销毁时清除定时器，以防止内存泄漏
    window.addEventListener("beforeunload", function () {
        clearInterval(intervalId);
    });
}




function closevulnscan13() {
    var myModa14 = document.getElementById("myModa14");
    myModa14.style.display = "none";

}


// 系统配置开启JNDI
function jndistatusfunc() {

    $.ajax({
        url: '/startjndiservice/',
        method: 'GET',

        success: function (info) {
            const statusElement = document.getElementById('jndistatusid1');
            const status = info.jndistatus;

            // 清除所有可能的状态类
            statusElement.className = 'status-circle';

            // 根据状态添加对应样式
            if (status === '开启') {
                statusElement.classList.add('status-running');
            } else if (status === '关闭') {
                statusElement.classList.add('status-stopped');
            } else {
                statusElement.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement = document.getElementById('jndistatusid1');
            statusElement.className = 'status-circle status-error';
        }
    })
}

// 系统配置关闭JNDI
function stopjndistatusfunc() {

    $.ajax({
        url: '/stopjndiservice/',
        method: 'GET',

        success: function (info) {
            const statusElement = document.getElementById('jndistatusid1');
            const status = info.jndistatus;

            // 清除所有可能的状态类
            statusElement.className = 'status-circle';

            // 根据状态添加对应样式
            if (status === '开启') {
                statusElement.classList.add('status-running');
            } else if (status === '关闭') {
                statusElement.classList.add('status-stopped');
            } else {
                statusElement.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement = document.getElementById('jndistatusid1');
            statusElement.className = 'status-circle status-error';
        }
    })
}

// 点击logo图标返回首页
function pointlogopagefunc() {
    window.location.href = "/index/";
}


// 实时显示当前时间
function updateClock() {
    const now = new Date();
    const formattedTime = now.getFullYear() + '/' +
        String(now.getMonth() + 1).padStart(2, '0') + '/' +
        String(now.getDate()).padStart(2, '0') + ' ' +
        String(now.getHours()).padStart(2, '0') + ':' +
        String(now.getMinutes()).padStart(2, '0') + ':' +
        String(now.getSeconds()).padStart(2, '0');
    document.getElementById('clock').textContent = formattedTime;
}

setInterval(updateClock, 1000); // 更新时间间隔为1秒
updateClock(); // 初始化时立即更新时间


// 系统配置开启资产校验
function startassetsjiaoyanfunc() {

    $.ajax({
        url: '/startassetserification/',
        method: 'GET',

        success: function (info) {
            const statusElement = document.getElementById('assetsjiaoyanstatusid1');
            const status = info.verificationresult;

            // 清除所有可能的状态类
            statusElement.className = 'status-circle';

            // 根据状态添加对应样式
            if (status === '已开启校验') {
                statusElement.classList.add('status-running');
            } else if (status === '未开启校验') {
                statusElement.classList.add('status-stopped');
            } else {
                statusElement.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement = document.getElementById('assetsjiaoyanstatusid1');
            statusElement.className = 'status-circle status-error';
        }
    })
}

// 系统配置关闭资产校验
function stopassetsjiaoyanfunc() {

    $.ajax({
        url: '/stopassetserification/',
        method: 'GET',

        success: function (info) {
            const statusElement = document.getElementById('assetsjiaoyanstatusid1');
            const status = info.verificationresult;

            // 清除所有可能的状态类
            statusElement.className = 'status-circle';

            // 根据状态添加对应样式
            if (status === '已开启校验') {
                statusElement.classList.add('status-running');
            } else if (status === '未开启校验') {
                statusElement.classList.add('status-stopped');
            } else {
                statusElement.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement = document.getElementById('assetsjiaoyanstatusid1');
            statusElement.className = 'status-circle status-error';
        }
    })
}


// 查询高危资产规则
function select_rule_all_func() {
    var modal7 = document.getElementById("modal7");
    modal7.style.display = "block";
    // 清空表格体中的所有行
    const tableBody = document.querySelector('#data-table3 tbody');
    tableBody.innerHTML = '';
    $.ajax({
        url: '/high_asset_characteristics/',
        method: 'GET',
        success: function (info) {
            const tableBody = document.querySelector('#data-table3 tbody');

            // 遍历数组中的每个字符串项
            info.assets_character_result.forEach((item) => {
                const row = document.createElement('tr'); // 创建新的行

                // 创建内容单元格
                const contentCell = document.createElement('td');
                contentCell.textContent = item; // 显示数组中的字符串
                row.appendChild(contentCell);

                // 创建操作单元格
                const actionCell = document.createElement('td');

                // 创建删除按钮
                const deleteButton = document.createElement('button');
                deleteButton.classList.add('button', 'delete1-button');
                deleteButton.textContent = '删除';

                // 为删除按钮绑定点击事件
                deleteButton.onclick = function () {

                    // 删除当前规则指令到后端接口
                    $.ajax({
                        url: '/delete_point_rule_interface/', // 假设这是删除规则的API接口
                        method: 'POST',
                        data: {
                            rule: item,
                            key: 1
                        },
                        success: function (response) {
                            // 删除成功后，移除当前行
                            row.remove();
                            console.log('删除规则成功:', response.delete_rule);
                        },
                        error: function (error) {
                            console.error('删除规则失败:', error);
                        }
                    });
                };

                // 将删除按钮添加到操作单元格中
                actionCell.appendChild(deleteButton);

                // 将操作单元格添加到行中
                row.appendChild(actionCell);

                // 将行添加到表格体中
                tableBody.appendChild(row);
            });
        },
        error: function () {
            console.error('获取数据失败');
        },
        complete: function () {
            console.log('请求完成');
        }
    });
}


// 关闭高危资产查询规则
function stop_rule_all_func() {
    var modal7 = document.getElementById("modal7");
    modal7.style.display = "none";

}


// DNS日志更新当前域名
function dnslogupdatedomainfunc() {

    var dnslogkeyid = document.getElementById("dnslogkeyid").value;
    $.ajax({
        url: '/dnslogupdatedomain/',
        method: 'POST',
        data: {
            dnslogkeyid: dnslogkeyid
        },
        success: function (info) {
            document.getElementById("dnslogkeyid2").innerHTML = info.dnslogdomainresult;
        },

        error: function () {
            document.getElementById("dnslogkeyid2").innerHTML = "内部出错";
        },
        complete: function () {

        }
    })
}

// 关闭DNSLog Platform
function closevulnscan18() {
    var myModa18 = document.getElementById("myModa18");
    myModa18.style.display = "none";
}

// 打开DNSLog Platform
function opendnslogpaltform() {
    var myModa18 = document.getElementById("myModa18");
    myModa18.style.display = "block";
}

// 获取随机子域名
function getrandomsubdomainfunc() {
    $.ajax({
        url: '/getrandomsubdomain/',
        method: 'GET',
        success: function (info) {
            document.getElementById("getrandomsubdomainid1").innerHTML = info.randomdomain;
        },

        error: function () {
            document.getElementById("getrandomsubdomainid1").innerHTML = "内部出错";
        },
        complete: function () {

        }
    })
}

// ceyednslog详细用法
function ceyexianshixiangximethos() {
    var dnslogkeyid3 = document.getElementById("dnslogkeyid3");
    dnslogkeyid3.style.display = "block";
    var dnslogkeyid4 = document.getElementById("dnslogkeyid4");
    dnslogkeyid4.style.display = "block";
}

function ceyexianshiyincangmethos() {
    var dnslogkeyid3 = document.getElementById("dnslogkeyid3");
    dnslogkeyid3.style.display = "none";
    var dnslogkeyid4 = document.getElementById("dnslogkeyid4");
    dnslogkeyid4.style.display = "none";
}

// 全局白名单配置
// 打开白名单弹窗
function openwhiteupwindowsfunc() {
    var myModa19 = document.getElementById("myModa19");
    myModa19.style.display = "block";
    $.ajax({
        url: '/getglobalwhiteconfig/',
        method: 'GET',
        success: function (info) {
            // 全局白名单配置开关
            const statusElement1 = document.getElementById('globalwhiteconfigid1');
            const status1 = info.globalwhiteswitch;

            // 根据状态添加对应样式
            if (status1 === '已开启校验') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启校验') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }

            // 全局白名单目标
            var textAreaContent = '';
            for (var i = 0; i < info.globalwhitetarget.length; i++) {
                textAreaContent += info.globalwhitetarget[i] + '\n';
            }
            $('#globalwhiteconfigid2').val(textAreaContent);
            document.getElementById("globalwhiteconfigid3").innerHTML = info.globalwhitetargetlen;
        },
        error: function () {
            const statusElement = document.getElementById('jndistatusid1');
            statusElement.className = 'status-circle status-error';
        },
        complete: function () {

        }
    })
}

// 开启全局白名单控制
function startwhiteupwindowsfunc() {
    $.ajax({
        url: '/startglobalwhiteconfig/',
        method: 'GET',
        success: function (info) {
            // 资产校验开关状态
            const statusElement1 = document.getElementById('globalwhiteconfigid1');
            const status1 = info.startglobalwhiteswitch;
            // 清除所有可能的状态类
            statusElement1.className = 'status-circle';
            // 根据状态添加对应样式
            if (status1 === '已开启校验') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启校验') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement = document.getElementById('jndistatusid1');
            statusElement.className = 'status-circle status-error';
        },
        complete: function () {

        }
    })
}

// 关闭全局白名单控制
function stopwhiteupwindowsfunc() {
    $.ajax({
        url: '/stopglobalwhiteconfig/',
        method: 'GET',
        success: function (info) {
            // 资产校验开关状态
            const statusElement1 = document.getElementById('globalwhiteconfigid1');
            const status1 = info.stopglobalwhiteswitch;
            // 清除所有可能的状态类
            statusElement1.className = 'status-circle';
            // 根据状态添加对应样式
            if (status1 === '已开启校验') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启校验') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement = document.getElementById('jndistatusid1');
            statusElement.className = 'status-circle status-error';
        },
        complete: function () {

        }
    })
}

// 关闭白名单弹窗
function closewhiteupwindowsfunc() {
    var myModa19 = document.getElementById("myModa19");
    myModa19.style.display = "none";
    var globalwhiteconfigid4 = document.getElementById("globalwhiteconfigid4");
    globalwhiteconfigid4.style.display = "none";

}

// 新增全局白名单
function addglobalwhiteconffunc() {
    // 获取textarea的值  
    const text = document.getElementById('globalwhiteconfigid2').value;
    // 按换行符分割文本为数组  
    const lines = text.split('\n');
    // 使用jQuery的$.ajax方法发送POST请求到Flask后端  
    $.ajax({
        url: '/addglobalwhitedata/',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ lines: lines }),
        dataType: 'json',
        success: function (info) {
            document.getElementById('globalwhiteconfigid4').innerHTML = info.file_line;
        },
        error: function () {
            document.getElementById('globalwhiteconfigid4').innerHTML = "内部错误"
        },
        complete: function () {

        }
    });
}


// 关闭系统代理配置
function closesystemproxyfunc() {
    var myModa20 = document.getElementById("myModa20");
    myModa20.style.display = "none";
    // 清空前端选中的值
    document.getElementById('fileuploadid2').innerHTML = "";
    document.getElementById('fileuploadid1').value = "";
}

// 打开系统代理配置页面
function opensystemproxyconffunc() {
    var myModa20 = document.getElementById("myModa20");
    myModa20.style.display = "block";
    $.ajax({
        url: '/showsystemproxyconf/',
        method: 'GET',
        success: function (info) {
            // 地理位置
            document.getElementById('systemproxyid1').innerHTML = info.ip_location1;
            document.getElementById('systemproxyid6').innerHTML = info.ip_location2;
            document.getElementById('systemproxyid7').innerHTML = info.ip_location3;
            document.getElementById('systemproxyid4').innerHTML = info.proxyport;
            document.getElementById('systemproxyid5').innerHTML = info.public_ip_result;
            document.getElementById('systemproxyid8').innerHTML = info.proxynode_num;
            document.getElementById('systemproxyid9').innerHTML = info.response_time_kxsw;
            // 代理状态
            const statusElement1 = document.getElementById('systemproxyid2');
            const status1 = info.proxystatus;
            // 清除所有可能的状态类
            statusElement1.className = 'status-circle';
            // 根据状态添加对应样式
            if (status1 === '已开启') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }
        },
        error: function () {
            document.getElementById('systemproxyid1').innerHTML = "内部错误";
            statusElement1.className = 'status-circle status-error';
        }
    })
}

// 开启系统代理配置
function opensystemproxycontrolfunc() {

    $.ajax({
        url: '/startsystemproxyconf/',
        method: 'GET',

        success: function (info) {
            // 地理位置
            document.getElementById('systemproxyid1').innerHTML = info.ip_location1;
            document.getElementById('systemproxyid6').innerHTML = info.ip_location2;
            document.getElementById('systemproxyid7').innerHTML = info.ip_location3;
            document.getElementById('systemproxyid4').innerHTML = info.proxyport;
            document.getElementById('systemproxyid5').innerHTML = info.public_ip_result;
            
            // 代理状态
            const statusElement1 = document.getElementById('systemproxyid2');
            const status1 = info.proxystatus;
            // 清除所有可能的状态类
            statusElement1.className = 'status-circle';
            // 根据状态添加对应样式
            if (status1 === '已开启') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement1 = document.getElementById('systemproxyid2');
            statusElement1.className = 'status-circle status-error';
        }
    })
}

// 关闭系统代理配置
function stopdownsystemproxycontrolfunc() {

    $.ajax({
        url: '/stopdownsystemproxyconf/',
        method: 'GET',

        success: function (info) {
            // 地理位置
            document.getElementById('systemproxyid1').innerHTML = info.ip_location1;
            document.getElementById('systemproxyid6').innerHTML = info.ip_location2;
            document.getElementById('systemproxyid7').innerHTML = info.ip_location3;
            document.getElementById('systemproxyid4').innerHTML = info.proxyport;
            document.getElementById('systemproxyid5').innerHTML = info.public_ip_result;
            // 代理状态
            const statusElement1 = document.getElementById('systemproxyid2');
            const status1 = info.proxystatus;
            // 清除所有可能的状态类
            statusElement1.className = 'status-circle';
            // 根据状态添加对应样式
            if (status1 === '已开启') {
                statusElement1.classList.add('status-running');
            } else if (status1 === '未开启') {
                statusElement1.classList.add('status-stopped');
            } else {
                statusElement1.classList.add('status-error');
            }
        },
        error: function () {
            const statusElement1 = document.getElementById('systemproxyid2');
            statusElement1.className = 'status-circle status-error';
        }
    })
}

// 配置文件上传
function proxyfileuploadfunc() {
    // 获取文件选择框中的文件
    const fileInput = document.getElementById('fileuploadid1');
    const file = fileInput.files[0];
    // 文件上传格式校验通过后端进行校验
    // 创建 FormData 对象，用于封装文件数据
    const formData = new FormData();
    formData.append('file', file);
    $.ajax({
        url: '/proxyconfigfileupload/',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function (response) {
            // 请求成功
            if (response.success) {
                document.getElementById('fileuploadid2').innerHTML = "文件上传成功！";
            } else {
                document.getElementById('fileuploadid2').innerHTML = "文件上传失败：" + response.message;

            }
        },
        error: function (xhr, status, error) {
            // 请求失败
            document.getElementById('fileuploadid2').innerHTML = "文件上传发生错误：" + error;
        }
    });
}

// 删除系统代理配置文件
function deletesystemproxyfilefunc() {
    $.ajax({
        url: '/deleteproxyconfigfile/',
        method: 'GET',
        success: function (info) {
            document.getElementById("fileuploadid2").innerHTML = info.delete_result;
        },

        error: function () {
            document.getElementById("fileuploadid2").innerHTML = "内部出错";
        },
        complete: function () {

        }
    })
}

// JWT爆破结果预览
function jwtreportfunc() {
    $.ajax({
        url: '/jwt_result_show/',
        method: 'GET',

        success: function (info) {
            // 当请求成功时调用
            var resultDiv = document.getElementById('jwtresultid1');
            resultDiv.innerHTML = ''; // 清空原有内容
            info.jwtresultdata.forEach(function (item) {
                var itemDiv = document.createElement('div'); // 创建一个新的div元素
                itemDiv.textContent = item; // 设置文本内容
                resultDiv.appendChild(itemDiv); // 将新的div元素添加到结果div中
            });


        },
        error: function () {
            document.getElementById('jwtresultid1').innerHTML = "内部出错";
        },
        complete: function () {

        }

    })
}

// 开启JWT爆破
function startjwtscanfunc() {
    // 打开弹窗
    var myModa21 = document.getElementById("myModa21");
    myModa21.style.display = "block";
     // 获取textarea的值  
    const jwtresultid2 = document.getElementById('jwtresultid2').value;
    var jwtresultid3 = $('select[name="jwtresultid3"]').val();
    $.ajax({
        url: '/startjwtscan/',
        method: 'POST',
        data: {
            jwtresultid2: jwtresultid2,
            jwtresultid3,jwtresultid3
        },
        success: function (info) {
            document.getElementById("jwtresultid4").innerHTML = info.jwt_status_result;
        },

        error: function () {
            document.getElementById("jwtresultid4").innerHTML = "内部出错";
        },
        complete: function () {

        }
    })
}

// 关闭jwt弹窗
function closevulnscan19() {
    var myModa21 = document.getElementById("myModa21");
    myModa21.style.display = "none";
}
