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





//ajax异步清除数据
function deletenmapfunc() {
    var input = document.getElementById("myInput");
    input.value = "";
    $.ajax({
        url: '/deletenmapresult/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已删除端口扫描报告')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('已删除端口扫描报告')
        }
    })
}



//xray报告预览
function xrayreportshow() {
    window.open(ipvalue + ":18888/", "_blank");
}


//urlfinder报告预览
function urlfinderreportshow() {
    window.open(ipvalue + ":16666/", "_blank");
}


//ajax异步删除xray报告
function xrayreportdelete() {
    $.ajax({
        url: '/deletexrayreport/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已删除xray报告')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('已删除xray报告')
        }
    })
}


//ajax异步删除api接口扫描报告
function deleteurlfinderreportfunc() {
    $.ajax({
        url: '/deleteurlfinderreport/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已删除api接口报告')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('已删除api接口报告')
        }
    })
}



//ajax异步关闭xray和rad引擎进程
function killxrayandradfunc() {
    $.ajax({
        url: '/killprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭xray和rad引擎')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('已关闭xray和rad引擎')
        }
    })
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


//启动xray和rad提示
function startradandxray() {
    alert("进入命令行分别开启xray和rad" + "\n" + "启动rad：python3 /TIP/batch_scan_domain/radscan.py" + "\n" +
        "启动xray：bash /TIP/batch_scan_domain/start.sh startxray")
}


//ajax异步启动nuclei
function startnucleifunc() {
    var poc_dir = $('select[name="poc_dir"]').val();
    $.ajax({
        url: '/startnuclei/',
        method: 'POST',
        data: {
            poc_dir: poc_dir
        },
        success: function (info) {
            alert(info.nuclei_status_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步查看历史url
function historyurlfunc() {
    $.ajax({
        url: '/historyshow/',
        method: 'GET',
        success: function (info) {
            alert(info.otx_status_result)
        },
        error: function () {
            alert('内部出错')

        },
        complete: function () {

        }
    })

}




//ajax异步关闭otx历史url查询接口
function killotxhistory_func() {
    $.ajax({
        url: '/killotxhistory/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_otx_url_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭基于证书查询子域名接口
function kill_crt_subdomain_func() {
    $.ajax({
        url: '/kill_crt_subdomain_shell/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_crt_subdomain_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
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
    var button6 = document.getElementById("button6");
    button6.disabled = false;
    var button7 = document.getElementById("button7");
    button7.disabled = false;
    var button8 = document.getElementById("button8");
    button8.disabled = false;
    var button9 = document.getElementById("button9");
    button9.disabled = false;
    var button10 = document.getElementById("button10");
    button10.disabled = false;
    var button11 = document.getElementById("button11");
    button11.disabled = false;
    var button12 = document.getElementById("button12");
    button12.disabled = false;
    var button13 = document.getElementById("button13");
    button13.disabled = false;
    var button14 = document.getElementById("button14");
    button14.disabled = false;
    var button15 = document.getElementById("button15");
    button15.disabled = false;
    var button16 = document.getElementById("button16");
    button16.disabled = false;
    
    var button18 = document.getElementById("button18");
    button18.disabled = false;
    var button19 = document.getElementById("button19");
    button19.disabled = false;
    var button20 = document.getElementById("button20");
    button20.disabled = false;
    var button21 = document.getElementById("button21");
    button21.disabled = false;
    var button22 = document.getElementById("button22");
    button22.disabled = false;
    var button23 = document.getElementById("button23");
    button23.disabled = false;
    var button24 = document.getElementById("button24");
    button24.disabled = false;
    var button25 = document.getElementById("button25");
    button25.disabled = false;
    var button27 = document.getElementById("button27");
    button27.disabled = false;
    var button28 = document.getElementById("button28");
    button28.disabled = false;
    var button29 = document.getElementById("button29");
    button29.disabled = false;
    var button30 = document.getElementById("button30");
    button30.disabled = false;
    var button31 = document.getElementById("button31");
    button31.disabled = false;
    var button32 = document.getElementById("button32");
    button32.disabled = false;
    var button33 = document.getElementById("button33");
    button33.disabled = false;
    var button34 = document.getElementById("button34");
    button34.disabled = false;
    var button35 = document.getElementById("button35");
    button35.disabled = false;
    var button36 = document.getElementById("button36");
    button36.disabled = false;
    var button37 = document.getElementById("button37");
    button37.disabled = false;
    var button38 = document.getElementById("button38");
    button38.disabled = false;
    var button39 = document.getElementById("button39");
    button39.disabled = false;
    var button40 = document.getElementById("button40");
    button40.disabled = false;
    var button41 = document.getElementById("button41");
    button41.disabled = false;
    var button42 = document.getElementById("button42");
    button42.disabled = false;
    var button43 = document.getElementById("button43");
    button43.disabled = false;
    var button46 = document.getElementById("button46");
    button46.disabled = false;
    var button47 = document.getElementById("button47");
    button47.disabled = false;
    var button48 = document.getElementById("button48");
    button48.disabled = false;
    var button49 = document.getElementById("button49");
    button49.disabled = false;
    var button50 = document.getElementById("button50");
    button50.disabled = false;
    var button51 = document.getElementById("button51");
    button51.disabled = false;
    var button52 = document.getElementById("button52");
    button52.disabled = false;
    var button53 = document.getElementById("button53");
    button53.disabled = false;
    var button54 = document.getElementById("button54");
    button54.disabled = false;
    var button55 = document.getElementById("button55");
    button55.disabled = false;
    var button56 = document.getElementById("button56");
    button56.disabled = false;
    var button58 = document.getElementById("button58");
    button58.disabled = false;
    var button59 = document.getElementById("button59");
    button59.disabled = false;
    var button60 = document.getElementById("button60");
    button60.disabled = false;
    var button61 = document.getElementById("button61");
    button61.disabled = false;
    var button62 = document.getElementById("button62");
    button62.disabled = false;
    var button63 = document.getElementById("button63");
    button63.disabled = false;
    var button66 = document.getElementById("button66");
    button66.disabled = false;
    var button67 = document.getElementById("button67");
    button67.disabled = false;
    var button68 = document.getElementById("button68");
    button68.disabled = false;
    var button69 = document.getElementById("button69");
    button69.disabled = false;
    var button70 = document.getElementById("button70");
    button70.disabled = false;
    var button71 = document.getElementById("button71");
    button71.disabled = false;
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
    var button78 = document.getElementById("button78");
    button78.disabled = false;
    var button79 = document.getElementById("button79");
    button79.disabled = false;
    var button80 = document.getElementById("button80");
    button80.disabled = false;
    var button81 = document.getElementById("button81");
    button81.disabled = false;
    var button82 = document.getElementById("button82");
    button82.disabled = false;
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
    var button6 = document.getElementById("button6");
    button6.disabled = true;
    var button7 = document.getElementById("button7");
    button7.disabled = true;
    var button8 = document.getElementById("button8");
    button8.disabled = true;
    var button9 = document.getElementById("button9");
    button9.disabled = true;
    var button10 = document.getElementById("button10");
    button10.disabled = true;
    var button11 = document.getElementById("button11");
    button11.disabled = true;
    var button12 = document.getElementById("button12");
    button12.disabled = true;
    var button13 = document.getElementById("button13");
    button13.disabled = true;
    var button14 = document.getElementById("button14");
    button14.disabled = true;
    var button15 = document.getElementById("button15");
    button15.disabled = true;
    var button16 = document.getElementById("button16");
    button16.disabled = true;
    
    var button18 = document.getElementById("button18");
    button18.disabled = true;
    var button19 = document.getElementById("button19");
    button19.disabled = true;
    var button20 = document.getElementById("button20");
    button20.disabled = true;
    var button21 = document.getElementById("button21");
    button21.disabled = true;
    var button22 = document.getElementById("button22");
    button22.disabled = true;
    var button23 = document.getElementById("button23");
    button23.disabled = true;
    var button24 = document.getElementById("button24");
    button24.disabled = true;
    var button25 = document.getElementById("button25");
    button25.disabled = true;
    var button27 = document.getElementById("button27");
    button27.disabled = true;
    var button28 = document.getElementById("button28");
    button28.disabled = true;
    var button29 = document.getElementById("button29");
    button29.disabled = true;
    var button30 = document.getElementById("button30");
    button30.disabled = true;
    var button31 = document.getElementById("button31");
    button31.disabled = true;
    var button32 = document.getElementById("button32");
    button32.disabled = true;
    var button33 = document.getElementById("button33");
    button33.disabled = true;
    var button34 = document.getElementById("button34");
    button34.disabled = true;
    var button35 = document.getElementById("button35");
    button35.disabled = true;
    var button36 = document.getElementById("button36");
    button36.disabled = true;
    var button37 = document.getElementById("button37");
    button37.disabled = true;
    var button38 = document.getElementById("button38");
    button38.disabled = true;
    var button39 = document.getElementById("button39");
    button39.disabled = true;
    var button40 = document.getElementById("button40");
    button40.disabled = true;
    var button41 = document.getElementById("button41");
    button41.disabled = true;
    var button42 = document.getElementById("button42");
    button42.disabled = true;
    var button43 = document.getElementById("button43");
    button43.disabled = true;
    var button46 = document.getElementById("button46");
    button46.disabled = true;
    var button47 = document.getElementById("button47");
    button47.disabled = true;
    var button48 = document.getElementById("button48");
    button48.disabled = true;
    var button49 = document.getElementById("button49");
    button49.disabled = true;
    var button50 = document.getElementById("button50");
    button50.disabled = true;
    var button51 = document.getElementById("button51");
    button51.disabled = true;
    var button52 = document.getElementById("button52");
    button52.disabled = true;
    var button53 = document.getElementById("button53");
    button53.disabled = true;
    var button54 = document.getElementById("button54");
    button54.disabled = true;
    var button55 = document.getElementById("button55");
    button55.disabled = true;
    var button56 = document.getElementById("button56");
    button56.disabled = true;
    var button58 = document.getElementById("button58");
    button58.disabled = true;
    var button59 = document.getElementById("button59");
    button59.disabled = true;
    var button60 = document.getElementById("button60");
    button60.disabled = true;
    var button61 = document.getElementById("button61");
    button61.disabled = true;
    var button62 = document.getElementById("button62");
    button62.disabled = true;
    var button63 = document.getElementById("button63");
    button63.disabled = true;
    var button66 = document.getElementById("button66");
    button66.disabled = true;
    var button67 = document.getElementById("button67");
    button67.disabled = true;
    var button68 = document.getElementById("button68");
    button68.disabled = true;
    var button69 = document.getElementById("button69");
    button69.disabled = true;
    var button70 = document.getElementById("button70");
    button70.disabled = true;
    var button71 = document.getElementById("button71");
    button71.disabled = true;
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
    var button78 = document.getElementById("button78");
    button78.disabled = true;
    var button79 = document.getElementById("button79");
    button79.disabled = true;
    var button80 = document.getElementById("button80");
    button80.disabled = true;
    var button81 = document.getElementById("button81");
    button81.disabled = true;
    var button82 = document.getElementById("button82");
    button82.disabled = true;
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

//api接口扫描
function urlfinderscanfunc() {
    $.ajax({
        url: '/starturlfinderinterface/',
        method: 'GET',
        success: function (info) {
            alert(info.urlfinder_status_result)
        },
        error: function () {
            alert('api接口扫描出错')
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
            console.log(res)
            console.log('资产回退成功点击文本查看最新数据')
        },
        error: function () {
            alert('资产回退出现错误')
        },
        complete: function () {
            alert('资产回退成功点击文本查看最新数据')
        }
    })
}

//weblogic_poc 扫描
function weblogicscanfunc() {
    $.ajax({
        url: '/weblogicscaninterface/',
        method: 'GET',

        success: function (res) {
            console.log(res)

        },
        error: function () {
            alert('weblogic_poc扫描出错')
        },
        complete: function () {

        }
    })
    $.getJSON("/weblogicscaninterface/",
        function (info) {
            alert(info.weblogic_status_result)
        })
}

//weblogic_poc报告预览
function weblogicreportfunc() {
    window.open("/weblogic_poc_report/", "_blank");
}


//ajax异步关闭weblogic漏洞扫描程序
function stopweblogicscanprocess() {
    $.ajax({
        url: '/stop_weblogic_poc_scan/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_weblogic_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

//struts2_poc报告预览
function struts2reportfunc() {
    window.open("/struts2_poc_report/", "_blank");
}


//struts2_poc 扫描
function struts2scanfunc() {
    $.ajax({
        url: '/struts2_poc_scan/',
        method: 'GET',

        success: function (info) {
            alert(info.struts2status_result)

        },
        error: function () {
            alert('struts2_poc扫描出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭struts2漏洞扫描程序
function stopstruts2scanprocess() {
    $.ajax({
        url: '/stop_struts2_poc_scan/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_struts2_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//报告整合
function reporttotalfunc() {
    $.ajax({
        url: '/report_total_interface/',
        method: 'GET',

        success: function () {

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('已完成整合点击报告下载进行预览')
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


//启动EHole
function eholefingerfunc() {
    $.ajax({
        url: '/ehole_finger_scan/',
        method: 'GET',

        success: function (info) {
            alert(info.finger_status_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//bbscan敏感信息扫描
function bbscaninfofunc() {
    $.ajax({
        url: '/bbscan_info_scan/',
        method: 'GET',

        success: function (info) {
            alert(info.bbscan_status_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

//bbscan报告预览
function showbbscanreportfunc() {
    window.open("/showbbscanreport/", "_blank");
}


//子域名结果预览
function showsubdomainfunc() {
    window.open("/showsubdomainreport/");
}



//子域名探测
function subdomainfindfunc() {
    $.ajax({
        url: '/batch_show_subdomain/',
        method: 'GET',

        success: function (info) {
            alert(info.crt_status_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

//vulmap漏扫报告预览
function vulmapscanreportfunc() {
    window.open("/vulmapscanreport/");
}


//启动vulmap漏扫接口
function startvulmapscanfunc() {
    var vulnname = $('select[name="vulnname"]').val();
    $.ajax({
        url: '/startvulmapinterface/',
        method: 'POST',
        data: {
            vulnname: vulnname
        },
        success: function (info) {
            alert(info.vummap_scan_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//批量端口扫描
function batchnmapportscanfunc() {
    $.ajax({
        url: '/startbatchnmapscan/',
        method: 'GET',

        success: function (info) {
            alert(info.nmap_status_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
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



    // // 定义一个函数来处理AJAX请求
    // function fetchData() {
    //     $.ajax({
    //         url: '/url_list_textarea_show/',
    //         method: 'GET',
    //         success: function (info) {
    //             // 假设info.textvalue是一个数组  
    //             var textAreaContent = ''; // 初始化一个空字符串来保存textarea的内容  

    //             // 遍历info.textvalue数组，为每个元素添加换行符并追加到textAreaContent  
    //             for (var i = 0; i < info.textvalue.length; i++) {
    //                 textAreaContent += info.textvalue[i] + '\n'; // 追加元素和换行符  
    //             }

    //             // 将textAreaContent的内容赋值给textarea  
    //             $('#myTextarea').val(textAreaContent); // 假设textarea的id是myTextarea  
    //         },
    //         error: function () {


    //         },
    //         complete: function () {

    //         }
    //     })
    // }

    // // 调用fetchData函数初始化显示
    // fetchData();
    // // 设置定时器，每5000毫秒（5秒）执行一次fetchData函数
    // var intervalId = setInterval(fetchData, 5000);
}

// 确保在页面卸载或组件销毁时清除定时器，以防止内存泄漏
window.addEventListener("beforeunload", function () {
    clearInterval(intervalId);
});





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

//ajax异步删除afrog报告
function deleteafrogreportfunc() {
    $.ajax({
        url: '/deleteafrogreport/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已删除afrog报告')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('已删除afrog报告')
        }
    })
}


//启动afrog漏扫接口
function startafrogfunc() {

    $.ajax({
        url: '/startafrogscanprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.start_afrog_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭afrog进程
function killafrogprocessfunc() {
    $.ajax({
        url: '/killafrogprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_afrog_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//fscan扫描结果预览
function fscanreprtfunc() {
    window.open("/fscanreportyulan/");
}

//批量fscan漏洞扫描
function batchfscanvulnfunc() {
    var fscanpartname = $('select[name="fscanpartname"]').val();
    $.ajax({
        url: '/startfcsaninterface/',
        method: 'POST',
        data: {
            fscanpartname: fscanpartname
        },
        success: function (info) {
            alert(info.fscan_status_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

// fscan扫描参数值查看
function fscanportshowfunc() {
    var fscanpartname = $('select[name="fscanpartname"]').val();
    $('#myTextarea2').val(fscanpartname);
}


//ajax异步关闭fscan进程
function killfscanprocessfunc() {
    $.ajax({
        url: '/killfscangprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_fscan_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//shiro扫描结果预览
function shiroscanreprtfunc() {
    window.open("/shiro_report_show/");
}


//shiro漏洞扫描
function batchshirovulnfunc() {
    $.ajax({
        url: '/startshirointerface/',
        method: 'GET',

        success: function (info) {
            alert(info.shiro_status_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭shiro漏洞扫描程序
function killshiroprocessfunc() {
    $.ajax({
        url: '/stop_shiro_poc_scan/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_shiro_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
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

//springboot漏洞扫描
function start_springboot_scan_func() {
    $.ajax({
        url: '/start_springboot_vuln_scan/',
        method: 'GET',

        success: function (info) {
            alert(info.springboot_scan_status_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭springboot漏洞扫描程序
function killspringbootprocessfunc() {
    $.ajax({
        url: '/stop_springboot_poc_scan/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_springboot_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

//ajax异步关闭nmap进程
function killnmapfunc() {
    $.ajax({
        url: '/killnmapprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_nmap_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}

//ajax异步关闭vulmap进程
function killvulmapfunc() {
    $.ajax({
        url: '/killvulmapprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_vulmap_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭nuclei进程
function killnucleifunc() {
    $.ajax({
        url: '/killnucleiprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_nuclei_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
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


// 启用hydra扫描
function start_hydra_scan_func() {
    var hydrapart = $('select[name="hydrapart"]').val();
    $.ajax({
        url: '/start_hydra_interface/',
        method: 'POST',
        data: {
            hydrapart: hydrapart
        },
        success: function (info) {
            // 当请求成功时调用  
            alert(info.hydra_scan_result);
        },
        error: function () {
            alert('接口内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭hydra进程
function killhydraprocessfunc() {
    $.ajax({
        url: '/killhydraprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_hydra_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭urlfinder进程
function killurlfinderprocessfunc() {
    $.ajax({
        url: '/killurlfinderprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_urlfinder_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//ajax异步关闭EHole进程
function killEHoleprocessfunc() {
    $.ajax({
        url: '/killEHoleprocess/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_EHole_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
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



// 关闭后端服务
function stopbackservicefunc() {
    $.ajax({
        url: '/stopbackserviceinterface/',
        method: 'GET',
        success: function (info) {
            // 参数1：确认操作
            // 参数2：取消操作
            if (confirm(info.backcomfirm)) {
                $.ajax({
                    url: '/confirm_stop_service/',
                    method: 'POST',
                    data: {
                        action: 1
                    },
                    success: function (info) {
                        alert(info.result_status)
                        window.location.href = "/index/";
                    },
                    error: function () {
                        alert('内部出错');
                    }
                });
            } else {

                $.ajax({
                    url: '/confirm_stop_service/',
                    method: 'POST',
                    data: {
                        action: 2
                    },
                    success: function (info) {
                        alert(info.result_status)
                        window.location.href = "/index/";
                    },
                    error: function () {
                        alert('内部出错');
                    }
                });

            }

        },
        // 关闭所有服务nginx会返回502
        error: function () {
            alert('内部出错')
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

function caozuo9cfunc() {
    setTimeout(function () {
        var tishisp9c = document.getElementById("tishisp9c");
        tishisp9c.style.display = "block";
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


//thinkphp漏洞扫描
function startthinkphpscanfunc() {
    $.ajax({
        url: '/starttpscaninterface/',
        method: 'GET',

        success: function (info) {
            alert(info.thinkphp_status_result)

        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


//thinkphp报告预览
function thinkphp_report_show_func() {

    window.open("/thinkphp_poc_report/");
}


//ajax异步关闭thinkphp漏洞扫描程序
function killthinkphpprocessfunc() {
    $.ajax({
        url: '/stop_thinkphp_poc_scan/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_thinkphp_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
}


// 漏洞扫描工具集合
function xianshipointfunc() {
    var pointid1 = document.getElementById("pointid1");
    pointid1.style.display = "block";

    var spanpointvalue = $('select[name="spanpointvalue"]').val();
    if (spanpointvalue == 1) {

        var point1 = document.getElementById("point1");
        point1.style.display = "block";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";

    } else if (spanpointvalue == 2) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "block";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";

    } else if (spanpointvalue == 3) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "block";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";

    } else if (spanpointvalue == 4) {

        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "block";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 6) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "block";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";

    } else if (spanpointvalue == 7) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "block";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 8) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "block";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 9) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "block";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 10) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "block";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 11) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 12) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "block";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 13) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "block";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 5) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "block";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "none";
    } else if (spanpointvalue == 15) {
        var point1 = document.getElementById("point1");
        point1.style.display = "none";
        var point2 = document.getElementById("point2");
        point2.style.display = "none";
        var point3 = document.getElementById("point3");
        point3.style.display = "none";
        var point4 = document.getElementById("point4");
        point4.style.display = "none";
        var point5 = document.getElementById("point5");
        point5.style.display = "none";
        var point6 = document.getElementById("point6");
        point6.style.display = "none";
        var point7 = document.getElementById("point7");
        point7.style.display = "none";
        var point8 = document.getElementById("point8");
        point8.style.display = "none";
        var point9 = document.getElementById("point9");
        point9.style.display = "none";
        var point10 = document.getElementById("point10");
        point10.style.display = "none";
        var point12 = document.getElementById("point12");
        point12.style.display = "none";
        var point13 = document.getElementById("point13");
        point13.style.display = "none";
        var point15 = document.getElementById("point15");
        point15.style.display = "block";
    }
}


function guanbipointfunc() {
    // 将select选项值重置
    var spanpointvalue = document.querySelector('select[name="spanpointvalue"]');
    spanpointvalue.selectedIndex = 0; // 将第一个选项设置为选中状态

    var point1 = document.getElementById("point1");
    point1.style.display = "block";
    var point2 = document.getElementById("point2");
    point2.style.display = "none";
    var point3 = document.getElementById("point3");
    point3.style.display = "none";
    var point4 = document.getElementById("point4");
    point4.style.display = "none";
    var point5 = document.getElementById("point5");
    point5.style.display = "none";
    var point6 = document.getElementById("point6");
    point6.style.display = "none";
    var point7 = document.getElementById("point7");
    point7.style.display = "none";
    var point8 = document.getElementById("point8");
    point8.style.display = "none";
    var point9 = document.getElementById("point9");
    point9.style.display = "none";
    var point10 = document.getElementById("point10");
    point10.style.display = "none";
    var point12 = document.getElementById("point12");
    point12.style.display = "none";
    var point13 = document.getElementById("point13");
    point13.style.display = "none";
    var point15 = document.getElementById("point15");
    point15.style.display = "none";
}


// 打开信息收集工具集合
function infoshoujitoolstart() {
    var spaninfomationname = $('select[name="spaninfomationname"]').val();
    if (spaninfomationname == 1) {
        var infoscanspan1 = document.getElementById("infoscanspan1");
        infoscanspan1.style.display = "block";
        var infoscanspan2 = document.getElementById("infoscanspan2");
        infoscanspan2.style.display = "none";
        var infoscanspan3 = document.getElementById("infoscanspan3");
        infoscanspan3.style.display = "none";
        var infoscanspan4 = document.getElementById("infoscanspan4");
        infoscanspan4.style.display = "none";
        var infoscanspan5 = document.getElementById("infoscanspan5");
        infoscanspan5.style.display = "none";
    } else if (spaninfomationname == 2) {
        var infoscanspan1 = document.getElementById("infoscanspan1");
        infoscanspan1.style.display = "none";
        var infoscanspan2 = document.getElementById("infoscanspan2");
        infoscanspan2.style.display = "block";
        var infoscanspan3 = document.getElementById("infoscanspan3");
        infoscanspan3.style.display = "none";
        var infoscanspan4 = document.getElementById("infoscanspan4");
        infoscanspan4.style.display = "none";
        var infoscanspan5 = document.getElementById("infoscanspan5");
        infoscanspan5.style.display = "none";
    } else if (spaninfomationname == 3) {
        var infoscanspan1 = document.getElementById("infoscanspan1");
        infoscanspan1.style.display = "none";
        var infoscanspan2 = document.getElementById("infoscanspan2");
        infoscanspan2.style.display = "none";
        var infoscanspan3 = document.getElementById("infoscanspan3");
        infoscanspan3.style.display = "block";
        var infoscanspan4 = document.getElementById("infoscanspan4");
        infoscanspan4.style.display = "none";
        var infoscanspan5 = document.getElementById("infoscanspan5");
        infoscanspan5.style.display = "none";
    } else if (spaninfomationname == 4) {
        var infoscanspan1 = document.getElementById("infoscanspan1");
        infoscanspan1.style.display = "none";
        var infoscanspan2 = document.getElementById("infoscanspan2");
        infoscanspan2.style.display = "none";
        var infoscanspan3 = document.getElementById("infoscanspan3");
        infoscanspan3.style.display = "none";
        var infoscanspan4 = document.getElementById("infoscanspan4");
        infoscanspan4.style.display = "block";
        var infoscanspan5 = document.getElementById("infoscanspan5");
        infoscanspan5.style.display = "none";
    } else if (spaninfomationname == 5) {
        var infoscanspan1 = document.getElementById("infoscanspan1");
        infoscanspan1.style.display = "none";
        var infoscanspan2 = document.getElementById("infoscanspan2");
        infoscanspan2.style.display = "none";
        var infoscanspan3 = document.getElementById("infoscanspan3");
        infoscanspan3.style.display = "none";
        var infoscanspan4 = document.getElementById("infoscanspan4");
        infoscanspan4.style.display = "none";
        var infoscanspan5 = document.getElementById("infoscanspan5");
        infoscanspan5.style.display = "block";
    }
}

// 关闭信息收集工具集合
function infoshoujitoolstop() {
    // 将select选项值重置
    var selectElement = document.querySelector('select[name="spaninfomationname"]');
    selectElement.selectedIndex = 0; // 将第一个选项设置为选中状态
    var infoscanspan1 = document.getElementById("infoscanspan1");
    infoscanspan1.style.display = "block";
    var infoscanspan2 = document.getElementById("infoscanspan2");
    infoscanspan2.style.display = "none";
    var infoscanspan3 = document.getElementById("infoscanspan3");
    infoscanspan3.style.display = "none";
    var infoscanspan4 = document.getElementById("infoscanspan4");
    infoscanspan4.style.display = "none";
    var infoscanspan5 = document.getElementById("infoscanspan5");
    infoscanspan5.style.display = "none";
}



//ajax异步开启泛微OA漏洞扫描
function startweaverscanfunc() {
    $.ajax({
        url: '/startweavervulnscan/',
        method: 'GET',
        success: function (info) {
            alert(info.weaver_status_result)
        },
        error: function () {
            alert('内部出错')

        },
        complete: function () {

        }
    })

}


//weaver扫描结果预览
function weaverscanfunc() {

    window.open("/weaverresultshow/");
}


//ajax异步关闭泛微OA漏洞扫描程序
function killweaverscanfunc() {
    $.ajax({
        url: '/killweavervulnscan/',
        method: 'GET',
        success: function (info) {
            alert(info.kill_weaver_result)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {

        }
    })
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
            alert(info.struts2status_result + "\n" + info.weblogic_status_result + "\n" + info.shiro_status_result + "\n" + info.springboot_scan_status_result + "\n" + info.thinkphp_status_result + "\n" + info.start_afrog_result + "\n" + info.fscan_status_result + "\n" + info.hydra_scan_result + "\n" + info.urlfinder_status_result + "\n" + info.vummap_scan_result + "\n" + info.nuclei_status_result + "\n" + info.weaver_status_result + "\n" + info.point_all_result + "\n" + info.es_status_result + "\n" + info.nacos_status_result + "\n" + info.tomcat_status_result + "\n" + info.jndi_status_result + "\n" + info.fastjson_status_result + "\n" + info.xray_status_result)
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
            alert(info.kill_struts2_result + "\n" + info.kill_weblogic_result + "\n" + info.kill_shiro_result + "\n" + info.kill_springboot_result + "\n" + info.kill_thinkphp_result + "\n" + info.kill_afrog_result + "\n" + info.kill_fscan_result + "\n" + info.kill_hydra_result + "\n" + info.kill_urlfinder_result + "\n" + info.kill_vulmap_result + "\n" + info.kill_nuclei_result + "\n" + info.kill_weaver_result + "\n" + info.kill_point_assset_result + "\n" + info.kill_es_result + "\n" + info.kill_nacos_result + "\n" + info.kill_tomcat_result + "\n" + info.kill_jndi_result + "\n" + info.kill_fastjson_result)
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
        data: JSON.stringify({ line_mysqltextarea1: line_mysqltextarea1, line_mysqltextarea2:line_mysqltextarea2,line_sshtextarea1:line_sshtextarea1, line_sshtextarea2:line_sshtextarea2,line_ftptextarea1:line_ftptextarea1,line_ftptextarea2:line_ftptextarea2,line_redistextarea2:line_redistextarea2,line_mssqltextarea1:line_mssqltextarea1,line_mssqltextarea2:line_mssqltextarea2,line_tomcattextarea1:line_tomcattextarea1,line_tomcattextarea2:line_tomcattextarea2,line_nacostextarea1:line_nacostextarea1,line_nacostextarea2:line_nacostextarea2}),
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


// 资产文本框鼠标悬停变大
function textarea_onhover(){
    var textarea = document.getElementById('myTextarea');
    textarea.rows = 20;
    textarea.cols = 152;
}
// 资产文本框鼠标移出变小
function textarea_onout(){
    var textarea = document.getElementById('myTextarea');
    textarea.rows = 2;
    textarea.cols = 152;
}
