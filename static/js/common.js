
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
            alert('出现内部错误')
        },
        complete: function () {
            alert('已删除端口扫描报告')
        }
    })
}



//xray报告预览
function xrayreportshow() {
    window.open("http://x.x.x.x:18888/", "_blank");
}


//urlfinder报告预览
function urlfinderreportshow() {
    window.open("http://x.x.x.x:16666/", "_blank");
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
            alert('出现内部错误')
        },
        complete: function () {
            alert('已删除xray报告')
        }
    })
}


//ajax异步删除链接扫描报告
function deleteurlfinderreportfunc() {
    $.ajax({
        url: '/deleteurlfinderreport/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已删除链接报告')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已删除链接报告')
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
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭xray和rad引擎')
        }
    })
}


//ajax异步发送textarea的值
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
        success: function (res) {
            console.log(res)
            console.log('URL添加成功点击文本查看是否添加成功')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('URL添加成功点击文本框查看是否添加成功')
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
        success: function (res) {
            console.log(res)
            
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
           
        }
    })

    $.getJSON("/startnuclei/",
        function (info) {
            alert(info.nuclei_status_result)
    })
}


//ajax异步查看历史url
function historyurlfunc() {
    $.ajax({
        url: '/historyshow/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('正在调用威胁情报网站OTX查询稍后点击OTX预览查看结果')
        },
        error: function () {
            alert('出现内部错误')

        },
        complete: function () {
            alert('正在调用威胁情报网站OTX查询稍后点击OTX预览查看结果')
        }
    })

}


//历史url预览
function historyurlpreviewfunc() {

    window.open("/previewhistoryurl/");
}


//文本框内容展示
function textinfoshowfunc() {
    $.ajax({
        url: '/textareashowinterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)

        },
        error: function () {


        },
        complete: function () {

        }
    })

    $.getJSON("/textareashowinterface/",
        function (info) {
            $('#opbyid3').empty();
            for (var i = 0; i < info.textvalue.length; i++) {
                $('#opbyid3').append('<option>' + info.textvalue[i] + '</option><br>');
            }
            document.getElementById("span1").innerHTML = info.url_num;
        })

}


//xray报告预览
function uniqdirfunc() {
    window.open("/pathuniqpage/", "_blank");
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
    var button4 = document.getElementById("button4");
    button4.disabled = false;

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
    var button17 = document.getElementById("button17");
    button17.disabled = false;
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
    var button44 = document.getElementById("button44");
    button44.disabled = false;
    var button45 = document.getElementById("button45");
    button45.disabled = false;
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
    var button57 = document.getElementById("button57");
    button57.disabled = false;
    var button58 = document.getElementById("button58");
    button58.disabled = false;


}

//禁用按钮
function stopbutton() {
    var button2 = document.getElementById("button2");
    button2.disabled = true;
    var button3 = document.getElementById("button3");
    button3.disabled = true;
    var button4 = document.getElementById("button4");
    button4.disabled = true;
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
    var button17 = document.getElementById("button17");
    button17.disabled = true;
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
    var button44 = document.getElementById("button44");
    button44.disabled = true;
    var button45 = document.getElementById("button45");
    button45.disabled = true;
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
    var button57 = document.getElementById("button57");
    button57.disabled = true;
    var button58 = document.getElementById("button58");
    button58.disabled = true;
}


//跳转到目录扫描页面
function jumpdirscanpage() {
    window.open("http://x.x.x.x:17777/dirscanpage/", "_blank");
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

        success: function (res) {
            console.log(res)
            console.log('存活检测成功点击文本查看最新数据')
        },
        error: function () {
            alert('存活检测出现错误')
        },
        complete: function () {
            alert('存活检测成功点击文本查看最新数据')
        }
    })
}

//链接扫描
function urlfinderscanfunc() {
    $.ajax({
        url: '/starturlfinderinterface/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            console.log('正在进行链接扫描稍后点击报告预览查看报告')
        },
        error: function () {
            alert('链接扫描出错')
        },
        complete: function () {
            alert('正在进行链接扫描稍后点击报告预览查看报告')
        }
    })
}

//ajax异步启动注销系统
function signoutfunc() {
    $.ajax({
        url: '/signout/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已注销系统')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已注销系统')
        }
    })
    window.location.href = "/index/";
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

//一键处理
// function oneclickprocessing() {
//     var button19 = document.getElementById("button19");
//     var button20 = document.getElementById("button20");
//     var button24 = document.getElementById("button24");
//     var button17 = document.getElementById("button17");

//     button19.disabled = false;
//     button20.disabled = false;
//     button24.disabled = false;
//     button17.disabled = false;
//     // 定义一个函数来模拟点击并安排下一次点击（如果有的话）  
//     function simulateClickAndSleep(buttons, index, interval) {
//         // 如果索引在按钮数组范围内，则模拟点击并安排下一次点击  
//         if (index < buttons.length) {
//             // 模拟点击当前按钮  
//             buttons[index].click();
//             console.log('Clicked button ' + (index + 1));

//             // 休眠interval毫秒后，安排下一次点击  
//             setTimeout(function () {
//                 simulateClickAndSleep(buttons, index + 1, interval);
//             }, interval);
//         }
//     }

//     // 开始模拟点击，从第一个按钮开始，每次点击后休眠10000毫秒（10秒）  
//     var buttonsToClick = [button20, button24, button19, button17];
//     simulateClickAndSleep(buttonsToClick, 0, 10000); // 第一个参数是按钮数组，第二个参数是开始索引，第三个参数是休眠时间（毫秒）
// }


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

//struts2_poc报告预览
function struts2reportfunc() {
    window.open("/struts2_poc_report/", "_blank");
}


//struts2_poc 扫描
function struts2scanfunc() {
    $.ajax({
        url: '/struts2_poc_scan/',
        method: 'GET',

        success: function (res) {
            console.log(res)
           
        },
        error: function () {
            alert('struts2_poc扫描出错')
        },
        complete: function () {
           
        }
    })
    $.getJSON("/struts2_poc_scan/",
        function (info) {
            alert(info.struts2status_result)
    })
}

//报告整合
function reporttotalfunc() {
    $.ajax({
        url: '/report_total_interface/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            console.log('报告已整合到excel中，点击下载报告进行查看')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('报告已整合到excel中，点击下载报告进行查看')
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


//ehole_finger 扫描
function eholefingerfunc() {
    $.ajax({
        url: '/ehole_finger_scan/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
           
        }
    })
    
    $.getJSON("/ehole_finger_scan/",
        function (info) {
            alert(info.finger_status_result)
    })
}


//bbscan敏感信息扫描
function bbscaninfofunc() {
    $.ajax({
        url: '/bbscan_info_scan/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            
        }
    })
    $.getJSON("/bbscan_info_scan/",
        function (info) {
            alert(info.bbscan_status_result)
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

        success: function (res) {
            console.log(res)
            console.log('子域名探测已开启稍后查看结果')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('子域名探测已开启稍后查看结果')
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
    alert(vulnname)
    $.ajax({
        url: '/startvulmapinterface/',
        method: 'POST',
        data: {
            vulnname: vulnname
        },
        success: function (res) {
            console.log(res)
            console.log('vulmap漏扫程序已启动稍后查看扫描结果')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('vulmap漏扫程序已启动稍后查看扫描结果')
        }
    })
}


//批量端口扫描
function batchnmapportscanfunc() {
    $.ajax({
        url: '/startbatchnmapscan/',
        method: 'GET',

        success: function (res) {
            console.log(res)
           
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
           
        }
    })

    $.getJSON("/startbatchnmapscan/",
        function (info) {
            alert(info.nmap_status_result)
    })
}


//目标url的值赋值给 textarea 文本框
function targeturlcopytextareafunc() {
    $.ajax({
        url: '/url_list_textarea_show/',
        method: 'GET',
        success: function (res) {
            console.log(res)

        },
        error: function () {


        },
        complete: function () {

        }
    })

    $.getJSON("/url_list_textarea_show/", function (info) {  
        // 假设info.textvalue是一个数组  
        var textAreaContent = ''; // 初始化一个空字符串来保存textarea的内容  
      
        // 遍历info.textvalue数组，为每个元素添加换行符并追加到textAreaContent  
        for (var i = 0; i < info.textvalue.length; i++) {  
            textAreaContent += info.textvalue[i] + '\n'; // 追加元素和换行符  
        }  
      
        // 将textAreaContent的内容赋值给textarea  
        $('#myTextarea').val(textAreaContent); // 假设textarea的id是myTextarea  
       
    });

}


//afrog报告预览
function afrogreportfun() {
    window.open("http://x.x.x.x:15555/", "_blank");
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
            alert('出现内部错误')
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
        success: function (res) {
            console.log(res)
            console.log('afrog漏扫程序已启动稍后查看扫描结果')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('afrog漏扫程序已启动稍后查看扫描结果')
        }
    })
}


//ajax异步关闭afrog进程
function killafrogprocessfunc() {
    $.ajax({
        url: '/killafrogprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭afrog进程')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭afrog进程')
        }
    })
}


//fscan扫描结果预览
function fscanreprtfunc() {
    window.open("/fscanreportyulan/");
}

//批量fscan漏洞扫描
function batchfscanvulnfunc() {
    $.ajax({
        url: '/startfcsaninterface/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            console.log('fscan漏扫程序已启动稍后查看结果')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('fscan漏扫程序已启动稍后查看结果')
        }
    })
}


//ajax异步关闭fscan进程
function killfscanprocessfunc() {
    $.ajax({
        url: '/killfscangprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭fscan进程')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭fscan进程')
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

        success: function (res) {
            console.log(res)
        
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            
        }
    })
    $.getJSON("/startshirointerface/",
        function (info) {
            alert(info.shiro_status_result)
    })
}


//识别重点资产
function key_data_tiqu_func() {
    $.ajax({
        url: '/key_assets_withdraw/',
        method: 'GET',

        success: function (res) {
            console.log(res)
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
           
        }
    })
    $.getJSON("/key_assets_withdraw/",
        function (info) {
            alert(info.key_assets_result)
    })
}


// 系统管理
function openModal() {  
    var modal = document.getElementById("modal");  
    modal.style.display = "block";
    $.getJSON("/systemmanagement/",
    function (info) {
        document.getElementById("spp1").innerHTML = info.nmapstatus;
        document.getElementById("spp2").innerHTML = info.nucleistatus;
        document.getElementById("spp3").innerHTML = info.xraystatus;
        document.getElementById("spp4").innerHTML = info.radstatus;
        document.getElementById("spp5").innerHTML = info.dirscanstatus;
        document.getElementById("spp6").innerHTML = info.weblogicstatus;
        document.getElementById("spp7").innerHTML = info.struts2status;
        document.getElementById("spp8").innerHTML = info.bbscanstatus;
        document.getElementById("spp9").innerHTML = info.vulmapscanstatus;
        document.getElementById("spp10").innerHTML = info.afrogscanstatus;
        document.getElementById("spp11").innerHTML = info.fscanstatus;
        document.getElementById("spp12").innerHTML = info.shirostatus;
        document.getElementById("spp13").innerHTML = info.httpxstatus;
        document.getElementById("spp14").innerHTML = info.url_file_num;
        document.getElementById("spp15").innerHTML = info.eholestatus;
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
        document.getElementById("spp28").innerHTML = info.springbootstatus;
    })

}  
  
// 关闭系统管理
function closeModal() {  
    var modal = document.getElementById("modal");  
    modal.style.display = "none";  
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
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {
        }
    })

    $.getJSON("/nuclei_poc_show_ajax/",
        function (info) {
            $('#nucleibyid1').empty();
            for (var i = 0; i < info.nuclei_poc_list_global.length; i++) {
                $('#nucleibyid1').append('<option>' + info.nuclei_poc_list_global[i] + '</option><br>');
            }
            document.getElementById("nucleibyid2").innerHTML = info.nuclei_poc_list_len;
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

        success: function (res) {
            console.log(res)
           
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
           
        }
    })
    $.getJSON("/start_springboot_vuln_scan/",
        function (info) {
            alert(info.springboot_scan_status_result)
    })
}


//ajax异步关闭nmap进程
function killnmapfunc() {
    $.ajax({
        url: '/killnmapprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭端口扫描程序')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭端口扫描程序')
        }
    })
}

//ajax异步关闭vulmap进程
function killvulmapfunc() {
    $.ajax({
        url: '/killvulmapprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭vulmap扫描程序')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭vulmap扫描程序')
        }
    })
}


//ajax异步关闭nuclei进程
function killnucleifunc() {
    $.ajax({
        url: '/killnucleiprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭nuclei扫描程序')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭nuclei扫描程序')
        }
    })
}


//ajax异步关闭bbscan进程
function killbbscanfunc() {
    $.ajax({
        url: '/killbbscanprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭bbscan扫描程序')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已关闭bbscan扫描程序')
        }
    })
}
