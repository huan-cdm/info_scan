
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
            console.log('已清空nmap和nuclei扫描文件')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已清空nmap和nuclei扫描文件')
        }
    })
}


//ajax异步查询队列状态
function statusnmapfunc() {
    $.ajax({
        url: '/nmapqueuestatus/',
        method: 'GET',
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {

        }
    })
    $.getJSON("/nmapqueuestatus/",
        function (info) {
            alert(info.nmapstatus + '\n' + info.nucleistatus + '\n' + info.xraystatus + '\n' + info.radstatus + '\n' + info.dirscanstatus+ '\n' + info.weblogicstatus+ '\n' +info.struts2status)
        })
}



//xray报告预览
function xrayreportshow() {
    window.open("http://121.37.207.248:18888/", "_blank");
}


//urlfinder报告预览
function urlfinderreportshow() {
    window.open("http://121.37.207.248:16666/", "_blank");
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



//ajax异步结束xray和rad引擎进程
function killxrayandradfunc() {
    $.ajax({
        url: '/killprocess/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已结束xray和rad引擎')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已结束xray和rad引擎')
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
    $.ajax({
        url: '/startnuclei/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已启动nuclei扫描')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已启动nuclei扫描')
        }
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

}


//跳转到目录扫描页面
function jumpdirscanpage() {
    window.open("http://121.37.207.248:17777/dirscanpage/", "_blank");
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
function oneclickprocessing() {
    var button19 = document.getElementById("button19");
    var button20 = document.getElementById("button20");
    var button24 = document.getElementById("button24");
    var button17 = document.getElementById("button17");

    button19.disabled = false;
    button20.disabled = false;
    button24.disabled = false;
    button17.disabled = false;
    // 定义一个函数来模拟点击并安排下一次点击（如果有的话）  
    function simulateClickAndSleep(buttons, index, interval) {
        // 如果索引在按钮数组范围内，则模拟点击并安排下一次点击  
        if (index < buttons.length) {
            // 模拟点击当前按钮  
            buttons[index].click();
            console.log('Clicked button ' + (index + 1));

            // 休眠interval毫秒后，安排下一次点击  
            setTimeout(function () {
                simulateClickAndSleep(buttons, index + 1, interval);
            }, interval);
        }
    }

    // 开始模拟点击，从第一个按钮开始，每次点击后休眠10000毫秒（10秒）  
    var buttonsToClick = [button20, button24, button19, button17];
    simulateClickAndSleep(buttonsToClick, 0, 10000); // 第一个参数是按钮数组，第二个参数是开始索引，第三个参数是休眠时间（毫秒）
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
            console.log('weblogic_poc扫描已开启稍后查看结果')
        },
        error: function () {
            alert('weblogic_poc扫描出错')
        },
        complete: function () {
            alert('weblogic_poc扫描已开启稍后查看结果')
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


//struts2_poc 扫描
function struts2scanfunc() {
    $.ajax({
        url: '/struts2_poc_scan/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            console.log('struts2_poc扫描已开启稍后查看结果')
        },
        error: function () {
            alert('struts2_poc扫描出错')
        },
        complete: function () {
            alert('struts2_poc扫描已开启稍后查看结果')
        }
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
            console.log('指纹识别已开启稍后查看结果')
        },
        error: function () {
            alert('内部出错')
        },
        complete: function () {
            alert('指纹识别已开启稍后查看结果')
        }
    })
}