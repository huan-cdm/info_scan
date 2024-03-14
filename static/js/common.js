
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
            alert(info.nmapstatus + '\n' + info.nucleistatus + '\n' + info.xraystatus + '\n' + info.radstatus+'\n'+info.dirscanstatus)
        })
}



//xray报告预览
function xrayreportshow() {
    window.open("http://121.37.207.248:18888/", "_blank");
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
        url: '/submit_data',
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

    inputUrls.forEach(function(url) {
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
    window.open("https://web.archive.org/cdx/search?collapse=urlkey&fl=original&limit=10000000000000000&matchType=domain&output=text&url="+inputValue, "_blank");
}


//启用按钮
function startbutton(){
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
}

//禁用按钮
function stopbutton(){
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
            console.log('数据处理已完成')
        },
        error: function () {
            alert('数据处理出错')
        },
        complete: function () {
            alert('数据处理已完成')
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