
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
            alert(info.nmapstatus + '\n' + info.nucleistatus + '\n' + info.xraystatus + '\n' + info.radstatus)
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
            console.log('URL添加成功')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('URL添加成功')
        }
    });  
}

//启动xray和rad提示
function startradandxray() {
   alert("进入命令行分别开启xray和rad"+"\n"+"启动rad：python3 /TIP/batch_scan_domain/radscan.py"+"\n"+
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