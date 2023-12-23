
function fanhui() {
    var input = document.getElementById("myInput");
    input.value = "";
    window.location.href = "/index/";
}



//nuclei扫描结果预览
function nmapjumpfunc() {
    var input = document.getElementById("myInput");
    input.value = "";
    window.open("/nmapresultshow/");
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
            console.log('已清空端口扫描数据')
        },
        error: function () {
            alert('出现内部错误')
        },
        complete: function () {
            alert('已清空端口扫描数据')
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
        alert(info.nmapstatus)
    })
}