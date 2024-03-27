//nuclei查看模板文件
function nucleishowtemplatefunc() {
    var obj = document.getElementById("nucleu_value_name_id"); //定位id
    var index = obj.selectedIndex; // 选中索引
    var text = obj.options[index].text; // 选中文本
    var oper_nucleu_value_name = obj.options[index].value; // 选中值

    $.ajax({
        url: '/templatenucleishowinterface/',
        method: 'POST',
        data: {
            oper_nucleu_value_name: oper_nucleu_value_name
        },
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {
        }
    })

    $.getJSON("/templatenucleishowbyajaxinterface/",
        function (info) {
            $('#nucleibyid1').empty();
            for (var i = 0; i < info.nuclei_result_list_1.length; i++) {
                $('#nucleibyid1').append('<option>' + info.nuclei_result_list_1[i] + '</option><br>');
            }
            document.getElementById("nucleibyid2").innerHTML = info.nuclei_length;
        })

}




//ajax异步启动Nuclei
function startnucleiserverfunc() {
    var nucleu_value_name = $('select[name="nucleu_value_name"]').val();
    $.ajax({
        url: '/startnucleiinterface/',
        method: 'POST',
        data: {
            nucleu_value_name: nucleu_value_name
        },
        success: function (res) {
            console.log(res)
            console.log('Nuclei服务正在启动中......')
        },
        error: function () {
            alert('Nuclei服务启动出错')
        },
        complete: function () {
            alert('Nuclei服务正在启动中......')
        }
    })
}




//ajax异步关闭nuclei进程
function stopnucleiprocessunc() {

    $.ajax({
        url: '/stopnucleiprocessinterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('已关闭Nuclei进程')
        },
        error: function () {
            alert('关闭Nuclei进程出错')
        },
        complete: function () {
            alert('已关闭Nuclei进程')
        }
    })
}


//扫描前黑名单批量添加
function scanbeforebatchinsert() {
    
    // 获取所有的复选框元素
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');

    // 创建一个空数组，用于存储选中的值
    const selectedValues = [];

    // 遍历复选框元素
    checkboxes.forEach((checkbox) => {
        // 判断复选框是否被选中
        if (checkbox.checked) {
            // 如果被选中，则将值添加到数组中
            selectedValues.push(checkbox.value);
        }
    });
    var jsonData = JSON.stringify(selectedValues);

    //将复选框选中的数组传递给后端
    $.ajax({
        url: '/scanbeforeinsertinterface/',
        method: 'POST',
        data: jsonData,
        dataType: "json",
        contentType: "application/json",
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {
        }
    })

    $.getJSON("/scanbeforeinsertinterfacebyajax/",
        function (info) {
            alert(info.insert_data_list_result);
    })
}


//扫描后黑名单批量添加
function scanafterbatchinsert() {
    // 获取所有的复选框元素
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');

    // 创建一个空数组，用于存储选中的值
    const selectedValues = [];

    // 遍历复选框元素
    checkboxes.forEach((checkbox) => {
        // 判断复选框是否被选中
        if (checkbox.checked) {
            // 如果被选中，则将值添加到数组中
            selectedValues.push(checkbox.value);
        }
    });
    var jsonData = JSON.stringify(selectedValues);

    //将复选框选中的数组传递给后端
    $.ajax({
        url: '/scanafterinsertinterface/',
        method: 'POST',
        data: jsonData,
        dataType: "json",
        contentType: "application/json",
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {
        }
    })

    $.getJSON("/scanafterinsertinterfacebyajax/",
        function (info) {
            alert(info.insert_after_data_list_result);
        })
}



//扫描后黑名单添加
function blacklistaddition(value) {
    var regex = /^(\w+):\/\/([^:/]+)(:\d+)?/;
    var match = value.match(regex);
    var keyvalue = match[0]

    $.ajax({
        url: '/filterdirsearch/',
        method: 'POST',
        data: {
            keyvalue: keyvalue
        },
        success: function (res) {
            console.log(res)

        },
        error: function () {

        },
        complete: function () {

        }
    })

    $.getJSON("/showdirsearchstatusinterfaceajax/",
        function (info) {
            alert(info.dirsearch_vuln_url_message)
        })

}





//扫描前黑名单添加
function beforeblacklistaddition(value) {
    var regex = /^(\w+):\/\/([^:/]+)(:\d+)?/;
    var match = value.match(regex);
    var vulnurl = match[0]

    $.ajax({
        url: '/addvulnurlinterface/',
        method: 'POST',
        data: {
            vulnurl: vulnurl
        },
        success: function (res) {
            console.log(res)

        },
        error: function () {

        },
        complete: function () {

        }
    })

    $.getJSON("/showmuluscanstausbyajax/",
        function (info) {
            alert(info.vuln_url_message_show)
        })

}




function hideRow(element) {
    element.parentElement.classList.add('hidden');
}




//nuclei扫描结果预览
function nucleijumpfunc(value) {
    window.open("/nucleifileshowinterface/");
}


//dirsearch扫描结果预览
function dirsearchresultshowfunc(value) {
    window.open("/dirsearchresultshowinterface/")
}


//dirsearch扫描目标预览
function dirsearchtargetshowfunc(value) {
    window.open("/dirsearchtargetfileshowinterface/")
}



//ajax异步目标文件去重
function uniqfofabatchfunc() {
    $.ajax({
        url: '/uniqbatchfofainterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('文件去重成功')
        },
        error: function () {
            alert('文件去重出错')
        },
        complete: function () {
            alert('文件去重完成')
        }
    })
}



//ajax异步隐藏漏洞
function vulndisplaystopfunc() {
    document.getElementById('divvulmapid11').style.display = "none";
}



//ajax异步隐藏漏洞数量
function stopvulmapcountfunc() {
    document.getElementById('divvulmapid').style.display = "none";
}




//ajax异步文本重命名
function textrenamefunc() {

    $.ajax({
        url: '/textrenameinterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('文本文件转换成功')
        },
        error: function () {
            alert('文本文件转换出错')
        },
        complete: function () {
            alert('文本文件转换完成')
        }
    })
}




//ajax异步临时文件复制
function copydirsearchtmpinterfacefunc() {

    $.ajax({
        url: '/copydirsearchtmpinterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('文件复制成功')
        },
        error: function () {
            alert('文件复制出错')
        },
        complete: function () {
            alert('文件复制完成')
        }
    })
}




//黑名单列表选中后给input框删除使用
function opbyid3func() {
    var obj = document.getElementById('opbyid3'); //定位id
    var index = obj.selectedIndex; // 选中索引
    var text = obj.options[index].text; // 选中文本
    var value = obj.options[index].value; // 选中值
    var valuename = document.getElementById("input1");
    valuename.value = value;
}




//黑名单扫描后列表选中后给input框删除使用
function opbyid6func() {
    var obj = document.getElementById('opbyid6'); //定位id
    var index = obj.selectedIndex; // 选中索引
    var text = obj.options[index].text; // 选中文本
    var value = obj.options[index].value; // 选中值
    var valuename = document.getElementById("input6");
    valuename.value = value;
}



//白名单列表选中后给input框删除使用
function opbyid4func() {
    var obj = document.getElementById('opbyid4'); //定位id
    var index = obj.selectedIndex; // 选中索引
    var text = obj.options[index].text; // 选中文本
    var value = obj.options[index].value; // 选中值
    var valuename = document.getElementById("input2");
    valuename.value = value;
}




//漏洞扫描日志展示下拉列表数据传给input框删除使用
function logselectvaluefunc() {
    var obj = document.getElementById('logoperid1'); //定位id
    var index = obj.selectedIndex; // 选中索引
    var text = obj.options[index].text; // 选中文本
    var value = obj.options[index].value; // 选中值
    var valuename = document.getElementById("inputlog1");
    valuename.value = value;
}





//ajax异步清除数据
function vulmapclearcachefunc() {

    $.ajax({
        url: '/vulmapscanclearcacheinterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('缓存清空成功')
        },
        error: function () {
            alert('缓存清空出错')
        },
        complete: function () {
            alert('缓存清空完成')
        }
    })
}




//ajax异步清空列表
function cleardirvulmaptargetfunc() {

    $.ajax({
        url: '/cleardirvulmaptarget/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('列表已清空点击原始数据同步最新数据')
        },
        error: function () {
            alert('列表清空出现错误')
        },
        complete: function () {
            alert('列表已清空点击原始数据同步最新数据')
        }
    })
}



//ajax异步清空原始数据
function origindataclearfunc() {

    $.ajax({
        url: '/origindataclearinterface/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('原始数据已删除')
        },
        error: function () {
            alert('原始数据删除出错')
        },
        complete: function () {
            alert('原始数据已删除')
        }
    })
}



//异步公司名称查询处理前数据
function generatereportfunc122(url_value) {
    alert(url_value)
    $.ajax({
        url: '/dirscancompanyshowinterface/',
        method: 'POST',
        data: {
            url_value: url_value
        },
        success: function (res) {
            console.log(res)

        },
        error: function () {

        },
        complete: function () {

        }
    })
    $.getJSON("/dirscancompanyshowinterfacebyajax/",
        function (info) {
            //alert(info.soup_p_value_text_1);
        })

}




function showoriginaldatafunc() {
    //显示原始数据
    document.getElementById('tab1').style.display = "block";
    document.getElementById('adminTbody').style.display = "none";
    document.getElementById('aaa').style.display = "none";
}



function showoriginaldatafunc1() {
    //显示处理后数据
    document.getElementById('tab1').style.display = "none";
    document.getElementById('adminTbody').style.display = "block";
    document.getElementById('aaa').style.display = "block";

}



//ajax异步过滤设定阈值策略
function thresholdvaluefunc() {
    var thresholdname = $('select[name="thresholdname"]').val();
    $.ajax({
        url: '/filterthresholdvalue/?thresholdname=' + thresholdname,
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('阈值超过' + thresholdname + '次的屏蔽成功')
        },
        error: function () {
            alert('屏蔽失败')
        },
        complete: function () {
            alert('阈值超过' + thresholdname + '次的屏蔽完成')
        }
    })
}



//打开菜单按钮
function startlogofunc() {
    document.getElementById("button1").disabled = false;
    document.getElementById("button2").disabled = false;
    document.getElementById("button3").disabled = false;
    document.getElementById("button4").disabled = false;
    document.getElementById("button5").disabled = false;
    document.getElementById("button6").disabled = false;
}



//关闭菜单按钮
function stoplogofunc() {
    document.getElementById("button1").disabled = true;
    document.getElementById("button2").disabled = true;
    document.getElementById("button3").disabled = true;
    document.getElementById("button4").disabled = true;
    document.getElementById("button5").disabled = true;
    document.getElementById("button6").disabled = true;

}





function upFile(event) {
    const [file] = event.target.files || event.dataTransfer.files || this.file.files;

    console.dir(file); // 文件对象
    console.log(file.name); // 文件名称  
    console.log(file.type); // 文件类型
    console.log(file.size); // 文件大小

    // 对文件类型做简单限制：如：只允许上传 txt 这1种格式
    if (!file.type && /\.(?:xlsx)$/.test(file.name)) {
        alert('对不起：上传的图片格式只能是：xlsx 格式！');
        return false;
    }
}



//显示扫描后黑名单
function blacklistshowfunc() {
    document.getElementById('blacklistshowid').style.display = "block";
    document.getElementById('blacklistshowid1').style.display = "block";
    $.ajax({
        url: '/QueryingBlacklist/',
        method: 'GET',
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {

        }
    })

    $.getJSON("/QueryingBlacklist/",
        function (info) {
            $('#opbyid3').empty();
            for (var i = 0; i < info.query_black_list.length; i++) {
                $('#opbyid3').append('<option>' + info.query_black_list[i] + '</option><br>');
            }
        })
    //显示扫描前黑名单
    $.getJSON("/queryingbeforeblacklist/",
        function (info) {
            $('#opbyid6').empty();
            for (var i = 0; i < info.query_before_black_list.length; i++) {
                $('#opbyid6').append('<option>' + info.query_before_black_list[i] + '</option><br>');
            }
            document.getElementById("scanbeforefontid").innerHTML = info.query_before_black_list_len;
            document.getElementById("scanafterfontid").innerHTML = info.query_after_black_list_len;
            
        })


}



//显示白名单
function Whitelistshowfunc() {
    document.getElementById('Whitelistshowid').style.display = "block";
    $.ajax({
        url: '/QueryingWhitelist/',
        method: 'GET',
        success: function (res) {
            console.log(res)
        },
        error: function () {

        },
        complete: function () {

        }
    })

    $.getJSON("/QueryingWhitelist/",
        function (info) {
            $('#opbyid4').empty();
            for (var i = 0; i < info.query_white_list.length; i++) {
                $('#opbyid4').append('<option>' + info.query_white_list[i] + '</option><br>');
            }
        })
}



//隐藏黑名单
function blacklistshowlistfunc() {
    document.getElementById('blacklistshowid').style.display = "none";
    document.getElementById('blacklistshowid1').style.display = "none";
}




//隐藏白名单
function Whitelistshowlistfunc() {
    document.getElementById('Whitelistshowid').style.display = "none";
}




//通过JS进行跳转漏洞页面
function generatereportfunc(value) {
    window.open("" + value + "");
}





//通过JS跳转原始网址
function primitivereportfunc(value) {
    var regex = /^(\w+):\/\/([^:/]+)(:\d+)?/;
    var match = value.match(regex);
    //alert(match[0])
    window.open("" + match[0] + "");
}





//目录扫描查询原始数据
function primitivereportfunc1(url_data) {
    //alert(url_data)
    //var modal = document.getElementById("myModal");
    //modal.style.display = "block";
    $.ajax({
        url: '/queryorigindatainterface/',
        method: 'POST',
        data: {
            url_data: url_data
        },
        success: function (res) {
            console.log(res)

        },
        error: function () {

        },
        complete: function () {

        }
    })
    $.getJSON("/queryorigindatainterfacebyajax/",
        function (info) {
            alert(info.global_item_origin_data);
           
        })

}



//ajax异步添加dirsearch扫描任务
function dirsearchscanfunc() {
    var filename = $('select[name="filename"]').val();
    var thread = $('select[name="thread"]').val();
    var statuscode = $('select[name="statuscode"]').val();
    var level = $('select[name="level"]').val();
    var dict = $('select[name="dict"]').val();
    $.ajax({
        url: '/dirsearchscanfun/',
        method: 'POST',
        data: {

            filename: filename,
            thread: thread,
            statuscode: statuscode,
            level: level,
            dict: dict

        },
        success: function (res) {
            console.log(res)
            console.log('扫描任务已下发')
        },
        error: function () {
            alert('扫描任务已下发出错')
        },
        complete: function () {
            alert('扫描任务已下发完成')
        }
    })
}




//ajax异步添加黑名单input框添加
function filterdirsearchdatafunc() {
    var keyvalue = $('input[name="keyvalue"]').val();
    $.ajax({
        url: '/filterdirsearch/',
        method: 'POST',
        data: {
            keyvalue: keyvalue
        },
        success: function (res) {
            console.log(res)
            console.log(keyvalue + '添加到黑名单库成功')
        },
        error: function () {
            alert(keyvalue + '添加到黑名单库出错')
        },
        complete: function () {
            alert(keyvalue + '添加到黑名单库完成')
        }
    })
}




//ajax异步添加白名单
function filterdirsearchdatabywhitefunc() {
    var keyvalue1 = $('input[name="keyvalue1"]').val();
    $.ajax({
        url: '/filterdirsearchbywhite/',
        method: 'POST',
        data: {
            keyvalue1: keyvalue1
        },
        success: function (res) {
            console.log(res)
            console.log(keyvalue1 + '添加到白名单库成功')
        },
        error: function () {
            alert(keyvalue1 + '添加到白名单库出错')
        },
        complete: function () {
            alert(keyvalue1 + '添加到白名单库完成')
        }
    })
}




//ajax异步刷新过滤扫描结果(黑名单)
function flushdirsearchdatafunc() {

    $.ajax({
        url: '/blacklistsync/',
        method: 'GET',

        success: function (res) {
            console.log(res)
            console.log('黑名单同步成功')
        },
        error: function () {
            alert('黑名单同步出错')
        },
        complete: function () {
            alert('黑名单同步完成')
        }
    })
}




//ajax异步刷新过滤扫描结果(白名单)
function flushdirsearchdatabywhitefunc() {

    $.ajax({
        url: '/flushfilterbywhite/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('白名单同步成功')
        },
        error: function () {
            alert('白名单同步出错')
        },
        complete: function () {
            alert('白名单同步完成')
        }
    })
}



//ajax异步结束dirsearch后台进程
function dirsearchkillfunc() {

    $.ajax({
        url: '/killdirsearch/',
        method: 'POST',

        success: function (res) {
            console.log(res)
            console.log('结束dirsearch后台进程请求成功')
        },
        error: function () {
            alert('结束dirsearch后台进程请求出错')
        },
        complete: function () {
            alert('结束dirsearch后台进程请求完成')
        }
    })
}




//ajax异步删除数据
function deletedirfunc(value) {
    $.ajax({
        url: '/deletedirsearchbyid?id=' + value,
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('删除成功')
        },
        error: function () {
            alert('删除出错')
        },
        complete: function () {
            alert('删除完成')
        }
    })
}




//ajax异步异步删除扫描后黑名单
function deletedirsearchblackbynamefunc() {
    var blackname = $('input[name="blackname"]').val();
    $.ajax({
        url: '/deletedirsearchblackbyname?name=' + blackname,
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('扫描后黑名单' + blackname + '删除成功')
        },
        error: function () {
            alert('删除错误')
        },
        complete: function () {
            alert('扫描后黑名单' + blackname + '删除完成')
        }
    })
}




//ajax异步异步删除扫描前黑名单
function deletedirsearcscanbeforehblackbynamefunc() {
    var vulnurl = $('input[name="beforeblackname"]').val();
    $.ajax({
        
        url: '/deletedirsearcscanbeforehblackbyname/',
        method: 'POST',
        data: {
            vulnurl: vulnurl
        },
        success: function (res) {
            
            alert('扫描前黑名单' + vulnurl + '删除成功')
           
        },
        error: function () {
            alert('删除错误')
        },
        complete: function () {
            alert('扫描前黑名单' + vulnurl + '删除完成')
        }
    })
}





//ajax异步异步删除白名单
function deletedirsearchwhitebynamefunc() {
    var whitename = $('input[name="whitename"]').val();
    $.ajax({
        url: '/deletedirsearchwhitebyname?name=' + whitename,
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('白名单' + whitename + '删除成功')
        },
        error: function () {
            alert('删除错误')
        },
        complete: function () {
            alert('白名单' + whitename + '删除完成')
        }
    })
}







//ajax异步清除缓存
function dirsearchclearfunc() {
    $.ajax({
        url: '/deletedirsearchcache/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('缓存清除成功')
        },
        error: function () {
            alert('缓存清除出错')
        },
        complete: function () {
            alert('缓存清除完成')
        }
    })
}




//ajax异步复制文本
function dirsearchcopyfilefunc() {
    $.ajax({
        url: '/dirsearchcopyfile/',
        method: 'GET',
        success: function (res) {
            console.log(res)
            console.log('扫描结果同步成功')
        },
        error: function () {
            alert('扫描结果同步出错')
        },
        complete: function () {
            alert('扫描结果同步完成')
        }
    })
}




function hideRow(element) {
    element.parentElement.classList.add('hidden');
}


//全选
function selectAll() {
    var checkboxes = document.getElementsByName("checkbox");
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = true;
    }
}

//反选
function reverseSelection() {
    var checkboxes = document.getElementsByName("checkbox");
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = !checkboxes[i].checked;
    }
} 