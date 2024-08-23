#shodan key配置
shodankey = ""

# fofa相关配置，防止接口被耗尽，可配置单个key或者多个key
fofanum = "10000"  # fofa查询条数
# ①. 多个key配置
dict_key1 = {"email":"","key":""}
dict_key2 = {"email":"","key":""}
fofa_list_key = [dict_key1,dict_key2]


# ②. 单个key配置
# dict_key1 = {"email":"","key":""}
# fofa_list_key = [dict_key1]



#命令行查询入口
#switch = 0 单个扫描
#switch = 1 批量扫描
switch = 0

#云服务器列表
cloudserver = ["百度","华为","京东","阿里","亚马逊","腾讯","西部数码"]

#带宽出口列表
exitaddress = ["移动","电信","联通"]

#手机热点
hotspot = ["移动数据上网公共出口","中国电信北京研究院"]

#数据中心
datacenter = ["公司","数据中心"]


#高德地图API列表(可添加多个key)
amap_key_list = ["",""]

# ceye_key配置
ceye_key = ""


#判断直接扫描URL还是通过调用OTX接口查询的历史URL作为扫描目标
#history_switch = 1  调用OTX查询历史URL
#history_switch = 0  用户输入URL
history_switch = 0


#MySQL数据库配置
dict = {
    "ip":"127.0.0.1","username":"","password":"","dbname":"vuln_scan_database","portnum": 3306
}



#主系统账号密码配置选项
main_username = ""
main_password = ""

#子系统账号密码配置选项
sub_username = ""
sub_password = ""


#重点资产提取，列表里配置多个关键字
finger_list = ["spring-boot"]

# 重点资产提取启用配置文件或者MySQL数据库
# 1:配置文件
# 2:MySQL数据库
rule_options = 2


# 资产管理-重点资产数量展示，列表里只填一个关键字
Shiro_rule = ["Shiro"]
SpringBoot_rule = ["spring-boot"]
weblogic_rule = ["Weblogic"]
baota_rule = ["宝塔-BT"]
ruoyi_rule = ["若依"]
struts2_rule = ["Struts2"]
WordPress_rule = ["WordPress"]
jboss_rule = ["Jboss"]
phpMyAdmin_rule = ["phpMyAdmin"]
ThinkPHP_rule = ["ThinkPHP"]
nacos_rule = ["Nacos"]
fanwei_rule = ["泛微"]


# 信息收集类工具限制单位时间内禁止重复提交
info_time_controls = 5

# 漏洞扫描类工具限制单位时间内禁止重复提交
vuln_time_controls = 5
