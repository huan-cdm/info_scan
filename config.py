#shodan key配置
shodankey = "5wdqqD7mCbWQdehFqWhk5aKVK0OtwR0Z"

#fofa key 配置
fofaemail = "weakchicken@qq.com"
fofakey = "2aa095c6c28f3d511559282f8caa7a93"
fofanum = "10000"

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
amap_key_list = ["2c0f28df8ad2748d51f49d8a075c6c88","7b9b96ca1f7df413f999ebd7f08577e6"]

# ceye_key配置
ceye_key = "1c9ca5b4d4eebd74f3b77675c919005b"


#判断直接扫描URL还是通过调用OTX接口查询的历史URL作为扫描目标
#history_switch = 1  调用OTX查询历史URL
#history_switch = 0  用户输入URL
history_switch = 0


#MySQL数据库配置
dict = {
    "ip":"127.0.0.1","username":"admin","password":"admin@123","dbname":"vuln_scan_database","portnum": 3306
}



#主系统账号密码配置选项
main_username = "mainadmin"
main_password = "mainadmin"

#子系统账号密码配置选项
sub_username = "subadmin"
sub_password = "subadmin"


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
