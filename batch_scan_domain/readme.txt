config.py 脚本配置文件
url.txt   待扫描目标放到这里（https://www.xxx.com/）
result.txt 通过第三方接口查询出的历史URL存到这里
radscan.py 脚本入口文件，python3 radscan.py，会先检查config.py配置
history_switch = 1  调用OTX查询历史URL，在调用rad扫描
history_switch = 0  用户输入URL，在调用rad扫描
scan_lib.py、url_lib.py 调用第三方接口
脚本功能：批量通过rad爬取URL（直接输入URL+通过调用第三方接口获取的历史URL），然后把流量给xray进行被动扫描
利用https://github.com/huan-cdm/info_scan 控制batch_scan_domain、web服务查看xray报告相关操作、xray、rad服务运行状态