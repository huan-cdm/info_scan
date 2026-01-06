/*
 Navicat Premium Data Transfer

 Source Server         : 127.0.0.1
 Source Server Type    : MySQL
 Source Server Version : 80037
 Source Host           : 127.0.0.1:3306
 Source Schema         : vuln_scan_database

 Target Server Type    : MySQL
 Target Server Version : 80037
 File Encoding         : 65001

 Date: 06/01/2026 17:11:20
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for fofa_log
-- ----------------------------
DROP TABLE IF EXISTS `fofa_log`;
CREATE TABLE `fofa_log`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `fofa_grammar` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `file_path` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 135 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of fofa_log
-- ----------------------------
INSERT INTO `fofa_log` VALUES (112, 'title=\"后台管理\"', '/TIP/info_scan/result/assetmanager/2025/02/1117:21:37.txt');
INSERT INTO `fofa_log` VALUES (113, 'title=\"后台管理\"', '/TIP/info_scan/result/assetmanager/2025/02/1117:21:44.txt');
INSERT INTO `fofa_log` VALUES (114, 'title=\"北京市\"', '/TIP/info_scan/result/assetmanager/2025/03/2715:05:15.txt');
INSERT INTO `fofa_log` VALUES (115, 'title=\"后台管理\"', '/TIP/info_scan/result/assetmanager/2025/04/1810:23:25.txt');
INSERT INTO `fofa_log` VALUES (116, 'cert=\"大学\" && title=\"系统\" && country=\"CN\"', '/TIP/info_scan/result/assetmanager/2025/05/1409:57:12.txt');
INSERT INTO `fofa_log` VALUES (117, 'title=\"百度\"', '/TIP/info_scan/result/assetmanager/2025/05/2110:40:48.txt');
INSERT INTO `fofa_log` VALUES (118, 'title=\"百度\"', '/TIP/info_scan/result/assetmanager/2025/05/2110:41:17.txt');
INSERT INTO `fofa_log` VALUES (119, 'title=\"百度\"', '/TIP/info_scan/result/assetmanager/2025/05/2110:42:01.txt');
INSERT INTO `fofa_log` VALUES (120, 'port=\"6379\"', '/TIP/info_scan/result/assetmanager/2025/06/1811:13:22.txt');
INSERT INTO `fofa_log` VALUES (121, 'port=\"27017\"', '/TIP/info_scan/result/assetmanager/2025/06/1814:10:47.txt');
INSERT INTO `fofa_log` VALUES (122, 'port=\"27017\"', '/TIP/info_scan/result/assetmanager/2025/06/1814:48:05.txt');
INSERT INTO `fofa_log` VALUES (123, 'port=\"11211\"', '/TIP/info_scan/result/assetmanager/2025/06/1815:07:56.txt');
INSERT INTO `fofa_log` VALUES (124, 'port=\"2181\"', '/TIP/info_scan/result/assetmanager/2025/06/1815:22:37.txt');
INSERT INTO `fofa_log` VALUES (125, 'port = \"2181\"', '/TIP/info_scan/result/assetmanager/2025/06/1815:26:40.txt');
INSERT INTO `fofa_log` VALUES (126, 'port=\"2181\"', '/TIP/info_scan/result/assetmanager/2025/06/1815:31:45.txt');
INSERT INTO `fofa_log` VALUES (127, 'port=\"5984\"', '/TIP/info_scan/result/assetmanager/2025/06/1816:52:16.txt');
INSERT INTO `fofa_log` VALUES (128, 'port=\"2375\"', '/TIP/info_scan/result/assetmanager/2025/06/1816:54:14.txt');
INSERT INTO `fofa_log` VALUES (129, 'cert=\"155005921261218743509246525942157493544\"', '/TIP/info_scan/result/assetmanager/2025/06/1914:23:44.txt');
INSERT INTO `fofa_log` VALUES (130, 'title=\"后台管理\"', '/TIP/info_scan/result/assetmanager/2025/09/1116:04:06.txt');
INSERT INTO `fofa_log` VALUES (131, 'shiro', '/TIP/info_scan/result/assetmanager/2025/09/1710:27:29.txt');
INSERT INTO `fofa_log` VALUES (132, 'shiro', '/TIP/info_scan/result/assetmanager/2025/09/1710:27:40.txt');
INSERT INTO `fofa_log` VALUES (133, 'shiro', '/TIP/info_scan/result/assetmanager/2025/09/1710:28:10.txt');
INSERT INTO `fofa_log` VALUES (134, 'springboot', '/TIP/info_scan/result/assetmanager/2025/09/1715:19:41.txt');
INSERT INTO `fofa_log` VALUES (135, 'title=\"后台管理\"', '/TIP/info_scan/result/assetmanager/2025/09/2416:09:38.txt');

-- ----------------------------
-- Table structure for info_time_diff
-- ----------------------------
DROP TABLE IF EXISTS `info_time_diff`;
CREATE TABLE `info_time_diff`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `time_diff` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 10 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of info_time_diff
-- ----------------------------
INSERT INTO `info_time_diff` VALUES (1, '1758093973.0671844');
INSERT INTO `info_time_diff` VALUES (2, '1758093602.6588795');
INSERT INTO `info_time_diff` VALUES (3, '1767682738.6838644');
INSERT INTO `info_time_diff` VALUES (4, '1767682994.42451');
INSERT INTO `info_time_diff` VALUES (5, '1744939185.2067578');
INSERT INTO `info_time_diff` VALUES (6, '1767683079.7703862');
INSERT INTO `info_time_diff` VALUES (7, '1758265881.146521');
INSERT INTO `info_time_diff` VALUES (8, '1761878917.4496768');
INSERT INTO `info_time_diff` VALUES (9, '1726190650.8981938');
INSERT INTO `info_time_diff` VALUES (10, '1726190650.8981938');

-- ----------------------------
-- Table structure for interfacenum_table
-- ----------------------------
DROP TABLE IF EXISTS `interfacenum_table`;
CREATE TABLE `interfacenum_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `successnum` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `failnum` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `interid` int(0) NULL DEFAULT NULL,
  `decrib` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `totalnum` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of interfacenum_table
-- ----------------------------
INSERT INTO `interfacenum_table` VALUES (1, '47', '20', 1, 'fofa接口查询次数初始次数是0', '30000');
INSERT INTO `interfacenum_table` VALUES (2, '18', '0', 2, 'shodan接口查询次数初始次数是0', '897');
INSERT INTO `interfacenum_table` VALUES (3, '4', '0', 3, '基础证书查询子域名接口初始次数是0', '4998');
INSERT INTO `interfacenum_table` VALUES (4, '26', '1', 4, 'icp网站备案查询接口初始次数是0', '5000');
INSERT INTO `interfacenum_table` VALUES (5, '17', '0', 5, '高德地图查询接口初始次数是0', '5000');
INSERT INTO `interfacenum_table` VALUES (6, '2', '0', 6, 'otx历史url查询接口初始次数是0', '5000');

-- ----------------------------
-- Table structure for route_status
-- ----------------------------
DROP TABLE IF EXISTS `route_status`;
CREATE TABLE `route_status`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `typename` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `typevalue` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of route_status
-- ----------------------------
INSERT INTO `route_status` VALUES (1, 'fofa', '1');

-- ----------------------------
-- Table structure for rule_table
-- ----------------------------
DROP TABLE IF EXISTS `rule_table`;
CREATE TABLE `rule_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `rule` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 135 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of rule_table
-- ----------------------------

-- ----------------------------
-- Table structure for scan_after_black
-- ----------------------------
DROP TABLE IF EXISTS `scan_after_black`;
CREATE TABLE `scan_after_black`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4161 CHARACTER SET = utf8mb3 COLLATE = utf8mb3_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_after_black
-- ----------------------------

-- ----------------------------
-- Table structure for scan_after_white
-- ----------------------------
DROP TABLE IF EXISTS `scan_after_white`;
CREATE TABLE `scan_after_white`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 25 CHARACTER SET = utf8mb3 COLLATE = utf8mb3_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_after_white
-- ----------------------------
INSERT INTO `scan_after_white` VALUES (24, 'misc');
INSERT INTO `scan_after_white` VALUES (25, 'scope_settings');

-- ----------------------------
-- Table structure for scan_before_black
-- ----------------------------
DROP TABLE IF EXISTS `scan_before_black`;
CREATE TABLE `scan_before_black`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `vulnurl` text CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5355 CHARACTER SET = utf8mb3 COLLATE = utf8mb3_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_before_black
-- ----------------------------

-- ----------------------------
-- Table structure for scan_conf_table
-- ----------------------------
DROP TABLE IF EXISTS `scan_conf_table`;
CREATE TABLE `scan_conf_table`  (
  `id` int(0) NOT NULL,
  `partname` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_conf_table
-- ----------------------------
INSERT INTO `scan_conf_table` VALUES (1, '2');
INSERT INTO `scan_conf_table` VALUES (2, '2');
INSERT INTO `scan_conf_table` VALUES (3, 'shiro');
INSERT INTO `scan_conf_table` VALUES (4, '/root/nuclei-templates/http');
INSERT INTO `scan_conf_table` VALUES (5, 'top1000端口');
INSERT INTO `scan_conf_table` VALUES (6, '1-65535');
INSERT INTO `scan_conf_table` VALUES (7, '2');
INSERT INTO `scan_conf_table` VALUES (8, '1');
INSERT INTO `scan_conf_table` VALUES (9, '1');
INSERT INTO `scan_conf_table` VALUES (10, '1');
INSERT INTO `scan_conf_table` VALUES (11, '1');
INSERT INTO `scan_conf_table` VALUES (12, '1');

-- ----------------------------
-- Table structure for scan_total_time_table
-- ----------------------------
DROP TABLE IF EXISTS `scan_total_time_table`;
CREATE TABLE `scan_total_time_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `starttime` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `endtime` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `typeid` int(0) NULL DEFAULT NULL,
  `description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 46 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_total_time_table
-- ----------------------------
INSERT INTO `scan_total_time_table` VALUES (1, '1744939185.2161448', '1744939279.1639369', 1, '端口扫描');
INSERT INTO `scan_total_time_table` VALUES (2, '1758093602.6799939', '1758093605.8309216', 2, '指纹识别');
INSERT INTO `scan_total_time_table` VALUES (3, '1758093973.072074', '1758094003.774496', 3, '敏感信息');
INSERT INTO `scan_total_time_table` VALUES (4, '1767682738.7026145', '1767682742.8122838', 4, '域名绑定URL扫描');
INSERT INTO `scan_total_time_table` VALUES (5, '1767682994.430637', '1767682997.5232575', 5, '子域名扫描');
INSERT INTO `scan_total_time_table` VALUES (6, '1767683079.7758758', '1767683112.5189972', 6, 'WAF识别扫描');
INSERT INTO `scan_total_time_table` VALUES (7, '1758265881.16147', '1758265935.3141022', 7, '网站FUZZ');
INSERT INTO `scan_total_time_table` VALUES (8, '1761878917.4666042', '1761878918.1673822', 8, '爬虫扫描');
INSERT INTO `scan_total_time_table` VALUES (9, '1758251755.5517309', '1758251762.8912535', 9, 'struts2扫描');
INSERT INTO `scan_total_time_table` VALUES (10, '1758252306.1551316', '', 10, 'weblogic扫描');
INSERT INTO `scan_total_time_table` VALUES (11, '1758076289.7831426', '1758076462.500142', 11, 'shiro扫描');
INSERT INTO `scan_total_time_table` VALUES (12, '1758093765.232273', '1758093767.3412776', 12, 'springboot扫描');
INSERT INTO `scan_total_time_table` VALUES (13, '1758251865.486656', '1758251876.7372048', 13, 'thinkphp扫描');
INSERT INTO `scan_total_time_table` VALUES (14, '1734400494.2813883', '1734400581.0495818', 14, 'elasticsearch扫描');
INSERT INTO `scan_total_time_table` VALUES (15, '1736737124.0426946', '1736737127.1286259', 15, 'nacos扫描');
INSERT INTO `scan_total_time_table` VALUES (16, '1736737866.502889', '1736737884.9648108', 16, 'tomcat扫描');
INSERT INTO `scan_total_time_table` VALUES (17, '1730030295.4099455', '1730030297.625545', 17, 'fastjson扫描');
INSERT INTO `scan_total_time_table` VALUES (18, '1758093047.1228065', '1758093152.400931', 18, 'afrog扫描');
INSERT INTO `scan_total_time_table` VALUES (19, '1757579571.5906143', '1757579583.9122372', 19, 'fscan扫描');
INSERT INTO `scan_total_time_table` VALUES (20, '1736735292.2294452', '1736735292.3164513', 20, '弱口令扫描');
INSERT INTO `scan_total_time_table` VALUES (21, '1757582333.294306', '1757582379.5041482', 21, 'api接口扫描');
INSERT INTO `scan_total_time_table` VALUES (22, '1758075785.1063664', '1758075855.736811', 22, 'vulmap扫描');
INSERT INTO `scan_total_time_table` VALUES (24, '1758074662.8834703', '1758074885.1221933', 23, 'nuclei扫描');
INSERT INTO `scan_total_time_table` VALUES (25, '1758252448.5153532', '1758252459.7916603', 24, '泛微OA');
INSERT INTO `scan_total_time_table` VALUES (26, '1757578880.9468884', '1757578905.6191366', 25, '存活检测');
INSERT INTO `scan_total_time_table` VALUES (27, '1761878693.495772', '1761878918.7042124', 26, 'xray');
INSERT INTO `scan_total_time_table` VALUES (28, '1736738577.865604', '1736738582.239719', 27, '致远OA');
INSERT INTO `scan_total_time_table` VALUES (29, '1736738683.19361', '1736738686.3005657', 28, '用友OA');
INSERT INTO `scan_total_time_table` VALUES (30, '1736738930.7371986', '1736738932.950809', 29, '金蝶OA');
INSERT INTO `scan_total_time_table` VALUES (31, '1736738931.098156', '1736738934.3221989', 30, '万户OA');
INSERT INTO `scan_total_time_table` VALUES (32, '1758268494.5801125', '1758268495.6335971', 31, 'subfinder');
INSERT INTO `scan_total_time_table` VALUES (33, '1750229020.5811174', '1750229121.4943352', 32, 'redis未授权');
INSERT INTO `scan_total_time_table` VALUES (34, '1750230135.6234949', '1750230197.5362675', 33, 'mongodb未授权');
INSERT INTO `scan_total_time_table` VALUES (35, '1750230522.3156428', '1750230621.0624535', 34, ' memcached未授权');
INSERT INTO `scan_total_time_table` VALUES (36, '1750233498.656621', '1750233502.9144003', 35, 'zookeeper未授权');
INSERT INTO `scan_total_time_table` VALUES (37, '1736759866.1047678', '1736759867.3577657', 36, ' ftp未授权');
INSERT INTO `scan_total_time_table` VALUES (38, '1750236763.426175', '1750236784.8921938', 37, 'CouchDB未授权');
INSERT INTO `scan_total_time_table` VALUES (39, '1750236867.5868056', '1750236879.0898104', 38, ' docker未授权');
INSERT INTO `scan_total_time_table` VALUES (40, '1736759867.548434', '1736759874.002249', 39, ' Hadoop未授权');
INSERT INTO `scan_total_time_table` VALUES (41, '1736759867.986261', '1736759886.5741658', 40, NULL);
INSERT INTO `scan_total_time_table` VALUES (42, '1736759868.258623', '1736759874.5329363', 41, NULL);
INSERT INTO `scan_total_time_table` VALUES (43, '1736759868.5117083', '1736759874.9131227', 42, NULL);
INSERT INTO `scan_total_time_table` VALUES (44, '1743493826.071692', '1743493863.33645', 43, NULL);
INSERT INTO `scan_total_time_table` VALUES (45, '1734055399.296267', '1734055399.296267', 44, NULL);
INSERT INTO `scan_total_time_table` VALUES (46, '1734055399.296267', '1734055399.296267', 45, NULL);

-- ----------------------------
-- Table structure for status_table
-- ----------------------------
DROP TABLE IF EXISTS `status_table`;
CREATE TABLE `status_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `status_value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of status_table
-- ----------------------------
INSERT INTO `status_table` VALUES (1, '通过fofa平台获取资产完成');
INSERT INTO `status_table` VALUES (2, '已完成开启批量信息收集');

-- ----------------------------
-- Table structure for sys_conf
-- ----------------------------
DROP TABLE IF EXISTS `sys_conf`;
CREATE TABLE `sys_conf`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `info_session_time` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `fofa_email` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `fofa_key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_conf
-- ----------------------------
INSERT INTO `sys_conf` VALUES (1, '700', NULL, NULL);
INSERT INTO `sys_conf` VALUES (2, NULL, 'xx', 'xx');
INSERT INTO `sys_conf` VALUES (3, 'xx', NULL, '');
INSERT INTO `sys_conf` VALUES (4, 'xx', NULL, '');
INSERT INTO `sys_conf` VALUES (5, 'xx', NULL, '');
INSERT INTO `sys_conf` VALUES (6, 'lednh4.ceye.io', NULL, NULL);

-- ----------------------------
-- Table structure for verification_table
-- ----------------------------
DROP TABLE IF EXISTS `verification_table`;
CREATE TABLE `verification_table`  (
  `id` int(0) NOT NULL,
  `logopart` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of verification_table
-- ----------------------------
INSERT INTO `verification_table` VALUES (1, '2');
INSERT INTO `verification_table` VALUES (2, '2');

-- ----------------------------
-- Table structure for vuln_time_diff
-- ----------------------------
DROP TABLE IF EXISTS `vuln_time_diff`;
CREATE TABLE `vuln_time_diff`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `time_diff` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 45 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of vuln_time_diff
-- ----------------------------
INSERT INTO `vuln_time_diff` VALUES (1, '1758251755.5435815');
INSERT INTO `vuln_time_diff` VALUES (2, '1758252306.13778');
INSERT INTO `vuln_time_diff` VALUES (3, '1758076289.7757976');
INSERT INTO `vuln_time_diff` VALUES (4, '1758093765.2276657');
INSERT INTO `vuln_time_diff` VALUES (5, '1758251865.4809525');
INSERT INTO `vuln_time_diff` VALUES (6, '1758093047.1123478');
INSERT INTO `vuln_time_diff` VALUES (7, '1757579571.5435116');
INSERT INTO `vuln_time_diff` VALUES (8, '1736735292.1973052');
INSERT INTO `vuln_time_diff` VALUES (9, '1757582333.2844467');
INSERT INTO `vuln_time_diff` VALUES (10, '1758075785.0997093');
INSERT INTO `vuln_time_diff` VALUES (11, '1758074662.8254197');
INSERT INTO `vuln_time_diff` VALUES (12, '1758252448.5099306');
INSERT INTO `vuln_time_diff` VALUES (13, '1724404603.553185');
INSERT INTO `vuln_time_diff` VALUES (14, '1734400494.2649791');
INSERT INTO `vuln_time_diff` VALUES (15, '1736737124.029489');
INSERT INTO `vuln_time_diff` VALUES (16, '1736737866.4422815');
INSERT INTO `vuln_time_diff` VALUES (17, '1744162294.4162545');
INSERT INTO `vuln_time_diff` VALUES (18, '1730030295.285501');
INSERT INTO `vuln_time_diff` VALUES (19, '1761878693.3988433');
INSERT INTO `vuln_time_diff` VALUES (20, '1736738577.6168153');
INSERT INTO `vuln_time_diff` VALUES (21, '1736738683.092784');
INSERT INTO `vuln_time_diff` VALUES (22, '1736738930.5457804');
INSERT INTO `vuln_time_diff` VALUES (23, '1736738930.9140022');
INSERT INTO `vuln_time_diff` VALUES (24, '1750229020.5431218');
INSERT INTO `vuln_time_diff` VALUES (25, '1750230135.5228999');
INSERT INTO `vuln_time_diff` VALUES (26, '1750230522.2936795');
INSERT INTO `vuln_time_diff` VALUES (27, '1750233498.1875892');
INSERT INTO `vuln_time_diff` VALUES (28, '1736759865.808939');
INSERT INTO `vuln_time_diff` VALUES (29, '1750236763.2376952');
INSERT INTO `vuln_time_diff` VALUES (30, '1750236867.522441');
INSERT INTO `vuln_time_diff` VALUES (31, '1736759867.3788712');
INSERT INTO `vuln_time_diff` VALUES (32, '1736759867.8206122');
INSERT INTO `vuln_time_diff` VALUES (33, '1736759868.1297352');
INSERT INTO `vuln_time_diff` VALUES (34, '1736759868.3779614');
INSERT INTO `vuln_time_diff` VALUES (35, '1743493825.5530636');
INSERT INTO `vuln_time_diff` VALUES (36, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (37, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (38, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (39, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (40, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (41, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (42, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (43, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (44, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (45, '1725522995.515026');

-- ----------------------------
-- Table structure for webpack_conf
-- ----------------------------
DROP TABLE IF EXISTS `webpack_conf`;
CREATE TABLE `webpack_conf`  (
  `id` int(0) NOT NULL,
  `logopart` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `cookiepart` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of webpack_conf
-- ----------------------------
INSERT INTO `webpack_conf` VALUES (1, '1', 'session=eyJfcGVybWFuZW50Ijp0cnVlLCJ1c2VybmFtZSI6Imh1YW42NjYifQ.aVym-A.JbWgsUsM3eD3oILA7THXJACnnHg; Expires=Tue, 06 Jan 2026 17:48:56 GMT; HttpOnly; Path=/');

SET FOREIGN_KEY_CHECKS = 1;
