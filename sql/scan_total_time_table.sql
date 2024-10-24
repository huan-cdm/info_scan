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

 Date: 24/10/2024 21:43:49
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

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
) ENGINE = InnoDB AUTO_INCREMENT = 26 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_total_time_table
-- ----------------------------
INSERT INTO `scan_total_time_table` VALUES (1, '1729774533.1155796', '1729774885.3804023', 1, '端口扫描');
INSERT INTO `scan_total_time_table` VALUES (2, '1729776643.9701164', '1729776664.3594337', 2, '指纹识别');
INSERT INTO `scan_total_time_table` VALUES (3, '1729775631.893891', '1729775648.2322917', 3, '敏感信息');
INSERT INTO `scan_total_time_table` VALUES (4, '1729775828.3115528', '1729775833.4433599', 4, '域名绑定URL扫描');
INSERT INTO `scan_total_time_table` VALUES (5, '1729761798.4443552', '1729761820.818005', 5, '子域名扫描');
INSERT INTO `scan_total_time_table` VALUES (6, '1729776698.525464', '1729776792.3247373', 6, 'WAF识别扫描');
INSERT INTO `scan_total_time_table` VALUES (7, '1729776676.2108405', '1729776728.3095646', 7, '网站FUZZ');
INSERT INTO `scan_total_time_table` VALUES (8, '1729777335.644232', '1729777338.7514884', 8, '爬虫扫描');
INSERT INTO `scan_total_time_table` VALUES (9, NULL, NULL, 9, 'struts2扫描');
INSERT INTO `scan_total_time_table` VALUES (10, NULL, NULL, 10, 'weblogic扫描');
INSERT INTO `scan_total_time_table` VALUES (11, NULL, NULL, 11, 'shiro扫描');
INSERT INTO `scan_total_time_table` VALUES (12, NULL, NULL, 12, 'springboot扫描');
INSERT INTO `scan_total_time_table` VALUES (13, NULL, NULL, 13, 'thinkphp扫描');
INSERT INTO `scan_total_time_table` VALUES (14, NULL, NULL, 14, 'elasticsearch扫描');
INSERT INTO `scan_total_time_table` VALUES (15, NULL, NULL, 15, 'nacos扫描');
INSERT INTO `scan_total_time_table` VALUES (16, NULL, NULL, 16, 'tomcat扫描');
INSERT INTO `scan_total_time_table` VALUES (17, NULL, NULL, 17, 'fastjson扫描');
INSERT INTO `scan_total_time_table` VALUES (18, NULL, NULL, 18, 'afrog扫描');
INSERT INTO `scan_total_time_table` VALUES (19, NULL, NULL, 19, 'fscan扫描');
INSERT INTO `scan_total_time_table` VALUES (20, NULL, NULL, 20, '弱口令扫描');
INSERT INTO `scan_total_time_table` VALUES (21, NULL, NULL, 21, 'api接口扫描');
INSERT INTO `scan_total_time_table` VALUES (22, NULL, NULL, 22, 'vulmap扫描');
INSERT INTO `scan_total_time_table` VALUES (23, NULL, NULL, 22, 'vulmap扫描');
INSERT INTO `scan_total_time_table` VALUES (24, NULL, NULL, 23, 'nuclei扫描');
INSERT INTO `scan_total_time_table` VALUES (25, NULL, NULL, 24, '泛微OA');

SET FOREIGN_KEY_CHECKS = 1;
