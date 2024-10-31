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

 Date: 29/10/2024 20:19:40
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
INSERT INTO `scan_total_time_table` VALUES (2, '1730031885.1799793', '1730031889.284735', 2, '指纹识别');
INSERT INTO `scan_total_time_table` VALUES (3, '1729775631.893891', '1729775648.2322917', 3, '敏感信息');
INSERT INTO `scan_total_time_table` VALUES (4, '1729775828.3115528', '1729775833.4433599', 4, '域名绑定URL扫描');
INSERT INTO `scan_total_time_table` VALUES (5, '1729761798.4443552', '1729761820.818005', 5, '子域名扫描');
INSERT INTO `scan_total_time_table` VALUES (6, '1729776698.525464', '1729776792.3247373', 6, 'WAF识别扫描');
INSERT INTO `scan_total_time_table` VALUES (7, '1729776676.2108405', '1729776728.3095646', 7, '网站FUZZ');
INSERT INTO `scan_total_time_table` VALUES (8, '1729777335.644232', '1729777338.7514884', 8, '爬虫扫描');
INSERT INTO `scan_total_time_table` VALUES (9, '1729842159.836591', '1729842162.9138258', 9, 'struts2扫描');
INSERT INTO `scan_total_time_table` VALUES (10, '1729842439.9239888', '1729842453.1829948', 10, 'weblogic扫描');
INSERT INTO `scan_total_time_table` VALUES (11, '1729842979.4207397', '1729842982.5032306', 11, 'shiro扫描');
INSERT INTO `scan_total_time_table` VALUES (12, '1729844236.1169736', '1729844238.1773283', 12, 'springboot扫描');
INSERT INTO `scan_total_time_table` VALUES (13, '1729845239.4041088', '1729845255.740449', 13, 'thinkphp扫描');
INSERT INTO `scan_total_time_table` VALUES (14, '1729846016.4401536', '1729846019.5538988', 14, 'elasticsearch扫描');
INSERT INTO `scan_total_time_table` VALUES (15, '1729846591.2994435', '1729846635.133274', 15, 'nacos扫描');
INSERT INTO `scan_total_time_table` VALUES (16, '1730029450.6792734', '1730029535.431823', 16, 'tomcat扫描');
INSERT INTO `scan_total_time_table` VALUES (17, '1730030295.4099455', '1730030297.625545', 17, 'fastjson扫描');
INSERT INTO `scan_total_time_table` VALUES (18, '1730030907.894969', '1730031101.2418377', 18, 'afrog扫描');
INSERT INTO `scan_total_time_table` VALUES (19, '1730031904.748478', '1730031908.8556728', 19, 'fscan扫描');
INSERT INTO `scan_total_time_table` VALUES (20, '1730032531.0688286', '1730032589.1758244', 20, '弱口令扫描');
INSERT INTO `scan_total_time_table` VALUES (21, '1730033325.8456275', '1730033327.4604876', 21, 'api接口扫描');
INSERT INTO `scan_total_time_table` VALUES (22, '1730033940.2562637', '1730034125.9052339', 22, 'vulmap扫描');
INSERT INTO `scan_total_time_table` VALUES (24, '1730034451.4575036', '1730034822.5108426', 23, 'nuclei扫描');
INSERT INTO `scan_total_time_table` VALUES (25, '1730035470.8967807', '1730035485.215591', 24, '泛微OA');
INSERT INTO `scan_total_time_table` VALUES (26, NULL, NULL, 25, '存活检测');
INSERT INTO `scan_total_time_table` VALUES (27, NULL, NULL, 26, '占位');
INSERT INTO `scan_total_time_table` VALUES (28, NULL, NULL, 27, '占位');
INSERT INTO `scan_total_time_table` VALUES (29, NULL, NULL, 28, '占位');
INSERT INTO `scan_total_time_table` VALUES (30, NULL, NULL, 29, '占位');
INSERT INTO `scan_total_time_table` VALUES (31, NULL, NULL, 30, '占位');
INSERT INTO `scan_total_time_table` VALUES (32, NULL, NULL, 31, '占位');

SET FOREIGN_KEY_CHECKS = 1;
