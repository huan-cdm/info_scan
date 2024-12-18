/*
 Navicat Premium Data Transfer

 Source Server         : 127.0.0.1
 Source Server Type    : MySQL
 Source Server Version : 80037
 Source Host           : 117.72.16.222:3306
 Source Schema         : vuln_scan_database

 Target Server Type    : MySQL
 Target Server Version : 80037
 File Encoding         : 65001

 Date: 17/12/2024 17:18:53
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
) ENGINE = InnoDB AUTO_INCREMENT = 32 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of scan_total_time_table
-- ----------------------------
INSERT INTO `scan_total_time_table` VALUES (1, '1733993171.8410106', '1733993283.0170074', 1, '端口扫描');
INSERT INTO `scan_total_time_table` VALUES (2, '1734400437.8626134', '1734400458.276578', 2, '指纹识别');
INSERT INTO `scan_total_time_table` VALUES (3, '1729775631.893891', '1729775648.2322917', 3, '敏感信息');
INSERT INTO `scan_total_time_table` VALUES (4, '1730873089.1738102', '1730873090.2154527', 4, '域名绑定URL扫描');
INSERT INTO `scan_total_time_table` VALUES (5, '1733820301.3280592', '1733820327.3085327', 5, '子域名扫描');
INSERT INTO `scan_total_time_table` VALUES (6, '1729776698.525464', '1729776792.3247373', 6, 'WAF识别扫描');
INSERT INTO `scan_total_time_table` VALUES (7, '1729776676.2108405', '1729776728.3095646', 7, '网站FUZZ');
INSERT INTO `scan_total_time_table` VALUES (8, '1733971303.8818808', '1733971304.0479515', 8, '爬虫扫描');
INSERT INTO `scan_total_time_table` VALUES (9, '1732245351.724273', '1732245358.5395215', 9, 'struts2扫描');
INSERT INTO `scan_total_time_table` VALUES (10, '1732245351.7917867', '1732245417.1704173', 10, 'weblogic扫描');
INSERT INTO `scan_total_time_table` VALUES (11, '1732245351.8662305', '1732245357.5535111', 11, 'shiro扫描');
INSERT INTO `scan_total_time_table` VALUES (12, '1732245352.0101523', '1732245355.5693376', 12, 'springboot扫描');
INSERT INTO `scan_total_time_table` VALUES (13, '1732245352.1299918', '1732245366.823733', 13, 'thinkphp扫描');
INSERT INTO `scan_total_time_table` VALUES (14, '1734400494.2813883', '1734400581.0495818', 14, 'elasticsearch扫描');
INSERT INTO `scan_total_time_table` VALUES (15, '1732245352.5749812', '1732245365.8302112', 15, 'nacos扫描');
INSERT INTO `scan_total_time_table` VALUES (16, '1732245352.7784276', '1732245376.665109', 16, 'tomcat扫描');
INSERT INTO `scan_total_time_table` VALUES (17, '1730030295.4099455', '1730030297.625545', 17, 'fastjson扫描');
INSERT INTO `scan_total_time_table` VALUES (18, '1732245353.179586', '1732245488.4157429', 18, 'afrog扫描');
INSERT INTO `scan_total_time_table` VALUES (19, '1732245353.2934723', '1732245364.652513', 19, 'fscan扫描');
INSERT INTO `scan_total_time_table` VALUES (20, '1733971521.2913115', '1733971523.3483002', 20, '弱口令扫描');
INSERT INTO `scan_total_time_table` VALUES (21, '1732245353.8045185', '1732245432.3836343', 21, 'api接口扫描');
INSERT INTO `scan_total_time_table` VALUES (22, '1732245354.2099197', '1732245357.7201622', 22, 'vulmap扫描');
INSERT INTO `scan_total_time_table` VALUES (24, '1732245354.43893', '1732245379.504172', 23, 'nuclei扫描');
INSERT INTO `scan_total_time_table` VALUES (25, '1733994003.746786', '1733994007.006624', 24, '泛微OA');
INSERT INTO `scan_total_time_table` VALUES (26, '1732522466.9131224', '1732522482.2121959', 25, '存活检测');
INSERT INTO `scan_total_time_table` VALUES (27, '1733970770.5203142', '1733970792.9953525', 26, 'xray');
INSERT INTO `scan_total_time_table` VALUES (28, '1733993953.9136307', '1733993955.006164', 27, '致远OA');
INSERT INTO `scan_total_time_table` VALUES (29, '1733993953.9877112', '1733993954.036797', 28, '用友OA');
INSERT INTO `scan_total_time_table` VALUES (30, '1733993954.0691726', '1733993954.0975301', 29, '金蝶OA');
INSERT INTO `scan_total_time_table` VALUES (31, '1733993954.1698034', '1733993955.2592373', 30, '万户OA');
INSERT INTO `scan_total_time_table` VALUES (32, '1734055399.296267', '1734055403.9583802', 31, 'subfinder');
INSERT INTO `scan_total_time_table` VALUES (33, '1734055399.296267', '1734055399.296267', 32, 'redis未授权');
INSERT INTO `scan_total_time_table` VALUES (34, '1734055399.296267', '1734055399.296267', 33, 'mongodb未授权');
INSERT INTO `scan_total_time_table` VALUES (35, '1734055399.296267', '1734055399.296267', 34, ' memcached未授权');
INSERT INTO `scan_total_time_table` VALUES (36, '1734055399.296267', '1734055399.296267', 35, 'zookeeper未授权');
INSERT INTO `scan_total_time_table` VALUES (37, '1734055399.296267', '1734055399.296267', 36, ' ftp未授权');
INSERT INTO `scan_total_time_table` VALUES (38, '1734055399.296267', '1734055399.296267', 37, 'CouchDB未授权');
INSERT INTO `scan_total_time_table` VALUES (39, '1734055399.296267', '1734055399.296267', 38, ' docker未授权');
INSERT INTO `scan_total_time_table` VALUES (40, '1734055399.296267', '1734055399.296267', 39, ' Hadoop未授权');
INSERT INTO `scan_total_time_table` VALUES (41, '1734055399.296267', '1734055399.296267', 40, NULL);
INSERT INTO `scan_total_time_table` VALUES (42, '1734055399.296267', '1734055399.296267', 41, NULL);
INSERT INTO `scan_total_time_table` VALUES (43, '1734055399.296267', '1734055399.296267', 42, NULL);
INSERT INTO `scan_total_time_table` VALUES (44, '1734055399.296267', '1734055399.296267', 43, NULL);
INSERT INTO `scan_total_time_table` VALUES (45, '1734055399.296267', '1734055399.296267', 44, NULL);
INSERT INTO `scan_total_time_table` VALUES (46, '1734055399.296267', '1734055399.296267', 45, NULL);

SET FOREIGN_KEY_CHECKS = 1;
