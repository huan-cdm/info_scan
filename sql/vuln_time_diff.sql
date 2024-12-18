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

 Date: 17/12/2024 17:18:33
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for vuln_time_diff
-- ----------------------------
DROP TABLE IF EXISTS `vuln_time_diff`;
CREATE TABLE `vuln_time_diff`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `time_diff` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 30 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of vuln_time_diff
-- ----------------------------
INSERT INTO `vuln_time_diff` VALUES (1, '1732245351.7159686');
INSERT INTO `vuln_time_diff` VALUES (2, '1732245351.7665136');
INSERT INTO `vuln_time_diff` VALUES (3, '1732245351.8578331');
INSERT INTO `vuln_time_diff` VALUES (4, '1732245351.9284198');
INSERT INTO `vuln_time_diff` VALUES (5, '1732245352.1234403');
INSERT INTO `vuln_time_diff` VALUES (6, '1732245353.1126816');
INSERT INTO `vuln_time_diff` VALUES (7, '1732245353.2856026');
INSERT INTO `vuln_time_diff` VALUES (8, '1733971521.2776482');
INSERT INTO `vuln_time_diff` VALUES (9, '1732245353.691496');
INSERT INTO `vuln_time_diff` VALUES (10, '1732245353.9012265');
INSERT INTO `vuln_time_diff` VALUES (11, '1732245354.3808692');
INSERT INTO `vuln_time_diff` VALUES (12, '1733994003.4802892');
INSERT INTO `vuln_time_diff` VALUES (13, '1724404603.553185');
INSERT INTO `vuln_time_diff` VALUES (14, '1734400494.2649791');
INSERT INTO `vuln_time_diff` VALUES (15, '1732245352.5022569');
INSERT INTO `vuln_time_diff` VALUES (16, '1732245352.6978216');
INSERT INTO `vuln_time_diff` VALUES (17, '1733906217.6128004');
INSERT INTO `vuln_time_diff` VALUES (18, '1730030295.285501');
INSERT INTO `vuln_time_diff` VALUES (19, '1733970770.4706767');
INSERT INTO `vuln_time_diff` VALUES (20, '1733993953.900041');
INSERT INTO `vuln_time_diff` VALUES (21, '1733993953.9390526');
INSERT INTO `vuln_time_diff` VALUES (22, '1733993954.0584261');
INSERT INTO `vuln_time_diff` VALUES (23, '1733993954.1644063');
INSERT INTO `vuln_time_diff` VALUES (24, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (25, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (26, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (27, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (28, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (29, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (30, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (31, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (32, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (33, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (34, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (35, '1725522995.515026');
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

SET FOREIGN_KEY_CHECKS = 1;
