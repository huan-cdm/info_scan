/*
 Navicat Premium Data Transfer

 Source Server         : 117.72.16.222
 Source Server Type    : MySQL
 Source Server Version : 80037
 Source Host           : 117.72.16.222:3306
 Source Schema         : vuln_scan_database

 Target Server Type    : MySQL
 Target Server Version : 80037
 File Encoding         : 65001

 Date: 23/08/2024 17:12:14
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
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of vuln_time_diff
-- ----------------------------
INSERT INTO `vuln_time_diff` VALUES (1, '1724404283.4737413');
INSERT INTO `vuln_time_diff` VALUES (2, '1724404283.5186772');
INSERT INTO `vuln_time_diff` VALUES (3, '1724404283.621506');
INSERT INTO `vuln_time_diff` VALUES (4, '1724404283.6919847');
INSERT INTO `vuln_time_diff` VALUES (5, '1724404283.764939');
INSERT INTO `vuln_time_diff` VALUES (6, '1724404283.8790371');
INSERT INTO `vuln_time_diff` VALUES (7, '1724404283.9663506');
INSERT INTO `vuln_time_diff` VALUES (8, '1724404284.1073413');
INSERT INTO `vuln_time_diff` VALUES (9, '1724404284.2572255');
INSERT INTO `vuln_time_diff` VALUES (10, '1724404284.3285947');
INSERT INTO `vuln_time_diff` VALUES (11, '1724404265.546095');
INSERT INTO `vuln_time_diff` VALUES (12, '1724404265.593695');
INSERT INTO `vuln_time_diff` VALUES (13, '1724404265.66369');

SET FOREIGN_KEY_CHECKS = 1;
