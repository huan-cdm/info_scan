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

 Date: 09/09/2024 16:23:37
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
) ENGINE = InnoDB AUTO_INCREMENT = 16 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of vuln_time_diff
-- ----------------------------
INSERT INTO `vuln_time_diff` VALUES (1, '1724838623.4747577');
INSERT INTO `vuln_time_diff` VALUES (2, '1724740341.7877247');
INSERT INTO `vuln_time_diff` VALUES (3, '1724661728.2483444');
INSERT INTO `vuln_time_diff` VALUES (4, '1724658544.0025449');
INSERT INTO `vuln_time_diff` VALUES (5, '1724658544.0690985');
INSERT INTO `vuln_time_diff` VALUES (6, '1724741299.5538535');
INSERT INTO `vuln_time_diff` VALUES (7, '1724663321.6490097');
INSERT INTO `vuln_time_diff` VALUES (8, '1724664128.1036596');
INSERT INTO `vuln_time_diff` VALUES (9, '1724658544.488516');
INSERT INTO `vuln_time_diff` VALUES (10, '1724658544.6377418');
INSERT INTO `vuln_time_diff` VALUES (11, '1724727845.795996');
INSERT INTO `vuln_time_diff` VALUES (12, '1724658544.8673444');
INSERT INTO `vuln_time_diff` VALUES (13, '1724404603.553185');
INSERT INTO `vuln_time_diff` VALUES (14, '1725604050.8838062');
INSERT INTO `vuln_time_diff` VALUES (15, '1725243767.781577');
INSERT INTO `vuln_time_diff` VALUES (16, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (17, '1725867598.1682694');
INSERT INTO `vuln_time_diff` VALUES (18, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (19, '1725522995.515026');
INSERT INTO `vuln_time_diff` VALUES (20, '1725522995.515026');

SET FOREIGN_KEY_CHECKS = 1;
