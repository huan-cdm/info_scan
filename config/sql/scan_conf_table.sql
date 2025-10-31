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

 Date: 31/10/2025 10:59:39
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

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
INSERT INTO `scan_conf_table` VALUES (2, '1');
INSERT INTO `scan_conf_table` VALUES (3, '1');
INSERT INTO `scan_conf_table` VALUES (4, '1');
INSERT INTO `scan_conf_table` VALUES (5, '1');
INSERT INTO `scan_conf_table` VALUES (6, '1');

SET FOREIGN_KEY_CHECKS = 1;
