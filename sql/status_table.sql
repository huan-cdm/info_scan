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

 Date: 26/07/2024 15:06:48
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for status_table
-- ----------------------------
DROP TABLE IF EXISTS `status_table`;
CREATE TABLE `status_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `status_value` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of status_table
-- ----------------------------
INSERT INTO `status_table` VALUES (1, '识别重点资产已完成');
INSERT INTO `status_table` VALUES (2, '已完成springboot漏洞扫描');

SET FOREIGN_KEY_CHECKS = 1;
