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

 Date: 22/05/2025 09:55:44
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

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
INSERT INTO `verification_table` VALUES (2, '1');

SET FOREIGN_KEY_CHECKS = 1;
