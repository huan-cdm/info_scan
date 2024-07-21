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

 Date: 21/07/2024 19:08:58
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for rule_table
-- ----------------------------
DROP TABLE IF EXISTS `rule_table`;
CREATE TABLE `rule_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `rule` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of rule_table
-- ----------------------------
INSERT INTO `rule_table` VALUES (2, 'Struts2');
INSERT INTO `rule_table` VALUES (3, 'Shiro');

SET FOREIGN_KEY_CHECKS = 1;
