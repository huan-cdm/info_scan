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

 Date: 13/09/2024 13:44:35
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for info_time_diff
-- ----------------------------
DROP TABLE IF EXISTS `info_time_diff`;
CREATE TABLE `info_time_diff`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `time_diff` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of info_time_diff
-- ----------------------------
INSERT INTO `info_time_diff` VALUES (1, '1724744415.1523805');
INSERT INTO `info_time_diff` VALUES (2, '1726022376.1907308');
INSERT INTO `info_time_diff` VALUES (3, '1724744415.241787');
INSERT INTO `info_time_diff` VALUES (4, '1724744415.3084066');
INSERT INTO `info_time_diff` VALUES (5, '1726190650.8981938');
INSERT INTO `info_time_diff` VALUES (6, '1726190650.8981938');
INSERT INTO `info_time_diff` VALUES (7, '1726190650.8981938');
INSERT INTO `info_time_diff` VALUES (8, '1726190650.8981938');
INSERT INTO `info_time_diff` VALUES (9, '1726190650.8981938');
INSERT INTO `info_time_diff` VALUES (10, '1726190650.8981938');

SET FOREIGN_KEY_CHECKS = 1;
