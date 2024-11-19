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

 Date: 19/11/2024 15:21:47
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for route_status
-- ----------------------------
DROP TABLE IF EXISTS `route_status`;
CREATE TABLE `route_status`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `typename` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `typevalue` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of route_status
-- ----------------------------
INSERT INTO `route_status` VALUES (1, 'fofa', '1');

SET FOREIGN_KEY_CHECKS = 1;
