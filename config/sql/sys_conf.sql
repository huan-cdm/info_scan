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

 Date: 07/05/2025 17:13:45
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for sys_conf
-- ----------------------------
DROP TABLE IF EXISTS `sys_conf`;
CREATE TABLE `sys_conf`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `info_session_time` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `fofa_email` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `fofa_key` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_conf
-- ----------------------------
INSERT INTO `sys_conf` VALUES (1, '60', NULL, NULL);
INSERT INTO `sys_conf` VALUES (2, NULL, 'test@qq.com', '1231426ed6a3f3b84518312e12388b6b53012');
INSERT INTO `sys_conf` VALUES (3, '1235wdqqD7mCbWQdehFqWhk5aKVK0OtwR0Z12', NULL, '');
INSERT INTO `sys_conf` VALUES (4, '1232c0f28df8ad2748d51f49d8a075c6c8812', NULL, '');
INSERT INTO `sys_conf` VALUES (5, '1231c9ca5b4d4eebd74f3b77675c919005b12', NULL, '');
INSERT INTO `sys_conf` VALUES (6, 'test.ceye.io', NULL, NULL);

SET FOREIGN_KEY_CHECKS = 1;
