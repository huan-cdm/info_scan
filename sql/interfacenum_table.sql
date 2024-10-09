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

 Date: 09/10/2024 16:46:21
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for interfacenum_table
-- ----------------------------
DROP TABLE IF EXISTS `interfacenum_table`;
CREATE TABLE `interfacenum_table`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `successnum` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `failnum` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `interid` int(0) NULL DEFAULT NULL,
  `decrib` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of interfacenum_table
-- ----------------------------
INSERT INTO `interfacenum_table` VALUES (1, '13', '0', 1, 'fofa接口查询次数初始次数是0');
INSERT INTO `interfacenum_table` VALUES (2, '6', '0', 2, 'shodan接口查询次数初始次数是0');
INSERT INTO `interfacenum_table` VALUES (3, '2', '0', 3, '基础证书查询子域名接口初始次数是0');
INSERT INTO `interfacenum_table` VALUES (4, '5', '0', 4, 'icp网站备案查询接口初始次数是0');
INSERT INTO `interfacenum_table` VALUES (5, '1', '0', 5, '高德地图查询接口初始次数是0');
INSERT INTO `interfacenum_table` VALUES (6, '2', '0', 6, 'otx历史url查询接口初始次数是0');

SET FOREIGN_KEY_CHECKS = 1;
