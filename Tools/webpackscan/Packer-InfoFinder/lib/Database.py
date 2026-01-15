# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import sqlite3,os,time
from urllib.parse import urlparse
from lib.common.CreatLog import creatLog


class DatabaseType():

    def __init__(self, project_tag):
        self.projectTag = project_tag
        self.log = creatLog().get_logger()

    def createDatabase(self):
        """
        优化后的主数据库创建函数
        - 增加连接超时时间（30秒）
        - 启用WAL模式提高并发性能
        - 添加重试机制
        - 优化数据库配置
        """
        maindatabasedb_path = "/TIP/info_scan/Tools/webpackscan/Packer-InfoFinder"
        # main_db_path = os.path.join(maindatabasedb_path, "main.db")  

        # path = os.getcwd() + os.sep + "main.db"
        path = maindatabasedb_path + "main.db"
        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                # 增加超时时间到30秒，避免批量扫描时锁竞争
                connect = sqlite3.connect(path, timeout=30.0)
                cursor = connect.cursor()

                # 启用WAL模式（Write-Ahead Logging）提高并发性能
                # WAL模式允许读写并发，大幅提升批量扫描时的性能
                cursor.execute('PRAGMA journal_mode=WAL')
                cursor.execute('PRAGMA synchronous=NORMAL')  # 平衡性能和安全性
                cursor.execute('PRAGMA cache_size=10000')  # 增加缓存
                cursor.execute('PRAGMA temp_store=MEMORY')  # 临时表存储在内存中

                # 创建表
                cursor.execute('''CREATE TABLE if not exists project(
                             id         INTEGER PRIMARY KEY     autoincrement,
                             tag        TEXT                    NOT NULL,
                             host       TEXT                            ,
                             time       INT                             ,
                             process    TEXT                            ,
                             finish     INT                             );''')
                connect.commit()
                connect.close()
                self.log.debug("主数据库创建成功（已启用WAL模式）")
                break

            except sqlite3.OperationalError as e:
                retry_count += 1
                if "database is locked" in str(e).lower() and retry_count < max_retries:
                    self.log.warning(f"[警告] 数据库被锁定，正在重试 ({retry_count}/{max_retries})...")
                    time.sleep(0.5 * retry_count)  # 递增延迟
                    continue
                else:
                    self.log.error(f"[Err] 创建主数据库失败: {e}")
                    break
            except Exception as e:
                self.log.error(f"[Err] 创建主数据库时发生未知错误: {e}")
                break

    def createProjectDatabase(self, url, type, cloneTag):
        """
        优化后的项目数据库创建函数
        - 增加超时和重试机制
        - 对主数据库写入添加重试逻辑
        - 使用事务确保数据一致性
        """
        if type == 1:
            typeValue = "simple"
        else:
            typeValue = "adv"
        unixTime = int(time.time())
        res = urlparse(url)
        domain = res.netloc
        if ":" in domain:
            domain = str(domain).replace(":","_")

        # 确保tmp目录存在
        tmp_dir = "/TIP/info_scan/Tools/webpackscan/Packer-InfoFinder/tmp"
        if not os.path.exists(tmp_dir):
            try:
                os.makedirs(tmp_dir, exist_ok=True)
            except Exception as e:
                self.log.error(f"[Err] 无法创建tmp目录: {e}")
                # 继续执行，尝试使用相对路径

        # 创建项目特定目录
        project_dir = tmp_dir + os.sep + self.projectTag + "_" + domain
        if not os.path.exists(project_dir):
            try:
                os.makedirs(project_dir, exist_ok=True)
            except Exception as e:
                self.log.error(f"[Err] 无法创建项目目录: {e}")
                # 继续执行，尝试使用相对路径

        PATH = project_dir + os.sep + self.projectTag + ".db"

        try:
            # 使用绝对路径确保文件位置正确
            db_path = os.path.abspath(os.sep.join(PATH.split('/')))
            # 增加超时时间到30秒
            connect = sqlite3.connect(db_path, timeout=30.0)
            cursor = connect.cursor()

            # 启用WAL模式和性能优化
            cursor.execute('PRAGMA journal_mode=WAL')
            cursor.execute('PRAGMA synchronous=NORMAL')
            cursor.execute('PRAGMA cache_size=5000')

            # 创建表
            cursor.execute('''CREATE TABLE if not exists info(
                         name       TEXT    PRIMARY KEY     NOT NULL,
                         vaule      TEXT                            );''')
            cursor.execute('''CREATE TABLE if not exists js_file(
                         id         INTEGER PRIMARY KEY     autoincrement,
                         name       TEXT                    NOT NULL,
                         path       TEXT                            ,
                         local      TEXT                            ,
                         success    INT                             ,
                         spilt      INT                             ,
                         discovery_source TEXT DEFAULT 'static_html',
                         parent_url TEXT                            ,
                         iframe_depth INTEGER DEFAULT 0             );''')
            cursor.execute('''CREATE TABLE if not exists js_split_tree(
                         id         INTEGER PRIMARY KEY     autoincrement,
                         jsCode    TEXT                            ,
                         js_name    TEXT                            ,
                         js_result  TEXT                            ,
                         success    INT                             );''')
            cursor.execute('''CREATE TABLE if not exists api_tree(
                         id         INTEGER PRIMARY KEY     autoincrement,
                         path       TEXT                            ,
                         name       TEXT                    NOT NULL,


                         from_js    INT                             );''')



            # 使用参数化查询防止SQL注入，并插入数据
            cursor.execute("insert into info values('time', ?)", (str(unixTime),))
            cursor.execute("insert into info values('url', ?)", (url,))
            cursor.execute("insert into info values('host', ?)", (domain,))
            cursor.execute("insert into info values('type', ?)", (typeValue,))
            cursor.execute("insert into info values('tag', ?)", (self.projectTag,))
            cursor.execute("insert into info (name) VALUES ('clone')")
            connect.commit()
            connect.close()

            # 对主数据库的写入添加重试机制（批量扫描时容易锁竞争）
            # 定义绝对路径
            maindatabasedb_path = "/TIP/info_scan/Tools/webpackscan/Packer-InfoFinder"
            main_db_path = os.path.join(maindatabasedb_path, "main.db")    
            # main_db_path = os.path.abspath(os.getcwd() + os.sep + "main.db")
            max_retries = 5
            retry_count = 0

            while retry_count < max_retries:
                try:
                    conn2 = sqlite3.connect(main_db_path, timeout=30.0)
                    cursor2 = conn2.cursor()

                    # 使用参数化查询
                    sql = "INSERT into project (tag, host, time) VALUES (?, ?, ?)"
                    cursor2.execute(sql, (self.projectTag, domain, unixTime))
                    conn2.commit()
                    conn2.close()
                    break  # 成功则跳出循环

                except sqlite3.OperationalError as e:
                    retry_count += 1
                    if "database is locked" in str(e).lower() and retry_count < max_retries:
                        self.log.warning(f"[警告] 主数据库被锁定，正在重试 ({retry_count}/{max_retries})...")
                        time.sleep(0.5 * retry_count)  # 递增延迟
                        continue
                    else:
                        self.log.error(f"[Err] 写入主数据库失败: {e}")
                        break
                except Exception as e:
                    self.log.error(f"[Err] 写入主数据库时发生未知错误: {e}")
                    break

            self.log.debug("项目数据库创建成功")

        except sqlite3.OperationalError as e:
            self.log.error(f"[Err] 创建项目数据库失败（操作错误）: {e}")
        except Exception as e:
            self.log.error(f"[Err] 创建项目数据库失败: {e}")

    def getPathfromDB(self):
        """优化后的路径获取方法 - 增加超时和异常处理"""
        maindatabasedb_path = "/TIP/info_scan/Tools/webpackscan/Packer-InfoFinder"
        path = maindatabasedb_path+ "main.db"
        
        # main_db_path = os.path.join(maindatabasedb_path, "main.db")  

        # path = os.getcwd() + os.sep + "main.db"
        # path = maindatabasedb_path + "main.db"
        try:
            conn = sqlite3.connect(path, timeout=30.0)
            cursor = conn.cursor()
            # 使用参数化查询
            cursor.execute("select host from project where tag = ?", (self.projectTag,))
            result = cursor.fetchone()
            conn.close()

            if result:
                host = result[0]
                projectPath = "tmp" + os.sep + self.projectTag + "_" + host + os.sep
                return projectPath
            else:
                self.log.error(f"[Err] 未找到项目标签: {self.projectTag}")
                return None
        except Exception as e:
            self.log.error(f"[Err] 获取项目路径失败: {e}")
            return None

    def getJsUrlFromDB(self, localFileName, projectPath):
        """优化后的JS URL获取方法"""
        projectDBPath = projectPath + self.projectTag + ".db"
        try:
            conn = sqlite3.connect(projectDBPath, timeout=30.0)
            cursor = conn.cursor()
            # 使用参数化查询
            cursor.execute("select path from js_file where local = ?", (localFileName,))
            result = cursor.fetchone()
            conn.close()

            if result:
                return result[0]
            else:
                self.log.warning(f"[警告] 未找到本地文件: {localFileName}")
                return None
        except Exception as e:
            self.log.error(f"[Err] 获取JS URL失败: {e}")
            return None

    def getJsIDFromDB(self, localFileName, projectPath):
        """优化后的JS ID获取方法"""
        projectDBPath = projectPath + self.projectTag + ".db"
        try:
            conn = sqlite3.connect(projectDBPath, timeout=30.0)
            cursor = conn.cursor()
            # 使用参数化查询
            cursor.execute("select id from js_file where local = ?", (localFileName,))
            result = cursor.fetchone()
            conn.close()

            if result:
                return result[0]
            else:
                self.log.warning(f"[警告] 未找到本地文件ID: {localFileName}")
                return None
        except Exception as e:
            self.log.error(f"[Err] 获取JS ID失败: {e}")
            return None

    def apiRecordToDB(self, js_path, api_path):
        projectPath = DatabaseType(self.projectTag).getPathfromDB()
        projectDBPath = projectPath + self.projectTag + ".db"
        connect = sqlite3.connect(os.sep.join(projectDBPath.split('/')))
        cursor = connect.cursor()
        localFileName = js_path.split(os.sep)[-1]
        jsFileID = DatabaseType(self.projectTag).getJsIDFromDB(localFileName, projectPath)
        connect.isolation_level = None
        sql = "insert into api_tree(path,name,from_js) values(\"" + api_path + "\",\"" + api_path.split("/")[
            -1] + "\"," + str(jsFileID) + ")"
        cursor.execute(sql)
        connect.commit()
        connect.close()


    # 获取数据库里面的path
    def apiPathFromDB(self):
        apis = []
        projectPath = DatabaseType(self.projectTag).getPathfromDB()
        projectDBPath = projectPath + self.projectTag + ".db"
        conn = sqlite3.connect(projectDBPath)
        cursor = conn.cursor()
        conn.isolation_level = None
        cursor.execute("select path from api_tree")
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            # print("".join(row))
            api = "".join(row)
            apis.append(api)
        return apis


    def getURLfromDB(self):
        """优化后的URL获取方法"""
        projectPath = DatabaseType(self.projectTag).getPathfromDB()
        if not projectPath:
            return None

        projectDBPath = projectPath + self.projectTag + ".db"
        try:
            conn = sqlite3.connect(projectDBPath, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute("select vaule from info where name = 'url'")
            result = cursor.fetchone()
            conn.close()

            if result:
                return result[0]
            else:
                self.log.warning("[警告] 未找到URL信息")
                return None
        except Exception as e:
            self.log.error(f"[Err] 获取URL失败: {e}")
            return None


