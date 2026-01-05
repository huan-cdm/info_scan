#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os, re, sqlite3
from urllib.parse import urlparse, urljoin
from lib.common.utils import Utils
from lib.Database import DatabaseType
from lib.DownloadJs import DownloadJs
from lib.common.CreatLog import creatLog
import deno_vm
import esprima

class RecoverSpilt():

    def __init__(self, projectTag, options):
        self.projectTag = projectTag
        self.options = options
        self.log = creatLog().get_logger()
        self.processed_files = set()
        self.pending_js_files = set()
        self.js_split_id_counter = 1

    def _get_db_connection(self):
        projectDBPath = DatabaseType(self.projectTag).getPathfromDB() + self.projectTag + ".db"
        conn = sqlite3.connect(os.sep.join(projectDBPath.split('/')))
        conn.isolation_level = None
        return conn

    def _execute_in_deno(self, js_code_func, name_list):
        filenames_found = set()
        with deno_vm.VM() as vm:
            vm.run(js_code_func)
            for name in name_list:
                try:
                    param = int(name) if name.isdigit() else name
                    result = vm.call("js_compile", param)
                    if result and "undefined" not in str(result):
                        filenames_found.add(str(result))
                except Exception:
                    continue
        return filenames_found

    def _sanitize_code_body(self, code_body):
        """
        移除运行时 publicPath 前缀（*.p +），避免依赖外部上下文。
        例如：i.p + "static/js/" -> "static/js/"
        """
        try:
            sanitized = re.sub(r"[A-Za-z_$][\w$]*\.p\s*\+\s*", "", code_body)
            sanitized = re.sub(r"__webpack_require__\.p\s*\+\s*", "", sanitized)
            return sanitized
        except Exception:
            return code_body

    def _extract_keys_robust(self, code_text):
        """
        解析对象字面量的键，兼容 引号/标识符/数字键，用于枚举可能的 chunkId/name。
        """
        try:
            keys = re.findall(r'[{,]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:', code_text)
            result = set()
            for a, b, c, d in keys:
                key = a or b or c or d
                if key is not None and key != "":
                    result.add(str(key))
            return list(result)
        except Exception:
            return []

    def _extract_keys_followed_by_param(self, code_text, param_name):
        """
        在 return 表达式中，优先提取 "{...}[param]" 这种紧邻对象取下标的键集合，
        使用平衡括号向后/向前扫描，兼容对象值内部包含嵌套花括号的情况。
        """
        try:
            results = set()
            bracket_pat = re.compile(r"\[\s*" + re.escape(param_name) + r"\s*\]")
            for m in bracket_pat.finditer(code_text):
                idx = m.start() - 1
                # 跳过空白与外围括号包裹
                while idx >= 0 and code_text[idx].isspace():
                    idx -= 1
                # 若遇到右括号，回退到与之匹配的左括号（处理 ({...})[e] 情况）
                if idx >= 0 and code_text[idx] == ')':
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == ')':
                            depth += 1
                        elif ch == '(':
                            depth -= 1
                        idx -= 1
                    while idx >= 0 and code_text[idx].isspace():
                        idx -= 1
                # 现在应位于 '}' 处；向前做花括号配对，截出 { ... }
                if idx >= 0 and code_text[idx] == '}':
                    end_brace = idx
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == '}':
                            depth += 1
                        elif ch == '{':
                            depth -= 1
                        idx -= 1
                    start_brace = idx + 1
                    if start_brace >= 0 and end_brace > start_brace:
                        obj_text = code_text[start_brace:end_brace+1]
                        keys = re.findall(r'[{,]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:', obj_text)
                        for a,b,c,d in keys:
                            k = a or b or c or d
                            if k:
                                results.add(str(k))
            return list(results)
        except Exception:
            return []

    def _extract_keys_by_ast(self, code_text):
        """
        使用 esprima 对表达式进行 AST 解析，直接提取其中所有 ObjectExpression 的键。
        作为正则失败时的通用兜底方案。
        """
        try:
            wrapper = f"function __W(e){{ return {code_text}; }}"
            ast = esprima.parseScript(wrapper, {'range': True, 'tolerant': True})
            found = set()

            def walk(node):
                if not node or not isinstance(node, esprima.nodes.Node):
                    return
                if getattr(node, 'type', None) == 'ObjectExpression':
                    for prop in getattr(node, 'properties', []):
                        key_node = getattr(prop, 'key', None)
                        k = None
                        if key_node is None:
                            continue
                        # Identifier key
                        if hasattr(key_node, 'name') and key_node.name is not None:
                            k = key_node.name
                        # Literal key (string/number)
                        elif hasattr(key_node, 'value') and key_node.value is not None:
                            k = str(key_node.value)
                        if k is not None and k != "":
                            found.add(str(k))
                # walk children
                for attr in dir(node):
                    if attr.startswith('_'):
                        continue
                    child = getattr(node, attr)
                    if isinstance(child, esprima.nodes.Node):
                        walk(child)
                    elif isinstance(child, list):
                        for it in child:
                            if isinstance(it, esprima.nodes.Node):
                                walk(it)

            walk(ast)
            return list(found)
        except Exception:
            return []

    def _find_indexed_vars(self, code_text, param_name):
        """
        在返回表达式中查找形如: ident[param_name] 的下标访问，返回 ident 列表。
        例如返回 ['t','n'] 对应 t[e], n[e]。
        """
        try:
            idents = re.findall(r"([A-Za-z_$][\w$]*)\s*\[\s*" + re.escape(param_name) + r"\s*\]", code_text)
            return list(set(idents))
        except Exception:
            return []

    def _extract_object_keys_from_parent_by_ast(self, var_names, parent_js_content):
        """
        在父JS内容中，使用AST查找 变量=对象字面量 的定义，从而提取键集合。
        支持: var/let/const 声明中的 ObjectExpression，或赋值表达式中的 ObjectExpression。
        """
        results = set()
        try:
            ast = esprima.parseScript(parent_js_content, {'range': True, 'tolerant': True})
        except Exception:
            return results

        def collect_from_object(obj_expr):
            for prop in getattr(obj_expr, 'properties', []):
                key_node = getattr(prop, 'key', None)
                k = None
                if key_node is None:
                    continue
                if hasattr(key_node, 'name') and key_node.name is not None:
                    k = key_node.name
                elif hasattr(key_node, 'value') and key_node.value is not None:
                    k = str(key_node.value)
                if k is not None and k != "":
                    results.add(str(k))

        def walk(node):
            if not node or not isinstance(node, esprima.nodes.Node):
                return
            ntype = getattr(node, 'type', None)
            if ntype == 'VariableDeclarator':
                id_node = getattr(node, 'id', None)
                init = getattr(node, 'init', None)
                if id_node and getattr(id_node, 'name', None) in var_names and getattr(init, 'type', None) == 'ObjectExpression':
                    collect_from_object(init)
            elif ntype == 'AssignmentExpression' and getattr(node, 'operator', None) == '=':
                left = getattr(node, 'left', None)
                right = getattr(node, 'right', None)
                if getattr(right, 'type', None) == 'ObjectExpression':
                    # 情况1：简单变量赋值  v = { ... }
                    if getattr(left, 'type', None) == 'Identifier' and getattr(left, 'name', None) in var_names:
                        collect_from_object(right)
                    # 情况2：对象属性赋值  obj.v = { ... } 或 obj["v"] = { ... }
                    elif getattr(left, 'type', None) == 'MemberExpression':
                        prop = getattr(left, 'property', None)
                        pname = None
                        if prop is not None:
                            if getattr(left, 'computed', False):
                                # obj["v"]
                                if hasattr(prop, 'value') and prop.value is not None:
                                    pname = str(prop.value)
                            else:
                                # obj.v
                                if hasattr(prop, 'name') and prop.name is not None:
                                    pname = prop.name
                        if pname in var_names:
                            collect_from_object(right)
            for attr in dir(node):
                if attr.startswith('_'):
                    continue
                child = getattr(node, attr)
                if isinstance(child, esprima.nodes.Node):
                    walk(child)
                elif isinstance(child, list):
                    for it in child:
                        if isinstance(it, esprima.nodes.Node):
                            walk(it)

        walk(ast)
        return results

    def _iter_object_texts_for_param(self, code_text, param_name):
        """
        返回表达式中，找到所有形如 { ... }[param_name] 的对象文本（包含花括号）。
        使用平衡括号向后/向前扫描，避免被嵌套干扰。
        """
        texts = []
        try:
            bracket_pat = re.compile(r"\[\s*" + re.escape(param_name) + r"\s*\]")
            for m in bracket_pat.finditer(code_text):
                idx = m.start() - 1
                while idx >= 0 and code_text[idx].isspace():
                    idx -= 1
                if idx >= 0 and code_text[idx] == ')':
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == ')':
                            depth += 1
                        elif ch == '(':
                            depth -= 1
                        idx -= 1
                    while idx >= 0 and code_text[idx].isspace():
                        idx -= 1
                if idx >= 0 and code_text[idx] == '}':
                    end_brace = idx
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == '}':
                            depth += 1
                        elif ch == '{':
                            depth -= 1
                        idx -= 1
                    start_brace = idx + 1
                    if start_brace >= 0 and end_brace > start_brace:
                        texts.append(code_text[start_brace:end_brace+1])
        except Exception:
            pass
        return texts

    def _find_balanced_block(self, text, start_pos):
        """
        从 start_pos 处的 '{' 开始，返回与之匹配的大括号内的文本（不包含最外层花括号）。
        尽量忽略字符串中的花括号干扰（简单跳过引号片段）。
        """
        try:
            n = len(text)
            if start_pos < 0 or start_pos >= n or text[start_pos] != '{':
                return ''
            depth = 0
            i = start_pos
            while i < n:
                ch = text[i]
                if ch == '"' or ch == '\'':
                    q = ch
                    i += 1
                    # 跳过带转义的字符串内容
                    while i < n:
                        if text[i] == '\\':
                            i += 2
                            continue
                        if text[i] == q:
                            i += 1
                            break
                        i += 1
                    continue
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return text[start_pos+1:i]
                i += 1
        except Exception:
            pass
        return ''

    def _extract_return_expr_from_func_body(self, body_text):
        """
        从函数体中提取第一条 return 表达式（不含分号）。
        """
        try:
            m = re.search(r"\breturn\b", body_text)
            if not m:
                return ''
            rest = body_text[m.end():]
            semi = rest.find(';')
            if semi != -1:
                return rest[:semi]
            return rest.strip()
        except Exception:
            return ''

    def _parse_kv_from_object_text(self, obj_text):
        """
        从对象字面量文本中解析 key->value（字符串/标识符/数字）映射。
        仅做简单场景解析，足以应对 webpack 名称与 hash 映射。
        """
        mapping = {}
        try:
            pat = re.compile(r'[{},]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))')
            for a,b,c,d,e,f,g,h in pat.findall(obj_text):
                k = a or b or c or d
                v = e or f or g or h
                if k is not None and v is not None and k != "":
                    mapping[str(k)] = str(v)
        except Exception:
            pass
        return mapping

    def _extract_string_literals(self, code_text):
        """
        提取表达式内出现的字符串字面量（保持出现顺序）。
        """
        strings = []
        try:
            for m in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', code_text):
                s = m.group(1) if m.group(1) is not None else m.group(2)
                strings.append(s)
        except Exception:
            pass
        return strings

    def _try_build_filenames_without_vm(self, sanitized, param_name, name_list):
        """
        不依赖 Deno VM，通过结构化模板组装方式生成候选 chunk 文件名。
        典型模式: "prefix/" + ({nameMap}[e]||e) + "." + {hashMap}[e] + ".js"
        """
        filenames = set()
        try:
            obj_texts = self._iter_object_texts_for_param(sanitized, param_name)
            maps = [self._parse_kv_from_object_text(t) for t in obj_texts]
            maps = [m for m in maps if m]
            if not maps:
                # 当未能解析到对象映射时，仍按“字符串前缀 + 名称 + 扩展 + 可选查询串”进行模板组装
                strings = self._extract_string_literals(sanitized)
                prefix = ''
                try:
                    banned_ext = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|json|txt|html?)$', re.I)
                    # 优先选择看起来像“目录”的字符串作为前缀（以 / 结尾）
                    dir_like = [s for s in strings if s.endswith('/') and not banned_ext.search(s)]
                    # 进一步优先包含 js/assets/static/scripts 目录
                    preferred = [s for s in dir_like if re.search(r'(?:^|/)(?:js|assets|static|scripts)/$', s)]
                    if preferred:
                        prefix = preferred[0]
                    elif dir_like:
                        prefix = dir_like[0]
                    else:
                        # 退而求其次：包含 / 但不以常见文件扩展名结尾
                        cand = [s for s in strings if '/' in s and not banned_ext.search(s)]
                        prefix = cand[0] if cand else ''
                except Exception:
                    pass
                # 最终兜底
                if not prefix and strings:
                    prefix = strings[0] if strings[0].endswith('/') else ''

                ext = 'js'
                qs = ''
                # 优先从字符串字面量中自右向左匹配允许的扩展
                for s in reversed(strings):
                    m = re.search(r'\.(js|mjs)(\?[^"\']*)?$', s)
                    if m:
                        ext = m.group(1)
                        qs = m.group(2) or ''
                        break
                # 仍未命中时，从表达式中全局搜索一次
                if not qs and ext == 'js':
                    m2 = re.search(r'\.(js|mjs)(\?[^"\'\s]*)?', sanitized)
                    if m2:
                        ext = m2.group(1)
                        qs = m2.group(2) or ''
                # 再兜底找独立的 ?query 字面量
                if not qs:
                    for s in reversed(strings):
                        if '?' in s:
                            qs = s[s.find('?'):]
                            break
                # 在明确的加载器上下文内（任意 X[e] + ".js"）不做严格白名单过滤
                # 兼容变量形式的映射（如 r[e]），以及内联对象字面量（{...}[e]）
                context_is_loader = bool(re.search(r"\[\s*" + re.escape(param_name) + r"\s*\][\s\S]{0,120}['\"]\.(?:js|mjs)['\"]", sanitized))
                def _looks_chunk_like(n: str) -> bool:
                    return bool(re.fullmatch(r'(?:chunk-[0-9a-f]{8}|2d[0-9a-f]{6,})', str(n), re.I))
                names_to_use = name_list if context_is_loader else [n for n in name_list if _looks_chunk_like(n)]
                if not names_to_use:
                    return set()
                for name in names_to_use:
                    filenames.add(f"{prefix}{name}.{ext}{qs}")
                return filenames

            # 识别 nameMap 与 hashMap（启发式）：
            def is_hexish(s):
                return bool(re.fullmatch(r'[0-9a-fA-F]{4,}', s or ''))
            name_map = {}
            hash_map = {}
            if len(maps) == 1:
                # 仅发现一张映射表时，使用启发式判断其角色：
                only = maps[0]
                vals = list(only.values())[:50]
                def is_hexish(s):
                    return bool(re.fullmatch(r'[0-9a-fA-F]{4,}', s or ''))
                hex_ratio = sum(1 for v in vals if is_hexish(v)) / max(1, len(vals))
                eq_ratio = sum(1 for k, v in only.items() if k == v) / max(1, len(only))
                # 更像 hash 的当作 hash_map；否则当作 name_map
                if hex_ratio >= 0.5 and eq_ratio < 0.5:
                    hash_map = only
                    name_map = {}
                else:
                    name_map = only
            else:
                # 选择“更像 hash”的为 hash_map，另一者为 name_map
                scored = []
                for mp in maps:
                    vals = list(mp.values())[:50]
                    hex_ratio = sum(1 for v in vals if is_hexish(v)) / max(1, len(vals))
                    eq_ratio = sum(1 for k,v in mp.items() if k == v) / max(1, len(mp))
                    scored.append((hex_ratio, eq_ratio, mp))
                scored.sort(key=lambda x: (x[0], -x[1]), reverse=True)
                hash_map = scored[0][2]
                # 选择另一张作为 name_map
                for _, _, mp in scored[1:]:
                    if mp is not hash_map:
                        name_map = mp
                        break
                if not name_map:
                    name_map = hash_map

            # 提取前缀、扩展名与查询串
            strings = self._extract_string_literals(sanitized)
            prefix = ''
            try:
                banned_ext = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|json|txt|html?)$', re.I)
                dir_like = [s for s in strings if s.endswith('/') and not banned_ext.search(s)]
                preferred = [s for s in dir_like if re.search(r'(?:^|/)(?:js|assets|static|scripts)/$', s)]
                if preferred:
                    prefix = preferred[0]
                elif dir_like:
                    prefix = dir_like[0]
                else:
                    cand = [s for s in strings if '/' in s and not banned_ext.search(s)]
                    prefix = cand[0] if cand else ''
            except Exception:
                pass
            if not prefix and strings:
                prefix = strings[0] if strings[0].endswith('/') else ''

            # 仅从允许集合中识别扩展名（js/mjs/css），避免误把 .admin 等当作扩展
            ext = 'js'
            qs = ''
            # 优先从字符串字面量自右向左匹配 .js/.mjs
            for s in reversed(strings):
                m = re.search(r'\.(js|mjs)(\?[^"\']*)?$', s)
                if m:
                    ext = m.group(1)
                    qs = m.group(2) or ''
                    break
            # 如未命中，再从表达式整体搜索一次
            if not qs and ext == 'js':
                m2 = re.search(r'\.(js|mjs)(\?[^"\'\s]*)?', sanitized)
                if m2:
                    ext = m2.group(1)
                    qs = m2.group(2) or ''
            # 再兜底从独立字面量里找 ?query
            if not qs:
                for s in reversed(strings):
                    if '?' in s:
                        idx = s.find('?')
                        qs = s[idx:]
                        break

            # 生成文件名（当存在 hash_map 时，只为命中 hash 的 name 生成；否则允许 name.ext）
            for name in name_list:
                nm = name_map.get(name, name)
                hv = hash_map.get(name, '')
                if hv:
                    filenames.add(f"{prefix}{nm}.{hv}.{ext}{qs}")
                else:
                    if not hash_map:
                        filenames.add(f"{prefix}{nm}.{ext}{qs}")
            return filenames

            '''

            for name in name_list:
                nm = name_map.get(name, name)
                hv = hash_map.get(name, '')
                if hv:
                    filenames.add(f"{prefix}{nm}.{hv}.{ext}{qs}")
                else:
                    # 
2a6 hash_map 4176fc66804e288f5170f60951580f
                    if not hash_map:
                        filenames.add(f"{prefix}{nm}.{ext}{qs}")
            '''

        except Exception:

            for name in name_list:
                nm = name_map.get(name, name)
                hv = hash_map.get(name, '')
                if hv:
                    filenames.add(f"{prefix}{nm}.{hv}.{ext}{qs}")
                else:
                    if not hash_map:
                        filenames.add(f"{prefix}{nm}.{ext}{qs}")

            
        return filenames


    def _extract_object_keys_from_parent_by_regex(self, var_names, parent_js_content):
        """
        正则兜底：在父JS中查找 ident = { ... } 的对象字面量，并解析其键。
        """
        results = set()
        try:
            for v in var_names:
                # 1) var/let/const v = { ... }
                pat = re.compile(r"(?:var|let|const)\s+" + re.escape(v) + r"\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                m = pat.search(parent_js_content)
                # 2) v = { ... }
                if not m:
                    pat2 = re.compile(r"\b" + re.escape(v) + r"\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                    m = pat2.search(parent_js_content)
                # 3) obj.v = { ... }
                if not m:
                    pat3 = re.compile(r"[A-Za-z_$][\w$]*\s*\.\s*" + re.escape(v) + r"\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                    m = pat3.search(parent_js_content)
                # 4) obj["v"] = { ... }
                if not m:
                    pat4 = re.compile(r"[A-Za-z_$][\w$]*\s*\[\s*([\"\'])" + re.escape(v) + r"\1\s*\]\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                    m = pat4.search(parent_js_content)
                if m:
                    # 对于 pat4，分组不同，统一取最后一个分组作为对象体
                    obj_body = m.group(m.lastindex) if m.lastindex else m.group(1)
                    keys = re.findall(r'[{,]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:', '{'+obj_body+'}')
                    for a,b,c,d in keys:
                        k = a or b or c or d
                        if k:
                            results.add(str(k))
        except Exception:
            pass
        return results


    def compile_from_ast(self, code_body, param_name, jsFilePath, parent_js_content):
        try:
            # 1) 去除 runtime publicPath 前缀，避免依赖 i.p/__webpack_require__.p
            sanitized = self._sanitize_code_body(code_body)
            # 2) 优先提取与参数相邻的对象键，其次鲁棒正则，再用 AST 作为兜底
            nameList = list(set(self._extract_keys_followed_by_param(sanitized, param_name)))
            if not nameList:
                nameList = list(set(self._extract_keys_robust(sanitized)))
            if not nameList:
                nameList = list(set(self._extract_keys_by_ast(sanitized)))
            if not nameList:
                # 3) 若表达式内未出现对象字面量，尝试解析 ident[param] 中的 ident 在父JS中的对象定义
                indexed_vars = self._find_indexed_vars(sanitized, param_name)
                if indexed_vars:
                    from_parent_ast = self._extract_object_keys_from_parent_by_ast(indexed_vars, parent_js_content)
                    from_parent_regex = set()
                    if not from_parent_ast:
                        from_parent_regex = self._extract_object_keys_from_parent_by_regex(indexed_vars, parent_js_content)
                    nameList = list(set(from_parent_ast) | set(from_parent_regex))
            if not nameList:
                # 输出少量调试信息，便于定位
                self.log.debug(f"在 {Utils().getFilename(jsFilePath)} 中未提取到有效的JS模块ID (AST)，expr_head={sanitized[:180]} ... len={len(sanitized)}")
                return

            self.log.info(f"  → 提取到 {len(nameList)} 个模块ID (AST)")
            # 3) 注入常见别名桩，进一步提升兼容性
            prefix_stub = "var __webpack_require__={p:''},i={p:''},t={p:''},n={p:''},r={p:''},o={p:''},a={p:''};"
            js_code_func = f"{prefix_stub} function js_compile({param_name}){{ try{{ return {sanitized}; }}catch(e){{ return undefined; }} }}"
            filenames_found = self._execute_in_deno(js_code_func, nameList)

            if filenames_found:
                self._log_filenames_success_once(jsFilePath, filenames_found, "AST")
                self._add_to_pending_list(filenames_found, jsFilePath, parent_js_content, code_body)
            else:
                # VM 求值失败或未返回，尝试模板拼接回退
                alt = self._try_build_filenames_without_vm(sanitized, param_name, nameList)
                if alt:
                    self._log_filenames_success_once(jsFilePath, alt, "Template")
                    self._add_to_pending_list(alt, jsFilePath, parent_js_content, code_body)
                else:
                    # 提示：虽然提取到模块ID，但没能拼出有效的 chunk 文件名
                    self.log.debug(f"  → 未能解析出有效异步JS文件名")
        except Exception as e:
            self.log.error(f"[Err] AST代码编译过程中出错: {e}")

    def compile_from_regex(self, code_body, param_name, jsFilePath, parent_js_content):
        """返回是否成功新增了候选文件名（用于上层判断是否命中）。"""
        added_any = False
        try:
            # 1) 去除 runtime publicPath 前缀
            sanitized = self._sanitize_code_body(code_body)
            # 2) 更健壮的对象键名提取：优先从 "{...}[e]" 模式提取，再回退到通用正则与 AST
            nameList = list(set(self._extract_keys_followed_by_param(sanitized, param_name)))
            if not nameList:
                nameList = list(set(self._extract_keys_robust(sanitized)))
            if not nameList:
                nameList = list(set(self._extract_keys_by_ast(sanitized)))
            if not nameList:
                # 若表达式内未出现对象字面量，尝试从父JS中解析被下标访问的变量所绑定的对象
                indexed_vars = self._find_indexed_vars(sanitized, param_name)
                if indexed_vars:
                    from_parent_ast = self._extract_object_keys_from_parent_by_ast(indexed_vars, parent_js_content)
                    from_parent_regex = set()
                    if not from_parent_ast:
                        from_parent_regex = self._extract_object_keys_from_parent_by_regex(indexed_vars, parent_js_content)
                    nameList = list(set(from_parent_ast) | set(from_parent_regex))
            if not nameList:
                self.log.debug(f"Regex回退时未能提取到JS模块ID，expr_head={sanitized[:180]} ... len={len(sanitized)} in {Utils().getFilename(jsFilePath)}")
                return False

            # 3) 对同一文件内“完全相同的一组模块ID”做去重，只在第一次命中时打印提示
            id_set = frozenset(nameList)
            file_key = Utils().getFilename(jsFilePath)
            if not hasattr(self, "_seen_module_id_sets"):
                self._seen_module_id_sets = {}
            seen_for_file = self._seen_module_id_sets.setdefault(file_key, set())
            is_dup_ids = id_set in seen_for_file
            if not is_dup_ids:
                seen_for_file.add(id_set)
                self.log.info(f"  → 提取到 {len(nameList)} 个模块ID (Regex)")
            else:
                # 重复的模块ID集合，降噪为 debug 日志
                self.log.debug(f"  → 跳过重复的模块ID集合")

            filenames_found = set()
            # 调用策略调整：短表达式使用 Deno VM 求值，超长表达式直接走模板拼接回退，避免在 VM 中执行大块代码
            if len(sanitized) <= 20000:
                prefix_stub = "var __webpack_require__={p:''},i={p:''},t={p:''},n={p:''},r={p:''},o={p:''},a={p:''};"
                jsCodeFunc = f"{prefix_stub} function js_compile({param_name}){{ try{{ return {sanitized}; }}catch(e){{ return undefined; }} }}"
                filenames_found = self._execute_in_deno(jsCodeFunc, nameList)

            if filenames_found:
                self._log_filenames_success_once(jsFilePath, filenames_found, "Regex")
                self._add_to_pending_list(filenames_found, jsFilePath, parent_js_content, code_body)
                added_any = True
            else:
                alt = self._try_build_filenames_without_vm(sanitized, param_name, nameList)
                if alt:
                    self._log_filenames_success_once(jsFilePath, alt, "Template")
                    self._add_to_pending_list(alt, jsFilePath, parent_js_content, code_body)
                    added_any = True
                else:
                    # 提示：虽然提取到模块ID，但没能拼出有效的 chunk 文件名
                    self.log.debug(f"  → 未能解析出有效异步JS文件名")
        except Exception as e:
            # 降噪：不再以错误级别输出该信息，改为调试级别
            self.log.debug(f"[Debug] Regex代码编译过程中出错: {e}")
            # 捕获异常时也尝试模板拼接回退
            try:
                alt = self._try_build_filenames_without_vm(sanitized, param_name, nameList)
                if alt:
                    self._log_filenames_success_once(jsFilePath, alt, "Template")
                    self._add_to_pending_list(alt, jsFilePath, parent_js_content, code_body)
                    added_any = True
                else:
                    # 与正常分支保持一致：提示本表达式最终未能还原出有效异步 JS 文件名
                    self.log.debug(f"  → 未能解析出有效异步JS文件名")
            except Exception:
                # 模板回退本身出错时，静默忽略，避免打断整体流程
                pass
        return added_any

    def _log_filenames_success_once(self, jsFilePath, filenames, source_label):
        """对同一文件内完全相同的一组异步JS文件名只打印一次成功日志，其余降为 debug。"""
        if not filenames:
            return
        file_key = Utils().getFilename(jsFilePath)
        key = frozenset(filenames)
        if not hasattr(self, "_seen_success_filename_sets"):
            self._seen_success_filename_sets = {}
        seen = self._seen_success_filename_sets.setdefault(file_key, set())
        if key in seen:
            self.log.debug(f"  → 跳过重复的文件名集合 ({source_label})")
            return
        seen.add(key)
        self.log.info(f"  ✓ 解析出 {len(filenames)} 个异步JS ({source_label})")


    def _add_to_pending_list(self, filenames_found, jsFilePath, parent_js_content, code_snippet):
        conn = self._get_db_connection()
        cursor = conn.cursor()
        localFile = os.path.basename(jsFilePath)

        jsSplitId = self.js_split_id_counter
        self.js_split_id_counter += 1

        sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name) VALUES(?, ?, ?)"
        cursor.execute(sql, (jsSplitId, code_snippet, localFile))
        conn.commit()

        cursor.execute("SELECT path FROM js_file WHERE local=?", (localFile,))
        jsUrlPath = cursor.fetchone()[0]
        conn.close()

        self.pending_js_files.update(
            self.getRealFilePath(list(filenames_found), jsUrlPath, parent_js_content)
        )
    def _add_to_pending_list_with_base(self, filenames_found, jsFilePath, base_url, parent_js_content, code_snippet):
        conn = self._get_db_connection()
        cursor = conn.cursor()
        localFile = os.path.basename(jsFilePath)

        jsSplitId = self.js_split_id_counter
        self.js_split_id_counter += 1

        sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name) VALUES(?, ?, ?)"
        cursor.execute(sql, (jsSplitId, code_snippet, localFile))
        conn.commit()
        conn.close()

        self.pending_js_files.update(
            self.getRealFilePath(list(filenames_found), base_url, parent_js_content)
        )
    def _add_static_paths(self, paths, jsFilePath, parent_js_content):
        """
        将 Vite/Rollup 模式发现的静态路径加入待下载列表，复用统一的URL构建逻辑。
        仅处理 .js/.mjs。
        """
        try:
            if not paths:
                return
            # 仅保留允许的扩展
            allow = ('.js', '.mjs')
            norm = {p for p in paths if any(p.lower().endswith(ext) or (( '.' in p) and p.lower().split('?',1)[0].endswith(ext)) for ext in allow)}
            if not norm:
                return
            self._add_to_pending_list(set(norm), jsFilePath, parent_js_content, 'Vite/Rollup detector')
        except Exception:
            return

    def _scan_vite_rollup(self, js_content, jsFilePath):
        """
        Vite/Rollup 检测器：
        - new URL("...", import.meta.url)
        - import("...") 仅静态字符串字面量
        支持可选查询串保留。
        """
        try:
            vite_url_pat = re.compile(r"new\s+URL\(\s*([\"\'])([^\"\']+\.(?:js|mjs)(?:\?[^\"\']*)?)\1\s*,\s*import\.meta\.url\s*\)")
            vite_import_pat = re.compile(r"import\s*\(\s*([\"\'])([^\"\']+\.(?:js|mjs)(?:\?[^\"\']*)?)\1\s*\)")
            found = set()
            for m in vite_url_pat.finditer(js_content):
                found.add(m.group(2))
            for m in vite_import_pat.finditer(js_content):
                found.add(m.group(2))
            if found:
                self.log.info(f"Vite/Rollup检测器: 发现 {len(found)} 个静态路径/导入: {Utils().getFilename(jsFilePath)}")
                # 这里 parent_js_content 直接使用 js_content
                self._add_static_paths(found, jsFilePath, js_content)
        except Exception:
            return
    def _scan_custom_loader(self, js_content, jsFilePath):
        """
        通用自定义加载器检测器 - 增强版
        
        检测模式：
        1. 任意 basePath 变量定义：var xxxPath = '/api/'; var BASE_URL = '/static/';
        2. 任意加载函数调用：load(...), loadScript(...), require(...), importScript(...)
        3. basePath + 相对路径拼接模式
        4. 数组形式的资源列表: ['a.js', 'b.js']
        
        示例:
            var _API_Path = '/proxyApi/ecity_js_api1.0';
            var BASE_URL = '/static/js/';
            var cdnPath = 'https://cdn.example.com/';
            _load('frame/libs/react.js', 'frame/js/jquery.js');
            loadScript('/vendor/lodash.js');
        """
        try:
            # 1) 通用 basePath 变量名模式 - 检测常见命名
            base_path_patterns = [
                # 常见命名: xxxPath, xxx_path, BASE_URL, CDN_URL, STATIC_URL 等
                r"\b([A-Za-z_$][\w$]*(?:Path|PATH|_path|Url|URL|_url|Base|BASE|Root|ROOT))\s*=\s*(['\"])([^'\"]+)\2",
                # 全大写常量: API_PATH, STATIC_PATH, CDN_BASE 等
                r"\b([A-Z][A-Z0-9_]*(?:PATH|URL|BASE|ROOT|CDN|STATIC|ASSETS))\s*=\s*(['\"])([^'\"]+)\3",
                # 通用赋值: var/let/const xxx = '/path/'（以 / 结尾的路径）
                r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"])(/[^'\"]*?/)\2",
            ]
            
            base_paths = set(getattr(self, "_custom_loader_base_paths", set()))
            for pat in base_path_patterns:
                for m in re.finditer(pat, js_content):
                    # 根据分组数量提取路径值
                    groups = m.groups()
                    path_value = groups[-1] if len(groups) >= 2 else None
                    if path_value and path_value.strip():
                        base = path_value.strip()
                        # 过滤掉明显不是路径的值
                        if not re.search(r'\.(?:png|jpe?g|gif|svg|ico|css|html?)$', base, re.I):
                            if not hasattr(self, "_custom_loader_base_paths"):
                                self._custom_loader_base_paths = set()
                            self._custom_loader_base_paths.add(base)
                            base_paths.add(base)

            # 2) 通用加载函数名模式
            loader_func_patterns = [
                r"\b(load|loadScript|loadJS|importScript|require|_load|loadModule|fetchScript)\s*\(",
                r"\b(loadScripts|loadResources|loadAssets|importScripts)\s*\(",
            ]
            
            found_paths = set()
            
            for func_pat in loader_func_patterns:
                for m in re.finditer(func_pat + r"(.*?)\)", js_content, re.DOTALL | re.I):
                    args_src = m.group(2) if m.lastindex >= 2 else m.group(1)
                    # 从参数中提取 .js/.mjs 路径
                    for sm in re.finditer(r"(['\"])([^'\"]+\.(?:js|mjs)(?:\?[^'\"]*)?)\1", args_src):
                        raw = (sm.group(2) or '').strip()
                        if not raw:
                            continue
                        
                        # 绝对 URL 直接加入
                        if re.match(r"^https?://", raw, re.I):
                            found_paths.add(raw)
                            continue
                        
                        # 绝对路径直接加入
                        if raw.startswith('/'):
                            found_paths.add(raw)
                            # 同时尝试与 base_paths 组合
                            for base in base_paths:
                                if base.startswith(('http://', 'https://')):
                                    found_paths.add(base.rstrip('/') + raw)
                            continue
                        
                        # 相对路径：与所有 base_paths 组合
                        if base_paths:
                            for base in base_paths:
                                base = base.rstrip('/') or ''
                                path = base + '/' + raw if base else raw
                                found_paths.add(path)
                        else:
                            # 无 base_path 时直接加入相对路径
                            found_paths.add(raw)

            # 3) 检测数组形式的资源列表: ['a.js', 'b.js']
            array_pat = re.compile(r"\[\s*(['\"][^'\"]+\.(?:js|mjs)['\"](?:\s*,\s*['\"][^'\"]+\.(?:js|mjs)['\"])+)\s*\]")
            for m in array_pat.finditer(js_content):
                arr_content = m.group(1)
                for sm in re.finditer(r"['\"]([^'\"]+\.(?:js|mjs)(?:\?[^'\"]*)?)['\"]", arr_content):
                    raw = sm.group(1).strip()
                    if raw:
                        if re.match(r"^https?://", raw, re.I) or raw.startswith('/'):
                            found_paths.add(raw)
                        elif base_paths:
                            for base in base_paths:
                                found_paths.add(base.rstrip('/') + '/' + raw)
                        else:
                            found_paths.add(raw)

            if found_paths:
                self.log.info(f"通用加载器检测: 发现 {len(found_paths)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
                self._add_to_pending_list(found_paths, jsFilePath, js_content, 'generic_loader')
        except Exception as e:
            self.log.debug(f"[Debug] 通用加载器扫描失败: {e}")
            return
    # 通用配置对象名列表 - 增强版
    CONFIG_OBJECT_NAMES = [
        'SITE_CONFIG', 'APP_CONFIG', 'CONFIG', '__CONFIG__', 
        'window.config', 'window.CONFIG', 'window.appConfig',
        'window.siteConfig', 'window.APP_CONFIG', 'window.SITE_CONFIG',
        '__webpack_public_path__', 'publicPath', 'PUBLIC_PATH',
        'ENV', 'env', '__ENV__', 'settings', 'SETTINGS',
        'globalConfig', 'GLOBAL_CONFIG', 'appSettings', 'APP_SETTINGS',
    ]

    def _eval_concat(self, expr, env):
        """
        通用配置对象拼接求值器 - 增强版
        
        在不执行任意代码的前提下，尝试对由字符串与配置变量拼接的表达式求值。
        支持多种常见配置对象名：SITE_CONFIG, APP_CONFIG, CONFIG, __CONFIG__ 等
        
        例如：
            window.SITE_CONFIG.cdnUrl + '/static/js/app.js'
            window.config.basePath + '/vendor/lodash.js'
            __CONFIG__.staticUrl + '/js/main.js'
        """
        try:
            if not expr:
                return None
            
            replaced = expr
            
            # 遍历所有已知配置对象名，替换其属性访问
            for config_name in self.CONFIG_OBJECT_NAMES:
                for k, v in env.items():
                    # 处理 window.xxx 前缀
                    if config_name.startswith('window.'):
                        base_name = config_name
                    else:
                        base_name = r"(?:window\.)?" + re.escape(config_name)
                    
                    # 点号访问: CONFIG.key
                    pat1 = re.compile(base_name + r"\s*\.\s*" + re.escape(k) + r"\b")
                    # 方括号访问: CONFIG["key"] 或 CONFIG['key']
                    pat2 = re.compile(base_name + r"\s*\[\s*([\"'])" + re.escape(k) + r"\1\s*\]")
                    
                    replaced = pat1.sub(lambda m: "'" + v + "'", replaced)
                    replaced = pat2.sub(lambda m: "'" + v + "'", replaced)

            # 仅允许 '...'+"..."+('...')+(...) 这类形式
            tmp = re.sub(r"\s+", "", replaced)
            probe = re.sub(r"([\'\"](?:\\.|[^\'\"])*[\'\"]|\+|\(|\))", "", tmp)
            if probe != "":
                return None

            # 依次取出字符串字面量并拼接
            out = []
            for m in re.finditer(r"([\'\"])((?:\\.|[^\'\"])*)\1", replaced):
                out.append(m.group(2))
            return "".join(out) if out else None
        except Exception:
            return None

    def _extract_simple_env(self, js_content):
        """
        通用配置对象解析器 - 增强版
        
        解析多种常见配置对象的赋值，支持字符串与已解析变量的拼接推导。
        支持的配置对象名：SITE_CONFIG, APP_CONFIG, CONFIG, __CONFIG__, 
                        window.config, globalConfig 等
        
        支持最多三轮迭代解析，先解析直接字面量，再解析依赖已知变量的拼接。
        """
        env = {}
        try:
            # 构建通用配置对象匹配模式
            config_names_pattern = '|'.join(
                re.escape(name) if not name.startswith('window.') 
                else re.escape(name)
                for name in self.CONFIG_OBJECT_NAMES
            )
            
            # 匹配 CONFIG.key = value 或 CONFIG["key"] = value
            assign_pat = re.compile(
                r"(?:(?:window\.)?(?:" + config_names_pattern + r"))\s*"
                r"(?:\[\s*([\"'])([^\"']+)\1\s*\]|\.\s*([A-Za-z_$][\w$]*))\s*=\s*([^;]+);",
                re.DOTALL,
            )
            assigns = assign_pat.findall(js_content)
            raw = []
            for q, key1, key2, expr in assigns:
                key = key1 or key2
                if not key:
                    continue
                raw.append((key, expr))
            
            # 额外检测：var/let/const xxx = { key: value } 形式的配置对象
            # 匹配常见配置变量名
            config_var_pat = re.compile(
                r"(?:var|let|const)\s+(config|CONFIG|appConfig|siteConfig|settings|SETTINGS|env|ENV)\s*=\s*\{([^}]+)\}",
                re.DOTALL | re.I
            )
            for m in config_var_pat.finditer(js_content):
                obj_body = m.group(2)
                # 提取 key: "value" 或 key: 'value'
                for kv in re.finditer(r"([A-Za-z_$][\w$]*)\s*:\s*([\"'])([^\"']*)\2", obj_body):
                    key = kv.group(1)
                    val = kv.group(3)
                    if key and val:
                        raw.append((key, f'"{val}"'))

            changed = True
            rounds = 0
            while changed and rounds < 3:
                changed = False
                rounds += 1
                for key, expr in raw:
                    if key in env:
                        continue
                    src = expr.strip()
                    # 纯字符串
                    m = re.fullmatch(r"([\"'])(.*)\1", src, re.DOTALL)
                    if m:
                        env[key] = m.group(2)
                        changed = True
                        continue
                    # 拼接可求值
                    val = self._eval_concat(src, env)
                    if val is not None:
                        env[key] = val
                        changed = True
            return env
        except Exception:
            return env

    def _scan_dom_loader(self, js_content, jsFilePath):
        """
        通用 DOM 加载器检测 - 增强版
        
        检测模式：
        1. document.write('<script src="...">') 中的 src
        2. 任意资源列表对象: { js: [...] }, { scripts: [...] }, { resources: [...] }
        3. script.src = '...' 赋值
        4. 动态创建 script 元素并设置 src
        5. 配置对象中的 JS 路径拼接
        
        解析出的相对路径交由统一 URL 构建逻辑处理。
        """
        try:
            env = self._extract_simple_env(js_content)
            found = set()

            # 1) document.write 中的 <script src="...">
            for m in re.finditer(r"document\.write(?:ln)?\(\s*([\"'])((?:\\.|[^\"'])*)\1\s*\)", js_content, re.DOTALL | re.I):
                html = m.group(2)
                for m2 in re.finditer(r"src\s*=\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\1", html, re.I):
                    found.add(m2.group(2))

            # 2) 通用资源列表对象检测 - 支持多种命名
            # 匹配: xxx = { js: [...] } 或 xxx = { scripts: [...] } 或 xxx = { resources: [...] }
            resource_list_patterns = [
                r"\b\w+\s*=\s*\{[\s\S]*?\b(js|scripts|jsList|scriptList|jsFiles)\s*:\s*\[([\s\S]*?)\]",
                r"\b(resources|assets|files|modules)\s*:\s*\{[\s\S]*?\b(js|scripts)\s*:\s*\[([\s\S]*?)\]",
                # 直接数组赋值: var scripts = ['a.js', 'b.js']
                r"\b(scripts|jsList|jsFiles|scriptList)\s*=\s*\[([\s\S]*?)\]",
            ]
            
            for pat in resource_list_patterns:
                for m in re.finditer(pat, js_content, re.I):
                    # 获取数组内容（最后一个分组）
                    arr = m.group(m.lastindex)
                    items = self._parse_array_items(arr)
                    
                    for it in items:
                        if not it:
                            continue
                        lit = None
                        # 纯字符串
                        mstr = re.fullmatch(r"([\"'])([^\"']+?(?:\.(?:js|mjs))(?:\?[^\"']*)?)\1", it, re.I)
                        if mstr:
                            lit = mstr.group(2)
                        else:
                            # 尝试配置对象拼接求值
                            lit = self._eval_concat(it, env)
                        if lit and re.search(r"\.(?:js|mjs)(?:\?|$)", lit, re.I):
                            found.add(lit)

            # 3) script.src = '...' 赋值
            for m in re.finditer(r"\.src\s*=\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\1", js_content, re.I):
                found.add(m.group(2))
            
            # 4) createElement('script') 后的 src 设置
            # 检测: var s = document.createElement('script'); s.src = '...'
            for m in re.finditer(r"createElement\s*\(\s*[\"']script[\"']\s*\)[\s\S]{0,200}?\.src\s*=\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\1", js_content, re.I):
                found.add(m.group(2))
            
            # 5) 配置对象中的路径属性
            # 检测: { src: 'xxx.js' } 或 { url: 'xxx.js' } 或 { path: 'xxx.js' }
            for m in re.finditer(r"\b(src|url|path|file)\s*:\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\2", js_content, re.I):
                found.add(m.group(3))

            if found:
                self.log.info(f"DOM 加载器检测: 发现 {len(found)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
                base = getattr(self.options, 'url', None)
                if base:
                    self._add_to_pending_list_with_base(found, jsFilePath, base, js_content, 'dom_loader')
                else:
                    self._add_static_paths(found, jsFilePath, js_content)
        except Exception:
            return
    
    def _parse_array_items(self, arr_content):
        """
        解析数组内容，支持括号与字符串内逗号。
        """
        items = []
        cur = []
        q = None
        depth = 0
        for ch in arr_content:
            if q is not None:
                cur.append(ch)
                if ch == q and (len(cur) < 2 or cur[-2] != '\\'):
                    q = None
                continue
            if ch in ('\"', "'"):
                q = ch
                cur.append(ch)
                continue
            if ch in '([':
                depth += 1
                cur.append(ch)
                continue
            if ch in ')]':
                depth = max(0, depth - 1)
                cur.append(ch)
                continue
            if ch == ',' and depth == 0:
                items.append(''.join(cur).strip())
                cur = []
                continue
            cur.append(ch)
        if cur:
            items.append(''.join(cur).strip())
        return items


    '''

    def _scan_webpack_literal_chunks(self, js_content, jsFilePath):
	        """
	        Webpack5 简易 chunk 检测器：

	        适配形如：
	            __webpack_require__.u = function(e){ return "js/" + e + ".js"; }
	            __webpack_require__.e("src_views_xxx").then(...)
	        的模式，不依赖对象字面量映射，直接从 .e("id") 中提取 chunkId，
	        再根据 .u 的返回模板拼接出 JS 路径。
	        """
        try:
            loaders = {}
            # 1) 普通 function 形式：obj.u = function(e){ return "js/"+e+".js"; }
            func_pat = re.compile(
                r"([A-Za-z_$][\w$]*)\.u\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{"
                r"[^;]{0,200}?return\s*([^;]+?);",
                re.DOTALL
            )
            for m in func_pat.finditer(js_content):
	                obj_name = m.group(1)
	                param = m.group(2)
	                ret_expr = m.group(3)
	                m2 = re.search(
	                    r"([\"'])([^\"']*?)\1\s*\+\s*"
	                    + re.escape(param)
	                    + r"\s*\+\s*([\"'])\.js(?:\?[^\"']*)?\3",
	                    ret_expr
	                )
	                if not m2:
	                    continue
	                prefix = m2.group(2) or ""
	                loaders[obj_name] = prefix

	            # 2) 箭头函数形式：obj.u = e => "js/"+e+".js";
	            arrow_pat = re.compile(
	                r"([A-Za-z_$][\w$]*)\.u\s*=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([^;]+?);",
	                re.DOTALL
	            )
	            for m in arrow_pat.finditer(js_content):
	                obj_name = m.group(1)
	                param = m.group(2)
	                ret_expr = m.group(3)
	                m2 = re.search(
	                    r"([\"'])([^\"']*?)\1\s*\+\s*"
	                    + re.escape(param)
	                    + r"\s*\+\s*([\"'])\.js(?:\?[^\"']*)?\3",
	                    ret_expr
	                )
	                if not m2:
	                    continue
	                prefix = m2.group(2) or ""
	                loaders.setdefault(obj_name, prefix)

	            if not loaders:
	                return

	            candidates = set()
	            for obj_name, prefix in loaders.items():
	                # 3) 从 obj.e("chunk_id") 调用中抽取 chunkId
	                call_pat = re.compile(
	                    re.escape(obj_name) + r"\.e\(\s*(?:/\*.*?\*/\s*)?([\"'])(.+?)\1\s*\)",
	                    re.DOTALL
	                )
	                for m in call_pat.finditer(js_content):
	                    chunk_id = (m.group(2) or "").strip()
	                    if not chunk_id:
	                        continue
	                    filename = f"{prefix}{chunk_id}.js"
	                    candidates.add(filename)

	            if candidates:
	                self.log.info(
	                    f"Webpack简易chunk检测器: 发现 {len(candidates)} 个静态JS路径: {Utils().getFilename(jsFilePath)}"
	                )
	                self._add_to_pending_list(candidates, jsFilePath, js_content, 'webpack_literal_chunks')
	        except Exception as e:
	            # 低优先级调试信息
	            self.log.debug(f"[Debug] Webpack 简易 chunk 检测失败: {e}")
	            return

    '''

    def _scan_webpack_literal_chunks(self, js_content, jsFilePath):
        """
        Webpack5 简易 chunk 检测器：

        适配形如：
            __webpack_require__.u = function(e){ return "js/" + e + ".js"; }
            __webpack_require__.e("src_views_xxx").then(...)
        的模式，不依赖对象字面量映射，直接从 .e("id") 中提取 chunkId，
        再根据 .u 的返回模板拼接出 JS 路径。
        """
        try:
            loaders = {}
            # 1) 普通 function 形式：obj.u = function(e){ return "js"+e +".js"; }
            func_pat = re.compile(
                r"([A-Za-z_$][\w$]*)\.u\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{"\
                r"[^;]{0,200}?return\s*([^;]+?);",
                re.DOTALL
            )
            for m in func_pat.finditer(js_content):
                obj_name = m.group(1)
                param = m.group(2)
                ret_expr = m.group(3)
                m2 = re.search(
                    r"([\"'])([^\"']*?)\1\s*\+\s*"
                    + re.escape(param)
                    + r"\s*\+\s*([\"'])\.js(?:\?[^\"']*)?\3",
                    ret_expr
                )
                if not m2:
                    continue
                prefix = m2.group(2) or ""
                loaders[obj_name] = prefix

            # 2) 箭头函数形式：obj.u = e => "js"+e+".js";
            arrow_pat = re.compile(
                r"([A-Za-z_$][\w$]*)\.u\s*=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([^;]+?);",
                re.DOTALL
            )
            for m in arrow_pat.finditer(js_content):
                obj_name = m.group(1)
                param = m.group(2)
                ret_expr = m.group(3)
                m2 = re.search(
                    r"([\"'])([^\"']*?)\1\s*\+\s*"
                    + re.escape(param)
                    + r"\s*\+\s*([\"'])\.js(?:\?[^\"']*)?\3",
                    ret_expr
                )
                if not m2:
                    continue
                prefix = m2.group(2) or ""
                loaders.setdefault(obj_name, prefix)

            if not loaders:
                return

            candidates = set()
            for obj_name, prefix in loaders.items():
                # 3) 从 obj.e("chunk_id") 调用中抽取 chunkId
                call_pat = re.compile(
                    re.escape(obj_name) + r"\.e\(\s*(?:/\*.*?\*/\s*)?([\"'])(.+?)\1\s*\)",
                    re.DOTALL
                )
                for m in call_pat.finditer(js_content):
                    chunk_id = (m.group(2) or "").strip()
                    if not chunk_id:
                        continue
                    filename = f"{prefix}{chunk_id}.js"
                    candidates.add(filename)

            if candidates:
                self.log.info(
                    f"Webpack简易chunk检测器: 发现 {len(candidates)} 个静态JS路径: {Utils().getFilename(jsFilePath)}"
                )
                self._add_to_pending_list(candidates, jsFilePath, js_content, 'webpack_literal_chunks')
        except Exception as e:
            # 低优先级调试信息
            self.log.debug(f"[Debug] Webpack 简易 chunk 检测失败: {e}")
            return


    def _build_full_url(self, path, script_url):
        """
        参照 content.js 中 buildFullUrl 逻辑的 Python 实现，用于健壮地拼接URL并处理双重路径。
        """
        try:
            script_url_parts = urlparse(script_url)
            base_origin = f"{script_url_parts.scheme}://{script_url_parts.netloc}"

            if path.startswith(('http://', 'https://')):
                return path

            if path.startswith('/'):
                return urljoin(base_origin, path)

            # 核心：处理相对路径和路径重叠
            script_path = script_url_parts.path
            script_directory = script_path[:script_path.rfind('/') + 1]

            path_segments = [s for s in path.split('/') if s]
            dir_segments = [s for s in script_directory.split('/') if s]

            overlap_len = 0
            # 从后向前寻找最大重叠
            for i in range(min(len(path_segments), len(dir_segments)), 0, -1):
                if dir_segments[-i:] == path_segments[:i]:
                    overlap_len = i
                    break

            # 拼接最终路径
            final_segments = dir_segments + path_segments[overlap_len:]
            final_path = "/" + "/".join(final_segments)

            return urljoin(base_origin, final_path)

        except Exception as e:
            self.log.error(f"构建URL时出错: path='{path}', script_url='{script_url}', error='{e}'")
            return urljoin(script_url, path) # Fallback

    def getRealFilePath(self, jsFileNames, jsUrlpath, parent_js_content):
        jsRealPaths = []
        # 尝试提取 publicPath（webpack 等构建工具的资源根路径）
        match = re.search(r'(__webpack_require__\.p|\w\.p)\s*=\s*["\'](.*?)["\']', parent_js_content)

        public_path = None
        base_url_for_build = jsUrlpath
        has_valid_public = False

        if match:
            candidate = (match.group(2) or '').strip()
            looks_like_file = re.search(
                r'\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|json|txt|html?)',
                candidate,
                re.I,
            )
            # 仅当看起来是“目录”而不是“具体文件”时才认为是有效 publicPath
            if candidate and candidate.endswith('/') and not looks_like_file:
                public_path = candidate
                has_valid_public = True
                # 针对同一父 JS + 相同 publicPath 只输出一次提示，其余降为 debug，避免刷屏
                script_key = Utils().getFilename(jsUrlpath)
                log_key = (script_key, public_path)
                if not hasattr(self, "_logged_public_paths"):
                    self._logged_public_paths = set()
                if log_key in self._logged_public_paths:
                    self.log.debug(
                        f"[Debug] 在 {script_key} 中已提取过 publicPath: '{public_path}'，跳过重复提示。",
                    )
                else:
                    self._logged_public_paths.add(log_key)
                    self.log.info(
                        f"在 {script_key} 中成功提取到 publicPath: '{public_path}'，将优先基于该路径来合并资源 URL。",
                    )
                base_url_for_build = urljoin(jsUrlpath, public_path)
            else:
                self.log.debug(
                    f"忽略可疑 publicPath: '{candidate}'（非目录/疑似文件）",
                )
        else:
            self.log.debug("未能在父JS中自动提取 publicPath，将使用父JS的URL作为基础。")

        # 若没有可靠的 publicPath，则退回到以父 JS 的 URL 作为基准
        if not has_valid_public:
            base_url_for_build = jsUrlpath

        # 安全网：若候选名是 'chunk-xxxx.js' 且父JS内存在映射 '"chunk-xxxx": "hash"'，则补全为 'chunk-xxxx.hash.js'
        def _patch_chunk_without_hash(path: str) -> str:
            try:
                # 已经带 hash 的直接跳过
                if re.search(r"/(?:chunk-[0-9a-fA-F]{6,})\.[0-9a-fA-F]{6,}\.js(?:\?|$)", path):
                    return path
                m = re.search(r"/(chunk-[0-9a-fA-F]{6,})\.js(?:\?|$)", path)
                if not m:
                    return path
                key = m.group(1)
                m2 = re.search(r"[\"']" + re.escape(key) + r"[\"']\s*:\s*[\"']([0-9a-fA-F]{6,})[\"']", parent_js_content)
                if m2:
                    hv = m2.group(1)
                    return path.replace(key + ".js", f"{key}.{hv}.js")
            except Exception:
                pass
            return path

        for jsFileName in jsFileNames:
            # 仅下载 JS 资源，显式跳过 CSS 等其它类型
            if not re.search(r'\.(?:js|mjs)(?:\?|$)', jsFileName, re.I):
                continue
            # 针对常见 webpack chunk 命名的修补（避免生成无 hash 的错误请求）
            jsFileName = _patch_chunk_without_hash(jsFileName)

            if has_valid_public:
                # 更通用规则：当存在明确的 publicPath 时，除显式相对路径(./、../)外，
                # 一律按 publicPath 作为构建根路径来解析，避免出现 /admin/login + "static/js/..." => /admin/static/js/... 这类错误。
                if jsFileName.startswith(("./", "../")):
                    base_for_this = jsUrlpath
                else:
                    base_for_this = base_url_for_build
            else:
                # 无 publicPath 时，保留此前基于父 JS 目录的启发式逻辑，兼容 Vite/Rollup 等场景
                if jsFileName.startswith(("./", "../")):
                    base_for_this = jsUrlpath
                elif "/" in jsFileName:
                    base_for_this = jsUrlpath
                else:
                    base_for_this = base_url_for_build

            # 统一调用我们健壮的URL构建函数
            full_url = self._build_full_url(jsFileName, base_for_this)
            jsRealPaths.append(full_url)

        return jsRealPaths

    def checkCodeSpilting(self, jsFilePath):
        if jsFilePath in self.processed_files:
            return
        self.processed_files.add(jsFilePath)

        try:
            with open(jsFilePath, 'r', encoding='UTF-8', errors="ignore") as f:
                js_content = f.read()

                # Vite/Rollup detector: scan for new URL(..., import.meta.url) and static import("...")
                self._scan_vite_rollup(js_content, jsFilePath)

                # 自定义脚本加载器（例如 _API_Path + _load(...)）
                self._scan_custom_loader(js_content, jsFilePath)
                self._scan_dom_loader(js_content, jsFilePath)
                # Webpack5 简单 chunk 命名模式：obj.u = function(e){ return "js/" + e + ".js"; }
                self._scan_webpack_literal_chunks(js_content, jsFilePath)


            self.log.info(f"[{Utils().tellTime()}] 正在分析: {Utils().getFilename(jsFilePath)}")
            found_by_ast = self._analyze_with_ast(js_content, jsFilePath)

            if not found_by_ast:
                self.log.debug(f"AST未找到模式，尝试Regex: {Utils().getFilename(jsFilePath)}")
                self._analyze_with_regex(js_content, jsFilePath)

        except Exception as e:
            self.log.error(f"[Err] 分析文件 {Utils().getFilename(jsFilePath)} 时发生未知错误: {e}")

    def _analyze_with_ast(self, js_content, jsFilePath):
        try:
            ast = esprima.parseScript(js_content, {'range': True, 'tolerant': True})
            return self._traverse_ast(ast, js_content, jsFilePath)
        except Exception as e:
            self.log.debug(f"[Debug] AST解析文件 {Utils().getFilename(jsFilePath)} 时失败: {e}")
            return False

    def _traverse_ast(self, node, js_content, jsFilePath):
        if not node or not isinstance(node, esprima.nodes.Node):
            return False

        # 1) 通用：任意赋值为函数/箭头函数的形式
        if node.type == 'AssignmentExpression' and node.operator == '=' and \
           getattr(node.right, 'type', None) in ('FunctionExpression', 'ArrowFunctionExpression'):

            func_node = node.right
            # 获取参数名
            if not getattr(func_node, 'params', None) or len(func_node.params) == 0:
                param_name = 'e'
            else:
                param_name = getattr(func_node.params[0], 'name', 'e')

            body = getattr(func_node, 'body', None)
            # 块体函数：查找 return 语句
            if body and getattr(body, 'type', None) == 'BlockStatement':
                if getattr(body, 'body', None):
                    for statement in body.body:
                        if getattr(statement, 'type', None) == 'ReturnStatement' and getattr(statement, 'argument', None):
                            start, end = statement.argument.range
                            code_body = js_content[start:end]
                            if re.search(r"\.(?:js|mjs)\b", code_body) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", code_body):
                                self.log.info(f"AST发现可能的异步加载函数: {Utils().getFilename(jsFilePath)}")
                                self.compile_from_ast(code_body, param_name, jsFilePath, js_content)
                                return True
            else:
                # 箭头函数的表达式体
                if body and hasattr(body, 'range'):
                    start, end = body.range
                    code_body = js_content[start:end]
                    if re.search(r"\.(?:js|mjs)\b", code_body) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", code_body):
                        self.log.info(f"AST发现可能的异步加载函数: {Utils().getFilename(jsFilePath)}")
                        self.compile_from_ast(code_body, param_name, jsFilePath, js_content)
                        return True

        # 2) 变量声明直接初始化为函数/箭头函数
        if node.type == 'VariableDeclarator':
            init = getattr(node, 'init', None)
            if getattr(init, 'type', None) in ('FunctionExpression', 'ArrowFunctionExpression'):
                func_node = init
                if not getattr(func_node, 'params', None) or len(func_node.params) == 0:
                    param_name = 'e'
                else:
                    param_name = getattr(func_node.params[0], 'name', 'e')
                body = getattr(func_node, 'body', None)
                if body and getattr(body, 'type', None) == 'BlockStatement':
                    if getattr(body, 'body', None):
                        for statement in body.body:
                            if getattr(statement, 'type', None) == 'ReturnStatement' and getattr(statement, 'argument', None):
                                start, end = statement.argument.range
                                code_body = js_content[start:end]
                                if re.search(r"\.(?:js|mjs)\b", code_body) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", code_body):
                                    self.log.info(f"AST发现可能的异步加载函数: {Utils().getFilename(jsFilePath)}")
                                    self.compile_from_ast(code_body, param_name, jsFilePath, js_content)
                                    return True
                else:
                    if body and hasattr(body, 'range'):
                        start, end = body.range
                        code_body = js_content[start:end]
                        if re.search(r"\.(?:js|mjs)\b", code_body) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", code_body):
                            self.log.info(f"AST发现可能的异步加载函数: {Utils().getFilename(jsFilePath)}")
                            self.compile_from_ast(code_body, param_name, jsFilePath, js_content)
                            return True

        for key in dir(node):
            if not key.startswith('_'):
                child = getattr(node, key)
                if isinstance(child, esprima.nodes.Node):
                    if self._traverse_ast(child, js_content, jsFilePath):
                        return True
                elif isinstance(child, list):
                    for item in child:
                        if isinstance(item, esprima.nodes.Node):
                            if self._traverse_ast(item, js_content, jsFilePath):
                                return True
        return False

    def _analyze_with_regex(self, js_content, jsFilePath):
        try:
            produced_any = False
            # 在单个文件作用域内，对“参数名 + 返回表达式”做一次去重，避免重复解析/重复日志
            seen_exprs = set()
            # 通用模式：函数/箭头函数体内直接 return '...js'（仅当表达式不超长时尝试）
            patterns = [
                re.compile(r"=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{[^{}]*?return\s+(.+?['\"]\.(?:js|mjs)[^;]*?)\s*;?[^}]*\}", re.DOTALL),
                re.compile(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\{[^{}]*?return\s+(.+?['\"]\.(?:js|mjs)[^;]*?)\s*;?[^}]*\}", re.DOTALL),
            ]
            for pat in patterns:
                matches = pat.findall(js_content)
                for m in matches:
                    param_name, return_expr = m
                    key = (param_name, return_expr.strip())
                    if key in seen_exprs:
                        continue
                    seen_exprs.add(key)
                    if len(return_expr) < 120000:
                        produced_any = self.compile_from_regex(return_expr, param_name, jsFilePath, js_content) or produced_any

            # 更通用的强力回退：无论上面是否命中，都额外扫描任意 “= function(p){...}” / “= (p)=>{...}”
            # 仅当成功生成候选文件名时，才算一次有效命中
            # a) 常规函数形式
            for m in re.finditer(r"=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{", js_content):
                param_name = m.group(1)
                brace_start = m.end() - 1
                body = self._find_balanced_block(js_content, brace_start)
                if body:
                    return_expr = self._extract_return_expr_from_func_body(body)
                    if return_expr and re.search(r"\.(?:js|mjs)\b", return_expr) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", return_expr):
                        key = (param_name, return_expr.strip())
                        if key in seen_exprs:
                            continue
                        seen_exprs.add(key)
                        self.log.info(f"Regex发现可能的异步加载函数(function): {Utils().getFilename(jsFilePath)}")
                        produced_any = self.compile_from_regex(return_expr, param_name, jsFilePath, js_content) or produced_any
            # b) 箭头函数块体形式
            for m in re.finditer(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\{", js_content):
                param_name = m.group(1)
                brace_start = m.end() - 1
                body = self._find_balanced_block(js_content, brace_start)
                if body:
                    return_expr = self._extract_return_expr_from_func_body(body)
                    if return_expr and re.search(r"\.(?:js|mjs)\b", return_expr) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", return_expr):
                        key = (param_name, return_expr.strip())
                        if key in seen_exprs:
                            continue
                        seen_exprs.add(key)
                        self.log.info(f"Regex发现可能的异步加载函数(arrow {{}}): {Utils().getFilename(jsFilePath)}")
                        produced_any = self.compile_from_regex(return_expr, param_name, jsFilePath, js_content) or produced_any
            # c) 箭头函数表达式体形式：u=(e)=> prefix + {...}[e] + ".js"
            for m in re.finditer(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*(?!\{)\s*([^;\n]+)", js_content):
                param_name = m.group(1)
                return_expr = m.group(2)
                if return_expr and re.search(r"\.(?:js|mjs)\b", return_expr) and re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", return_expr):
                    key = (param_name, return_expr.strip())
                    if key in seen_exprs:
                        continue
                    seen_exprs.add(key)
                    self.log.info(f"Regex发现可能的异步加载函数(arrow expr): {Utils().getFilename(jsFilePath)}")
                    produced_any = self.compile_from_regex(return_expr, param_name, jsFilePath, js_content) or produced_any

            # 其它常见回退：document.createElement("script") 场景（不会阻止上述扫描）
            if (not produced_any) and "document.createElement(\"script\")" in js_content:
                pattern = re.compile(r"\w\.p\+\"(.*?)\.js\"")
                jsCodeList = pattern.findall(js_content)
                if jsCodeList:
                    self.log.info(f"Regex发现 {len(jsCodeList)} 个可能的异步加载片段: {Utils().getFilename(jsFilePath)}")
                    for jsCode in jsCodeList:
                        if len(jsCode) < 120000:
                            full_js_code = '"' + jsCode + '.js"'
                            # 尝试从片段中推断真实的模块参数名（如 a、t 等），否则回退为 "e"
                            m_param = re.search(r'\[\s*([A-Za-z_$][\w$]*)\s*\]', full_js_code)
                            param_name = m_param.group(1) if m_param else "e"
                            key = (param_name, full_js_code)
                            if key in seen_exprs:
                                continue
                            seen_exprs.add(key)
                            self.compile_from_regex(full_js_code, param_name, jsFilePath, js_content)

        except Exception as e:
            self.log.debug(f"[Debug] Regex 回退解析失败: {e}")

    def recoverStart(self):
        projectPath = DatabaseType(self.projectTag).getPathfromDB()

        self.log.info("--- 开始混合模式分析 (AST为主, Regex为辅) ---")
        all_js_files = []
        for parent, _, filenames in os.walk(projectPath, followlinks=True):
            for filename in filenames:
                if filename.endswith(".js"):
                    all_js_files.append(os.path.join(parent, filename))

        for js_file_path in all_js_files:
            self.checkCodeSpilting(js_file_path)

        if self.pending_js_files:
            self.log.info(f"[+] 发现 {len(self.pending_js_files)} 个异步JS文件，开始下载...")
            domain = urlparse(self.options.url).netloc
            if ":" in domain:
                domain = domain.replace(":", "_")

            DownloadJs(list(self.pending_js_files), self.options).downloadJs(self.projectTag, domain, 999)
        else:
            self.log.info("[*] 未发现新的异步JS文件")