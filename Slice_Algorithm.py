import ast
import collections
import copy
import glob
import os
import time
from typing import List, Set, Dict, Optional
from Filter_Algorithm import PythonCryptoAPIFilter as Filter, Crypto_API_Base

class PyCryptoAPISlicer(Filter):
    def __init__(self):
        Filter.__init__(self)

    def filter_crypto_imports(self, module_aliases: Dict[str, str],
                            from_imports: Dict[str, Set[str]], wildcard_modules: Set[str], dynamic_imports: Dict[str, str]) -> Set[str]:
        """
        使用统一知识库过滤密码相关的导入模块
        1. module_aliases: import的各种情况，模块名与别名映射，一对一，import random，import random as rd
        2. from_imports: from import的各种情况，模块名与别名映射，一对多，from random import randint, randbytes，from random import randint as rd
        3. wildcard_modules: 为通配符导入的模块名集合
        4. dynamic_imports: 动态导入情况
        """
        crypto_wildcard_modules = {mod for mod in wildcard_modules if self.is_crypto_module(mod)}
        wildcard_functions = set()
        if crypto_wildcard_modules:
            for module in crypto_wildcard_modules:
                exports = self._get_module_exports(module)
                wildcard_functions.update(exports)

        crypto_imported_names = set()

        # 筛选出密码模块相关的导入
        for module_name, alias in module_aliases.items():
            if self.is_crypto_module(module_name):
                crypto_imported_names.add(alias)

        for module_name, imports in from_imports.items():
            if self.is_crypto_module(module_name):
                crypto_imported_names.update(imports)

        for module_name, alias in dynamic_imports.items():
            if self.is_crypto_module(module_name):
                crypto_imported_names.add(alias)

        # 添加通配符导入的函数
        crypto_imported_names.update(wildcard_functions)

        return crypto_imported_names

    def find_crypto_usages(self, ast_tree: ast.AST, crypto_imported_names: Set[str]) -> List:
        """
        查找密码API的使用点
        Args:
            ast_tree: AST根节点
            crypto_imported_names: 密码相关的模块名及其标识符列表字典
        Returns:
            密码API使用点的AST节点列表
        """
        usages = []

        all_identifiers = set(crypto_imported_names)

        for node in ast.walk(ast_tree):
            # 跳过导入语句本身
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue

            # 1. 检查函数调用
            if isinstance(node, ast.Call):
                # 直接检查调用本身
                if self._check_call_usage(node, all_identifiers):
                    usages.append(node)
                    # print("函数调用")

            # 2. 检查属性访问
            if isinstance(node, ast.Attribute):
                if self._check_attribute_usage(node, all_identifiers):
                    usages.append(node)
                    # print("属性访问")

            # 3. 检查名称引用
            if isinstance(node, ast.Name):
                if self._check_name_usage(node, all_identifiers):
                    usages.append(node)
                    # print("名称引用")

            # 4. 检查赋值语句
            if isinstance(node, ast.Assign):
                if self._check_assign_usage(node, all_identifiers, ast_tree):
                    usages.append(node)
                    # print("赋值语句")

        return usages

    def extract_complete_slice(self, file_path: str) -> List[str]:
        """
        从文件中提取完整的密码API使用相关的代码切片
        """
        # 解析文件
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        self.source_lines = content.splitlines(keepends=True)

        try:
            ast_tree = ast.parse(content)
        except (SyntaxError, UnicodeDecodeError, Exception) as e:
            ast_tree = None

        if ast_tree is None:
            return []

        self.ast_tree = ast_tree  # 初始化AST分析
        self._extract_definitions(ast_tree)
        self._analyze_function_calls(ast_tree)
        self._analyze_globals_and_dependencies(ast_tree)

        module_aliases, from_imports, wildcard_modules, dynamic_imports = self.extract_imports(ast_tree)  # 调用代码筛选算法的extract_imports方法，提取所有导入语句的导入模块名


        # 从所有的导入模块名中筛选出密码相关导入模块名
        crypto_imported_names = self.filter_crypto_imports(module_aliases, from_imports, wildcard_modules, dynamic_imports)

        # 查找密码API使用点
        usages = self.find_crypto_usages(ast_tree, crypto_imported_names)

        if not usages:
            return []

        # 在包含密码API使用的AST节点查找所有相关定义，但不包括嵌套函数。
        all_related_defs = set()
        for usage in usages:
            related_defs = self.find_related_definitions(usage)
            all_related_defs.update(related_defs)

        # 新增：添加使用密码API作为参数的函数定义
        # 新增：查找使用密码API作为参数的函数
        functions_with_crypto_args = self._find_functions_with_crypto_args(crypto_imported_names)
        for func_name in functions_with_crypto_args:
            if func_name in self.function_defs:
                all_related_defs.add(self.function_defs[func_name])

        # 查找调用链中的所有函数（排除嵌套函数）
        call_chain_defs = set()
        for usage in usages:
            # 找到包含使用点的函数
            current = usage
            while current and not isinstance(current, ast.Module):
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # 检查是否是嵌套函数或类方法
                    if (not self._is_nested_function(current) and
                            current.name not in self.class_methods):  # 新增：排除类方法
                        # 查找该函数的调用链
                        call_chain_defs.update(self.find_call_chain(current.name))
                    break
                current = self._find_parent(current, self.ast_tree)

        all_related_defs.update(call_chain_defs)

        # 查找与密码相关的全局变量
        crypto_identifiers = set(crypto_imported_names)

        crypto_related_globals = set()
        for var_name, dependencies in self.var_dependencies.items():
            for dep in dependencies:
                if dep in crypto_identifiers:
                    crypto_related_globals.add(var_name)
                    break

        # 查找使用这些全局变量的函数
        functions_using_crypto_globals = self.find_functions_using_global_vars(crypto_related_globals)
        all_related_defs.update(functions_using_crypto_globals)

        # 查找调用这些函数的函数
        crypto_function_names = {func.name for func in all_related_defs if
                                 isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))}
        functions_calling_crypto_functions = self.find_functions_calling_functions(crypto_function_names)
        all_related_defs.update(functions_calling_crypto_functions)

        # 检查是否有模块级别的使用
        has_module_level_usage = False
        for usage in usages:
            if self.is_module_level_usage(usage):
                has_module_level_usage = True
                break

        # 如果没有找到相关定义且没有模块级别的使用，返回空
        if not all_related_defs and not has_module_level_usage:
            return []

        # 提取模块级别的语句（排除已经在相关定义中的函数和类）
        excluded_definitions = {def_node.name for def_node in all_related_defs
                                if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}

        # 确保嵌套函数不被单独排除，因为它们已经是父函数的一部分
        excluded_definitions.update(self.nested_functions)
        # 新增：确保类方法不被排除，因为它们是类的一部分
        excluded_definitions.update(self.class_methods)

        # 查找与密码相关的变量
        crypto_related_vars = self.find_crypto_related_variables(crypto_imported_names, usages)

        # 优化：查找与密码API调用相关的环境变量赋值语句（如 os.environ['KEY'] = val）
        # 即使模块名(如os)不在密码知识库中，环境变量的设置也会影响密码API行为
        env_var_related_names = self._find_env_var_related_names(usages, crypto_imported_names)
        crypto_related_vars.update(env_var_related_names)

        # 优化：查找保留的函数/类定义中global引用的变量，保留这些变量的全局赋值
        # 即使全局赋值不直接包含密码API，切掉会影响保留函数的功能
        global_vars_in_kept_defs = set()
        for def_node in all_related_defs:
            if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for node in ast.walk(def_node):
                    if isinstance(node, ast.Global):
                        global_vars_in_kept_defs.update(node.names)
        # 将这些global变量加入crypto_related_vars，使其全局赋值被保留
        crypto_related_vars.update(global_vars_in_kept_defs)

        # 使用去重机制处理相关定义
        unique_defs = self._remove_duplicate_definitions(all_related_defs)

        # 提取相关定义（先提取类定义，再提取函数定义）
        class_defs = {}
        function_defs = {}
        for def_node in unique_defs:
            # 跳过嵌套函数，因为它们应该作为父函数的一部分被提取
            if (isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                    (def_node.name in self.nested_functions or
                     def_node.name in self.class_methods)):  # 新增：跳过类方法
                continue

            if isinstance(def_node, ast.ClassDef):
                class_defs[def_node.name] = def_node
            elif isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_defs[def_node.name] = def_node

        # 按依赖关系排序类定义
        sorted_class_defs = self._sort_class_definitions(class_defs)

        # 提取完整的代码切片
        slices = []

        # 优化导入语句，剔除仅导入未使用的密码API导入语句
        optimized_imports = self.optimize_imports_for_slice(crypto_imported_names, usages)
        all_imports = self.extract_all_imports(optimized_imports)

        # 计算密码相关的函数/类名集合，用于识别模块级调用行
        crypto_related_func_names = {def_node.name for def_node in all_related_defs
                                     if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}

        # 使用修复后的模块级别语句提取
        module_statements = self.extract_module_level_statements_with_exclusion(crypto_imported_names, crypto_related_vars, excluded_definitions, crypto_related_func_names)

        # 补充发现：密码相关代码通过实例属性间接依赖的类定义
        # 场景：runner_object = BaseRunner(val) → runner_object.argument 在密码API调用中使用
        # 但 BaseRunner 类本身不在 all_related_defs 中
        existing_class_names = {def_node.name for def_node in all_related_defs
                                if isinstance(def_node, ast.ClassDef)}
        existing_class_names.update(excluded_definitions)

        # 策略：从密码使用点出发，追踪所有被访问的实例属性，找到对应的类定义
        # 1. 收集密码使用点上下文中所有 obj.attr 形式的属性访问
        accessed_instance_attrs = {}  # var_name -> set of attr names
        for usage in usages:
            for node in ast.walk(self.ast_tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    var_name = node.value.id
                    if var_name not in ('self', 'cls'):
                        if var_name not in accessed_instance_attrs:
                            accessed_instance_attrs[var_name] = set()
                        accessed_instance_attrs[var_name].add(node.attr)

        # 2. 查找这些变量对应的类（通过 var = ClassName(...) 赋值）
        var_to_class = {}  # var_name -> class_name
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in accessed_instance_attrs:
                        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                            if node.value.func.id in self.class_defs:
                                var_to_class[target.id] = node.value.func.id

        # 3. 检查这些类的 __init__ 是否设置了被访问的属性
        missing_class_names = set()
        for var_name, class_name in var_to_class.items():
            if class_name in existing_class_names:
                continue
            class_node = self.class_defs[class_name]
            # 找 __init__ 中设置的 self 属性
            init_setter_attrs = set()
            for item in class_node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == '__init__':
                    for node in ast.walk(item):
                        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and
                                node.value.id == 'self' and isinstance(node.ctx, ast.Store)):
                            init_setter_attrs.add(node.attr)
            # 如果类的 __init__ 设置了被外部访问的属性，则此类需要保留
            if init_setter_attrs & accessed_instance_attrs.get(var_name, set()):
                missing_class_names.add(class_name)

        # 也检查 sorted_class_defs 中已有的类
        for cdef in sorted_class_defs:
            existing_class_names.add(cdef.name)

        # 将缺失的被依赖类补充到 class_defs（而非 module_statements），确保类定义在实例化语句之前
        need_resort = False
        for class_name in missing_class_names:
            if class_name not in existing_class_names:
                class_node = self.class_defs[class_name]
                class_defs[class_name] = class_node
                existing_class_names.add(class_name)
                need_resort = True

        # 将 module_statements 中的 ClassDef 节点也移到 class_defs，避免类定义出现在实例化之后
        class_stmts_from_module = []
        non_class_stmts = []
        for stmt in module_statements:
            if isinstance(stmt, ast.ClassDef):
                if stmt.name not in existing_class_names:
                    class_defs[stmt.name] = stmt
                    existing_class_names.add(stmt.name)
                    need_resort = True
                class_stmts_from_module.append(stmt)
            else:
                non_class_stmts.append(stmt)
        module_statements = non_class_stmts

        if need_resort:
            sorted_class_defs = self._sort_class_definitions(class_defs)

        # 收集所有代码段（带行号），最后按行号排序输出，确保与源文件顺序一致
        code_segments = []  # [(first_lineno, code, is_import)]

        # 提取导入语句
        import_set = set()
        for imp in all_imports:
            try:
                parent = self._find_parent(imp, optimized_imports)
                if isinstance(parent, (ast.Try, ast.With, ast.If)):
                    imp_node = parent
                else:
                    imp_node = imp
                imp_code = self._unparse_with_line_numbers(imp_node)
                if imp_code not in import_set:
                    import_set.add(imp_code)
                    lineno = getattr(imp_node, 'lineno', 0)
                    code_segments.append((lineno, imp_code, True))
            except Exception as e:
                print(f"Error unparsing import statement: {e}")

        # 提取类定义代码（剪枝：移除与密码API无关的方法）
        for class_def in sorted_class_defs:
            try:
                kept_methods = self._get_crypto_related_methods(class_def, usages, crypto_imported_names)
                all_class_methods = {item.name for item in class_def.body
                                     if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
                if all_class_methods and kept_methods != all_class_methods:
                    cls_code = self._unparse_class_with_pruning(class_def, kept_methods)
                else:
                    cls_code = self._unparse_with_line_numbers(class_def)
                lineno = getattr(class_def, 'lineno', 0)
                code_segments.append((lineno, cls_code, False))
            except Exception as e:
                print(f"Error unparsing class: {e}")

        # 提取模块级别的语句（已排除 ClassDef，仅剩赋值/调用等）
        module_set = set()
        for stmt in module_statements:
            try:
                stmt_code = self._unparse_with_line_numbers(stmt)
                if stmt_code not in module_set:
                    module_set.add(stmt_code)
                    lineno = getattr(stmt, 'lineno', 0)
                    code_segments.append((lineno, stmt_code, False))
            except Exception as e:
                print(f"Error unparsing module statement: {e}")

        # 提取函数定义代码（不包括嵌套函数和类方法）
        # 优化：若总行数超过100行，逐步移除离切片起点最远的前向切片子节点
        MAX_SLICE_LINES = 100

        # 计算函数定义行数，按顺序记录
        func_code_list = []  # [(func_name, lineno, code, line_count)]
        for func_name, func_def in function_defs.items():
            try:
                code = self._unparse_with_line_numbers(func_def) + "\n\n"
                line_count = code.count('\n') + 1
                lineno = getattr(func_def, 'lineno', 0)
                func_code_list.append((func_name, lineno, code, line_count))
            except Exception as e:
                print(f"Error unparsing function: {e}")

        # 计算当前非函数部分的行数
        non_func_lines = sum(seg.count('\n') + 1 for _, seg, _ in code_segments)
        func_total_lines = sum(item[3] for item in func_code_list)
        total_lines = non_func_lines + func_total_lines

        # 若超过100行，逐步移除离切片入口函数最远的子节点
        if total_lines > MAX_SLICE_LINES:
            # 计算每个函数的调用深度（从入口调用者出发的跳数）
            # 入口调用者 = 不被切片中其他函数调用的函数（调用链的最外层）
            # 如 starting_method 调用 call_method1 → call_method2 → call_method3
            # starting_method 深度0, call_method1 深度1, call_method2 深度2, call_method3 深度3

            # 标记包含密码API使用点的函数，这些函数不可移除
            usage_func_names = set()
            for usage in usages:
                current = usage
                while current and not isinstance(current, ast.Module):
                    if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if current.name in function_defs:
                            usage_func_names.add(current.name)
                        break
                    current = self._find_parent(current, self.ast_tree)

            all_func_names = set(function_defs.keys())

            # 找出被其他切片内函数调用的函数
            called_by_others = set()
            for fname in all_func_names:
                if fname in self.function_calls:
                    for called in self.function_calls[fname]:
                        if called in all_func_names:
                            called_by_others.add(called)

            # 入口函数 = 不被其他切片内函数调用的函数
            entry_funcs = all_func_names - called_by_others

            # BFS从入口函数出发计算深度
            func_depths = {}
            visited = set()
            queue = collections.deque()
            for name in entry_funcs:
                func_depths[name] = 0
                visited.add(name)
                queue.append(name)

            while queue:
                current = queue.popleft()
                current_depth = func_depths.get(current, 0)
                if current in self.function_calls:
                    for called in self.function_calls[current]:
                        if called in all_func_names and called not in visited:
                            func_depths[called] = current_depth + 1
                            visited.add(called)
                            queue.append(called)

            # 按深度降序排列（深度越大的离入口越远，优先移除）
            # 但包含密码API使用点的函数标记为不可移除（深度设为 -1 排到最后）
            func_code_list.sort(key=lambda x: (
                -1 if x[0] in usage_func_names else func_depths.get(x[0], 999)
            ), reverse=True)

            # 逐步移除，直到总行数低于100（跳过包含使用点的函数）
            removed_funcs = []
            while total_lines > MAX_SLICE_LINES and func_code_list:
                # 找到第一个不在 usage_func_names 中的函数
                removable_idx = None
                for idx, (fname, flno, fcode, lcount) in enumerate(func_code_list):
                    if fname not in usage_func_names:
                        removable_idx = idx
                        break
                if removable_idx is None:
                    break  # 所有剩余函数都包含使用点，无法继续移除
                removed = func_code_list.pop(removable_idx)
                total_lines -= removed[3]
                removed_funcs.append(removed[0])

        # 将函数定义加入 code_segments
        for fname, flno, fcode, lcount in func_code_list:
            code_segments.append((flno, fcode, False))

        # 按原始行号排序所有代码段，确保输出顺序与源文件一致
        code_segments.sort(key=lambda x: (not x[2], x[0]))  # 导入优先(按行号)，其余按行号

        # 组合所有代码
        combined_code = "\n".join(seg for _, seg, _ in code_segments)

        # 生成切片头注释信息
        # 密码API模块名
        # crypto_modules = sorted(crypto_imported_names)
        # crypto_modules_str = ", ".join(crypto_modules)

        # 切片起点：密码API使用点的行号及代码
        # entry_points = []
        # for usage in usages:
        #     if hasattr(usage, 'lineno'):
        #         try:
        #             usage_code = ast.unparse(usage).strip()
        #             # 截断过长的代码
        #             if len(usage_code) > 80:
        #                 usage_code = usage_code[:77] + "..."
        #             entry_points.append(f"L{usage.lineno}: {usage_code}")
        #         except Exception:
        #             entry_points.append(f"L{usage.lineno}")

        # entry_points_str = "; ".join(entry_points)
        # 构建头注释
        # header_lines = []
        # header_lines.append(f"# Crypto Modules: {crypto_modules_str}")
        # header_lines.append(f"# Entry Points: {entry_points_str}")
        # header_comment = "\n".join(header_lines) + "\n\n"
        #
        # slices.append(header_comment + combined_code)
        slices.append(combined_code)

        return slices

    def optimize_imports_for_slice(self, crypto_imports: Set[str], usages: List[ast.AST]) -> ast.AST:
        """
        直接在语法树中删除未使用的密码API导入语句
        返回修改后的语法树
        """
        used_identifiers = set()
        for usage in usages:
            if isinstance(usage, ast.Call):
                # 函数调用
                if isinstance(usage.func, ast.Name):
                    used_identifiers.add(usage.func.id)
                elif isinstance(usage.func, ast.Attribute):
                    if isinstance(usage.func.value, ast.Name):
                        used_identifiers.add(usage.func.value.id)
                for args in usage.args:
                    if isinstance(args, ast.Name):
                        used_identifiers.add(args.id)
                for keyword in usage.keywords:
                    if isinstance(keyword.value, ast.Name):
                        used_identifiers.add(keyword.value.id)
            elif isinstance(usage, ast.Attribute):
                # 属性访问
                if isinstance(usage.value, ast.Name):
                    used_identifiers.add(usage.value.id)
                current = usage
                while isinstance(current, ast.Attribute):
                    if isinstance(current.value, ast.Name):
                        used_identifiers.add(current.value.id)
                    current = current.value
            elif isinstance(usage, ast.Name):
                # 名称引用
                used_identifiers.add(usage.id)
            elif isinstance(usage, ast.Assign):
                # 赋值语句
                for target in usage.targets:
                    if isinstance(target, ast.Name):
                        # 检查是否将模块函数赋值给变量
                        if isinstance(usage.value, ast.Name):
                            used_identifiers.add(usage.value.id)
                        elif isinstance(usage.value, ast.Attribute):
                            if isinstance(usage.value.value, ast.Name):
                                used_identifiers.add(usage.value.value.id)
                            current = usage.value
                            while isinstance(current, ast.Attribute):
                                if isinstance(current.value, ast.Name):
                                    used_identifiers.add(current.value.id)
                                current = current.value
                        elif isinstance(usage.value, ast.Call):
                            if isinstance(usage.value.func, ast.Name):
                                used_identifiers.add(usage.value.func.id)
                            elif isinstance(usage.value.func, ast.Attribute):
                                if isinstance(usage.value.func.value, ast.Name):
                                    used_identifiers.add(usage.value.func.value.id)
                            for args in usage.value.args:
                                if isinstance(args, ast.Name):
                                    used_identifiers.add(args.id)
                            for keyword in usage.value.keywords:
                                if isinstance(keyword.value, ast.Name):
                                    used_identifiers.add(keyword.value.id)

        # 创建一个集合，包含所有密码相关的标识符（包括别名）
        all_crypto_identifiers = set(crypto_imports)
        used_crypto_identifiers = used_identifiers.intersection(all_crypto_identifiers)
        unused_crypto_identifiers = all_crypto_identifiers.difference(used_crypto_identifiers)

        # 4. 创建AST转换器，删除未使用的密码API导入
        class ImportRemover(ast.NodeTransformer):
            def __init__(self, unused_crypto_identifiers):
                self.unused_crypto_identifiers = unused_crypto_identifiers

            def visit_Import(self, node):
                # 过滤import语句
                filtered_names = []
                for alias in node.names:
                    module_name = alias.name
                    alias_name = alias.asname or module_name.split('.')[0]

                    # 检查是否是未使用的密码API导入
                    is_unused_crypto = alias_name in self.unused_crypto_identifiers

                    if not is_unused_crypto:
                        filtered_names.append(alias)

                if filtered_names:
                    # 创建新的import节点
                    new_node = ast.Import(names=filtered_names)
                    ast.copy_location(new_node, node)
                    return new_node
                else:
                    # 所有别名都是未使用的密码API，删除该节点
                    return None

            def visit_ImportFrom(self, node):
                module = node.module or ""
                filtered_names = []
                # print("module:", module)

                for alias in node.names:
                    imported_name = alias.name
                    alias_name = alias.asname or imported_name

                    if alias_name == "*" and module in self.unused_crypto_identifiers:
                        # 通配符导入情况
                        module_diff = Crypto_API_Base[module]['exports'].difference(self.unused_crypto_identifiers)
                        if module_diff != set():
                            filtered_names.append(alias)
                        else:
                            pass
                    else:
                        # 检查是否是未使用的密码API导入
                        is_unused_crypto = (
                                alias_name in self.unused_crypto_identifiers
                        )

                        if not is_unused_crypto:
                            filtered_names.append(alias)

                if filtered_names:
                    # 创建新的ImportFrom节点
                    new_node = ast.ImportFrom(
                        module=node.module,
                        names=filtered_names,
                        level=node.level
                    )
                    ast.copy_location(new_node, node)
                    return new_node
                else:
                    # 所有导入项都是未使用的密码API，删除该节点
                    return None

            def visit_Expr(self, node):
                # 检查动态导入表达式
                if isinstance(node.value, ast.Call):
                    call_node = node.value
                    # 检查是否是 __import__ 调用
                    if isinstance(call_node.func, ast.Name) and call_node.func.id == '__import__':
                        if call_node.args and isinstance(call_node.args[0], ast.Constant):
                            module_name = call_node.args[0].value
                            if isinstance(module_name, str):
                                identifier = module_name.split('.')[0]
                                if identifier in self.unused_crypto_identifiers:
                                    # 删除未使用的动态导入
                                    return None

                return self.generic_visit(node)

            def visit_Assign(self, node):
                # 检查赋值形式的动态导入
                if isinstance(node.value, ast.Call):
                    call_node = node.value
                    # 检查是否是 __import__ 调用
                    if isinstance(call_node.func, ast.Name) and call_node.func.id == '__import__':
                        if call_node.args and isinstance(call_node.args[0], ast.Constant):
                            module_name = call_node.args[0].value
                            if isinstance(module_name, str):
                                identifier = module_name.split('.')[0]
                                if identifier in self.unused_crypto_identifiers:
                                    # 检查赋值的目标是否被使用
                                    target_used = False
                                    for target in node.targets:
                                        if isinstance(target, ast.Name):
                                            # 这里需要检查target.id是否在used_identifiers中
                                            # 但由于我们只有unused_crypto_identifiers，需要特殊处理
                                            # 简化处理：如果目标变量名与模块名相同，则删除
                                            if target.id == identifier:
                                                target_used = False
                                            else:
                                                # 无法确定，保守保留
                                                return self.generic_visit(node)

                                    if not target_used:
                                        # 删除未使用的动态导入赋值
                                        return None

                return self.generic_visit(node)

        # 5. 应用转换器（在深拷贝上操作，避免破坏原始AST）
        remover = ImportRemover(unused_crypto_identifiers)
        tree_copy = copy.deepcopy(self.ast_tree)
        optimized_tree = remover.visit(tree_copy)

        # 6. 清理AST中的空节点
        class EmptyNodeCleaner(ast.NodeTransformer):
            def visit_Module(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                return node

            def visit_If(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                if node.orelse:
                    node.orelse = [self.visit(child) for child in node.orelse if child is not None]
                    node.orelse = [child for child in node.orelse if child is not None]
                return node

            def visit_For(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                if node.orelse:
                    node.orelse = [self.visit(child) for child in node.orelse if child is not None]
                    node.orelse = [child for child in node.orelse if child is not None]
                return node

            def visit_While(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                if node.orelse:
                    node.orelse = [self.visit(child) for child in node.orelse if child is not None]
                    node.orelse = [child for child in node.orelse if child is not None]
                return node

            def visit_FunctionDef(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                return node

            def visit_ClassDef(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                return node

            def visit_Try(self, node):
                node.body = [self.visit(child) for child in node.body if child is not None]
                node.body = [child for child in node.body if child is not None]
                for handler in node.handlers:
                    handler.body = [self.visit(child) for child in handler.body if child is not None]
                    handler.body = [child for child in handler.body if child is not None]
                if node.orelse:
                    node.orelse = [self.visit(child) for child in node.orelse if child is not None]
                    node.orelse = [child for child in node.orelse if child is not None]
                if node.finalbody:
                    node.finalbody = [self.visit(child) for child in node.finalbody if child is not None]
                    node.finalbody = [child for child in node.finalbody if child is not None]
                return node

        cleaner = EmptyNodeCleaner()
        final_tree = cleaner.visit(optimized_tree)

        # 7. 修复AST节点位置信息
        ast.fix_missing_locations(final_tree)

        return final_tree

    def _extract_definitions(self, ast_tree: ast.AST):
        """提取所有函数和类定义，区分全局函数和类方法，排除嵌套函数"""
        self.function_defs = {}  # 全局函数, 函数名与节点的映射
        self.class_defs = {}  # 类定义（包含类方法）, 类名与节点的映射
        self.nested_functions = set()  # 存储嵌套函数名，不单独处理
        self.class_methods = set()  # 新增：存储类方法名

        # 首先提取所有类定义
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.ClassDef):
                self.class_defs[node.name] = node
                # 记录类中的所有方法
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.class_methods.add(child.name)

        # 然后提取全局函数（排除类方法和嵌套函数）
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 检查函数是否是某个类的方法
                is_class_method = node.name in self.class_methods

                # 检查函数是否是嵌套函数（在另一个函数内部）
                is_nested = False

                if not is_class_method:
                    current = node
                    while current and not isinstance(current, ast.Module):
                        parent = self._find_parent(current, ast_tree)
                        if parent is None:
                            break

                        # 检查父节点是否是函数定义（说明是嵌套函数）
                        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            is_nested = True
                            break

                        current = parent

                # 只有全局函数（既不是类方法也不是嵌套函数）才添加到function_defs
                if not is_class_method and not is_nested:
                    self.function_defs[node.name] = node
                elif is_nested:
                    # 记录嵌套函数名，但不单独处理
                    self.nested_functions.add(node.name)

    def _analyze_function_calls(self, ast_tree: ast.AST):
        """分析函数调用关系"""
        self.function_calls = {}

        # 遍历AST，记录每个函数中调用的其他函数
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_name = node.name
                called_functions = set()

                # 查找函数体中的所有函数调用
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            called_functions.add(child.func.id)
                        elif (isinstance(child.func, ast.Attribute) and
                              isinstance(child.func.value, ast.Name)):
                            # 处理对象方法调用，如obj.method()
                            called_functions.add(child.func.value.id)

                self.function_calls[function_name] = called_functions

    def _analyze_globals_and_dependencies(self, ast_tree: ast.AST):
        """分析全局变量和变量依赖关系"""
        self.global_vars = set()
        self.var_dependencies = {}
        self.var_usages = {}

        # 首先收集所有全局变量
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assign) and self._is_module_level(node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.global_vars.add(target.id)

        # 分析变量依赖关系
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assign) and self._is_module_level(node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        dependencies = self._find_var_dependencies(node.value)
                        self.var_dependencies[var_name] = dependencies

        # 分析变量使用情况
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                var_name = node.id
                if var_name in self.var_usages:
                    self.var_usages[var_name].append(node)
                else:
                    self.var_usages[var_name] = [node]

    def _find_functions_with_crypto_args(self, crypto_imported_names: Set[str]) -> Set[str]:
        """
        查找所有使用密码API作为参数的函数定义
        Args:
            crypto_imported_names: 密码相关的模块名及其标识符字典
        Returns:
            使用密码API作为参数的函数名集合
        """
        crypto_functions = set()
        # 提取所有密码相关的标识符
        all_identifiers = set(crypto_imported_names)

        # 遍历所有函数定义
        for func_name, func_def in self.function_defs.items():
            for node in ast.walk(func_def):
                if isinstance(node, ast.Call):
                    # 检查调用中的参数是否包含密码API
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in all_identifiers:
                            crypto_functions.add(func_name)
                            break
                        elif isinstance(arg, ast.Attribute):
                            current = arg
                            while isinstance(current, ast.Attribute):
                                current = current.value
                            if isinstance(current, ast.Name) and current.id in all_identifiers:
                                crypto_functions.add(func_name)
                                break

        return crypto_functions

    def _is_module_level(self, node: ast.AST) -> bool:
        """检查节点是否在模块级别"""
        current = node
        while current and not isinstance(current, ast.Module):
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return False
            current = self._find_parent(current, self.ast_tree)
        return True

    def _find_var_dependencies(self, node: ast.AST) -> Set[str]:
        """查找变量赋值右侧的依赖"""
        dependencies = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):  # 例如: x = random, 或, x = y
                dependencies.add(child.id)
            elif isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):  # 例如: x = random.randint
                dependencies.add(child.value.id)

        return dependencies

    def _is_nested_function(self, node: ast.AST) -> bool:
        """检查节点是否是嵌套函数"""
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False

        current = node
        while current and not isinstance(current, ast.Module):
            parent = self._find_parent(current, self.ast_tree)
            if parent is None:
                break

            # 检查父节点是否是函数定义（说明是嵌套函数）
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return True

            current = parent

        return False

    def find_call_chain(self, function_name: str) -> Set:
        """
        查找函数调用链中的所有相关函数定义
        Args:
            function_name: 起始函数名
        Returns:
            调用链中的所有函数定义
        """
        call_chain = set()
        visited = set()

        # 使用队列进行广度优先BFS遍历
        queue = collections.deque([function_name])

        while queue:
            current_func = queue.popleft()

            # 跳过已访问或不在函数定义中的函数
            if current_func in visited or current_func not in self.function_defs:
                continue

            visited.add(current_func)
            call_chain.add(self.function_defs[current_func])

            # 查找该函数调用的其他函数
            if current_func in self.function_calls:
                for called_func in self.function_calls[current_func]:
                    # 只添加未访问的函数
                    if called_func not in visited:
                        queue.append(called_func)

            # 查找通过回调或高阶函数调用的函数
            additional_calls = self._find_indirect_calls(current_func)
            for indirect_func in additional_calls:
                if indirect_func not in visited and indirect_func in self.function_defs:
                    queue.append(indirect_func)

        return call_chain

    def _find_indirect_calls(self, function_name: str) -> Set[str]:
        """
        查找间接调用的函数（通过参数传递、回调等）
        Args:
            function_name: 函数名
        Returns:
            间接调用的函数名集合
        """
        indirect_calls = set()

        if function_name not in self.function_defs:
            return indirect_calls

        func_def = self.function_defs[function_name]

        # 遍历函数定义，查找可能的间接调用
        for node in ast.walk(func_def):
            # 查找函数调用
            if isinstance(node, ast.Call):
                # 检查参数中是否包含函数引用
                for arg in node.args:
                    indirect_calls.update(self._extract_function_references(arg))

                # 检查关键字参数中是否包含函数引用
                for kw in node.keywords:
                    indirect_calls.update(self._extract_function_references(kw.value))

            # 查找赋值语句中的函数引用
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # 检查赋值右侧是否包含函数引用
                        indirect_calls.update(self._extract_function_references(node.value))

            # 查找返回语句中的函数引用
            elif isinstance(node, ast.Return):
                if node.value:
                    indirect_calls.update(self._extract_function_references(node.value))

        return indirect_calls

    def _extract_function_references(self, node: ast.AST) -> Set[str]:
        """
        从AST节点中提取函数引用
        Args:
            node: AST节点
        Returns:
            函数名集合
        """
        function_refs = set()

        if isinstance(node, ast.Name):
            # 直接函数名引用
            if node.id in self.function_defs:
                function_refs.add(node.id)

        elif isinstance(node, ast.Attribute):
            # 属性引用（如obj.method）
            if isinstance(node.value, ast.Name) and node.value.id in self.function_defs:
                function_refs.add(node.value.id)

        elif isinstance(node, ast.Call):
            # 函数调用
            if isinstance(node.func, ast.Name) and node.func.id in self.function_defs:
                function_refs.add(node.func.id)
            elif (isinstance(node.func, ast.Attribute) and
                  isinstance(node.func.value, ast.Name) and
                  node.func.value.id in self.function_defs):
                function_refs.add(node.func.value.id)

        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            # 容器类型中的函数引用
            for elt in node.elts:
                function_refs.update(self._extract_function_references(elt))

        elif isinstance(node, ast.Dict):
            # 字典中的函数引用
            for key in node.keys:
                function_refs.update(self._extract_function_references(key))
            for value in node.values:
                function_refs.update(self._extract_function_references(value))

        elif isinstance(node, ast.Lambda):
            # Lambda表达式中的函数调用
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name) and child.func.id in self.function_defs:
                        function_refs.add(child.func.id)

        elif isinstance(node, ast.IfExp):
            # 条件表达式中的函数引用
            function_refs.update(self._extract_function_references(node.test))
            function_refs.update(self._extract_function_references(node.body))
            function_refs.update(self._extract_function_references(node.orelse))

        elif isinstance(node, ast.BoolOp):
            # 布尔操作中的函数引用
            for value in node.values:
                function_refs.update(self._extract_function_references(value))

        elif isinstance(node, ast.BinOp):
            # 二元操作中的函数引用
            function_refs.update(self._extract_function_references(node.left))
            function_refs.update(self._extract_function_references(node.right))

        elif isinstance(node, ast.UnaryOp):
            # 一元操作中的函数引用
            function_refs.update(self._extract_function_references(node.operand))

        elif isinstance(node, ast.Compare):
            # 比较操作中的函数引用
            function_refs.update(self._extract_function_references(node.left))
            for comparator in node.comparators:
                function_refs.update(self._extract_function_references(comparator))

        elif isinstance(node, ast.Subscript):
            # 下标操作中的函数引用
            function_refs.update(self._extract_function_references(node.value))
            function_refs.update(self._extract_function_references(node.slice))

        return function_refs

    def find_functions_using_global_vars(self, global_vars: Set[str]) -> Set:
        """
        查找使用指定全局变量的函数
        Args:
            global_vars: 全局变量名集合
        Returns:
            使用这些全局变量的函数定义集合
        """
        functions_using_globals = set()

        for func_name, func_def in self.function_defs.items():
            # 检查函数中是否有global声明
            for node in ast.walk(func_def):
                if isinstance(node, ast.Global):
                    for name in node.names:
                        if name in global_vars:
                            functions_using_globals.add(func_def)
                            break

            # 检查函数中是否使用了全局变量
            for node in ast.walk(func_def):
                if (isinstance(node, ast.Name) and
                        isinstance(node.ctx, ast.Load) and
                        node.id in global_vars):
                    functions_using_globals.add(func_def)
                    break

        return functions_using_globals

    def find_functions_calling_functions(self, target_functions: Set[str]) -> Set:
        """
        查找调用指定函数的函数（支持多层回溯）
        Args:
            target_functions: 目标函数名集合
        Returns:
            调用这些目标函数的函数定义集合（包含间接调用者）
        """
        calling_functions = set()
        visited = set(target_functions)  # 已处理的目标函数名
        current_targets = set(target_functions)  # 当前轮要查找的目标

        while current_targets:
            next_targets = set()

            for func_name, func_def in self.function_defs.items():
                if func_name in visited:
                    continue  # 避免重复处理和循环
                if func_name in self.function_calls:
                    called_functions = self.function_calls[func_name]
                    if any(called_func in current_targets for called_func in called_functions):
                        calling_functions.add(func_def)
                        visited.add(func_name)
                        next_targets.add(func_name)  # 新找到的调用者也作为下一轮的目标

            current_targets = next_targets

        return calling_functions

    def is_module_level_usage(self, usage_node: ast.AST) -> bool:
        """
        检查使用点是否在模块级别（不在任何函数内）
        Args:
            usage_node: 使用点AST节点
        Returns:
            如果使用点在模块级别，返回True；否则返回False
        """
        if usage_node is None or self.ast_tree is None:
            return False

        current = usage_node
        while current and not isinstance(current, ast.Module):
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return False
            current = self._find_parent(current, self.ast_tree)

            # 防止无限循环
            if current is usage_node:
                break

        return True

    def _find_parent(self, target_node: ast.AST, ast_tree: ast.AST) -> Optional[ast.AST]:
        """查找AST节点的父节点，优先使用预计算的.parent属性"""
        if ast_tree is None or target_node is None:
            return None

        # 优先使用_add_parent_refs预计算的parent属性（O(1)）
        parent = getattr(target_node, 'parent', None)
        if parent is not None:
            return parent

        # Fallback: 遍历整棵树查找（O(n)）
        for parent in ast.walk(ast_tree):
            if parent is None:
                continue

            for field, value in ast.iter_fields(parent):
                if isinstance(value, list):
                    for child in value:
                        if child is None:
                            continue
                        if child is target_node:
                            return parent
                elif value is target_node:
                    return parent
        return None

    def find_crypto_related_variables(self, crypto_imported_names: Set[str], usages: List[ast.AST]) -> Set[str]:
        """
        查找与密码相关的变量，增强版：考虑global关键字
        Args:
            crypto_imported_names: 密码相关的模块名及其标识符列表字典
            usages: 密码API使用点列表
        Returns:
            与密码相关的变量名集合
        """
        crypto_related_vars = set()
        # 提取所有密码相关的标识符
        all_identifiers = set(crypto_imported_names)

        # 第一步：从密码API使用点中提取直接使用的变量
        for usage in usages:
            # 处理函数调用
            if isinstance(usage, ast.Call):
                # 检查参数中的变量
                for arg in usage.args:
                    crypto_related_vars.update(self._extract_variables_from_node(arg))

                # 检查关键字参数中的变量
                for kw in usage.keywords:
                    crypto_related_vars.update(self._extract_variables_from_node(kw.value))

                # 检查函数调用本身的变量（如func()中的func）
                if isinstance(usage.func, ast.Name):
                    crypto_related_vars.add(usage.func.id)
                elif isinstance(usage.func, ast.Attribute) and isinstance(usage.func.value, ast.Name):
                    crypto_related_vars.add(usage.func.value.id)

            # 处理属性访问
            elif isinstance(usage, ast.Attribute):
                if isinstance(usage.value, ast.Name):
                    crypto_related_vars.add(usage.value.id)

            # 处理名称引用
            elif isinstance(usage, ast.Name) and isinstance(usage.ctx, ast.Load):
                crypto_related_vars.add(usage.id)

        # 第二步：查找直接依赖密码模块的变量
        for var_name, dependencies in self.var_dependencies.items():
            for dep in dependencies:
                if dep in all_identifiers:
                    crypto_related_vars.add(var_name)
                    break

        # 第三步：通过传递依赖关系扩展相关变量集合
        # 计算变量的传递依赖关系
        transitive_deps = self._compute_transitive_dependencies()
        extended_crypto_vars = crypto_related_vars
        for var_name, dependencies in transitive_deps.items():
            # 如果变量依赖任何已识别的密码相关变量，则将其加入
            if any(dep in crypto_related_vars for dep in dependencies):
                extended_crypto_vars.add(var_name)

        # 第四步：查找在密码相关函数中使用的变量
        crypto_function_vars = self._find_variables_in_crypto_functions(usages)
        extended_crypto_vars.update(crypto_function_vars)

        # 第五步：查找在密码相关类中使用的变量
        crypto_class_vars = self._find_variables_in_crypto_classes(usages)
        extended_crypto_vars.update(crypto_class_vars)

        # 第六步：查找全局变量中与密码相关的变量
        global_crypto_vars = self._find_global_crypto_variables(crypto_imported_names)
        extended_crypto_vars.update(global_crypto_vars)

        # 第七步：查找所有在密码API调用中使用的变量，包括作为参数传递的变量
        for usage in usages:
            if isinstance(usage, ast.Call):
                # 检查所有参数
                for arg in usage.args:
                    if isinstance(arg, ast.Name):
                        extended_crypto_vars.add(arg.id)

                # 检查所有关键字参数
                for kw in usage.keywords:
                    if isinstance(kw.value, ast.Name):
                        extended_crypto_vars.add(kw.value.id)

        # 第八步：查找密码相关函数中被global关键字引用的变量
        # 只收集包含密码API使用点的函数中的global变量，避免保留无关全局变量
        crypto_funcs = set()
        for usage in usages:
            current = usage
            while current and not isinstance(current, ast.Module):
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    crypto_funcs.add(current)
                    break
                current = self._find_parent(current, self.ast_tree)
        global_referenced_vars = self._find_global_variables_usage(crypto_funcs)
        extended_crypto_vars.update(global_referenced_vars)

        # 第九步：过滤掉Python内置函数和关键字
        filtered_vars = set()
        for var in extended_crypto_vars:
            if not self._is_builtin_or_keyword(var):
                filtered_vars.add(var)

        return filtered_vars

    def extract_module_level_statements_with_exclusion(self, crypto_imported_names: Set[str],
                                                       crypto_related_vars: Set[str],
                                                       excluded_definitions: Set[str],
                                                       crypto_related_func_names: Set[str] = None) -> List:
        """
        提取模块级别的语句，排除指定的定义，增强版：考虑global关键字和函数调用
        Args:
            crypto_imported_names: 密码相关的模块名及其标识符列表字典
            crypto_related_vars: 与密码相关的变量名集合
            excluded_definitions: 要排除的定义名称集合
            crypto_related_func_names: 密码相关的函数/类名集合，用于识别调用这些函数的模块级语句
        Returns:
            模块级别的语句列表
        """
        # 展平并去重所有密码相关的标识符
        all_identifiers = set(crypto_imported_names)
        aliases = list(all_identifiers)

        # 计算变量的传递依赖关系
        transitive_deps = self._compute_transitive_dependencies()

        # 扩展crypto_related_vars包含所有间接相关的变量
        extended_crypto_vars = set(crypto_related_vars)
        for var_name, dependencies in transitive_deps.items():
            if any(dep in crypto_related_vars for dep in dependencies):
                extended_crypto_vars.add(var_name)

        # 将已有的密码相关全局变量加入（已在find_crypto_related_variables中过滤）
        # 不再无条件添加所有global声明的变量

        # 提取所有模块级别的语句
        module_statements = []
        for node in self.ast_tree.body:
            # 跳过导入语句，因为我们会单独处理
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue

            # 如果是函数或类定义，并且名称在排除列表中，则跳过
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in excluded_definitions:
                    continue

            # 检查语句是否包含密码API使用
            has_crypto_usage = False

            # 对于赋值语句，检查是否定义了密码相关的全局变量
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Name) and
                            target.id in extended_crypto_vars):
                        has_crypto_usage = True
                        break
                    # 检查赋值右侧是否包含密码相关变量
                    if self._check_node_contains_crypto_usage(node.value, aliases, extended_crypto_vars):
                        has_crypto_usage = True
                        break
                    # 检查赋值左侧是否包含密码模块的属性访问（如 os.environ['KEY'] = val）
                    if self._check_node_contains_crypto_usage(target, aliases, extended_crypto_vars):
                        has_crypto_usage = True
                        break

            # 遍历语句中的所有节点
            for child_node in ast.walk(node):
                # 检查直接使用密码模块别名
                if (isinstance(child_node, ast.Name) and
                        child_node.id in aliases and
                        isinstance(child_node.ctx, ast.Load)):
                    has_crypto_usage = True
                    break

                # 检查属性访问（如crypto.module.function）
                elif (isinstance(child_node, ast.Attribute) and
                      isinstance(child_node.value, ast.Name) and
                      child_node.value.id in aliases):
                    has_crypto_usage = True
                    break

                # 检查变量使用（直接或间接相关的变量）
                elif (isinstance(child_node, ast.Name) and
                      child_node.id in extended_crypto_vars and
                      isinstance(child_node.ctx, ast.Load)):
                    has_crypto_usage = True
                    break

                # 检查是否调用了密码相关的函数/类（如 starting_method(), BaseRunner()）
                elif (isinstance(child_node, ast.Call) and
                      isinstance(child_node.func, ast.Name) and
                      crypto_related_func_names is not None and
                      child_node.func.id in crypto_related_func_names):
                    has_crypto_usage = True
                    break

            # 如果语句包含密码使用，添加到结果列表
            if has_crypto_usage:
                module_statements.append(node)

        return module_statements

    def extract_all_imports(self, optimized_imports: ast.AST) -> List[ast.AST]:
        """
        提取所有导入语句（包括嵌套在控制流中的导入）
        """
        imports = []

        def traverse_nodes(nodes):
            for node in nodes:
                # 直接导入语句
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    imports.append(node)

                # 处理try...except块
                elif isinstance(node, ast.Try):
                    traverse_nodes(node.body)
                    for handler in node.handlers:
                        traverse_nodes(handler.body)
                    if node.orelse:
                        traverse_nodes(node.orelse)
                    if node.finalbody:
                        traverse_nodes(node.finalbody)

                elif isinstance(node, ast.If):
                    traverse_nodes(node.body)
                    if node.orelse:
                        traverse_nodes(node.orelse)

        traverse_nodes(optimized_imports.body)
        return imports

    def _check_node_contains_crypto_usage(self, node: ast.AST, aliases: List[str],
                                          extended_crypto_vars: Set[str]) -> bool:
        """
        检查AST节点是否包含密码相关使用
        Args:
            node: AST节点
            aliases: 密码相关别名列表
            extended_crypto_vars: 扩展的密码相关变量集合
        Returns:
            是否包含密码相关使用
        """
        for child_node in ast.walk(node):
            # 检查直接使用密码模块别名
            if (isinstance(child_node, ast.Name) and
                    child_node.id in aliases and
                    isinstance(child_node.ctx, ast.Load)):
                return True

            # 检查属性访问（如crypto.module.function）
            elif (isinstance(child_node, ast.Attribute) and
                  isinstance(child_node.value, ast.Name) and
                  child_node.value.id in aliases):
                return True

            # 检查变量使用（直接或间接相关的变量）
            elif (isinstance(child_node, ast.Name) and
                  child_node.id in extended_crypto_vars and
                  isinstance(child_node.ctx, ast.Load)):
                return True

        return False

    def _compute_transitive_dependencies(self) -> Dict[str, Set[str]]:
        """
        计算变量的传递依赖关系（传递闭包）
        Returns:
            变量名到其所有直接和间接依赖的映射
        """
        # 构建依赖图
        graph = {var: deps.copy() for var, deps in self.var_dependencies.items()}

        # 添加所有变量节点（包括那些没有依赖的变量）
        for var in self.global_vars:
            if var not in graph:
                graph[var] = set()

        # 计算传递闭包
        nodes = list(graph.keys())
        closure = {node: set(deps) for node, deps in graph.items()}

        # 使用Floyd-Warshall算法计算传递闭包
        changed = True
        while changed:
            changed = False
            for k in nodes:
                for i in nodes:
                    if k in closure[i]:
                        for j in nodes:
                            if j in closure[k] and j not in closure[i]:
                                closure[i].add(j)
                                changed = True

        return closure

    def _extract_variables_from_node(self, node: Optional[ast.expr]) -> Set[str]:
        """
        从AST表达式节点中提取所有变量名
        Args:
            node: AST表达式节点（支持None）
        Returns:
            变量名集合
        """
        variables = set()

        if node is None:
            return variables

        # 处理基础表达式节点
        if isinstance(node, ast.Name):
            variables.add(node.id)
            return variables

        # 处理属性访问
        if isinstance(node, ast.Attribute):
            # 对于属性访问，提取对象变量
            if isinstance(node.value, ast.Name):
                variables.add(node.value.id)
            # 递归处理嵌套属性
            variables.update(self._extract_variables_from_node(node.value))
            return variables

        # 处理函数调用
        if isinstance(node, ast.Call):
            # 提取函数调用中的变量
            variables.update(self._extract_variables_from_node(node.func))
            for arg in node.args:
                variables.update(self._extract_variables_from_node(arg))
            for kw in node.keywords:
                variables.update(self._extract_variables_from_node(kw.value))
            return variables

        # 处理容器类型
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                variables.update(self._extract_variables_from_node(elt))
            return variables

        # 处理字典
        if isinstance(node, ast.Dict):
            for key in node.keys:
                variables.update(self._extract_variables_from_node(key))
            for value in node.values:
                variables.update(self._extract_variables_from_node(value))
            return variables

        # 处理下标操作
        if isinstance(node, ast.Subscript):
            variables.update(self._extract_variables_from_node(node.value))
            # 处理Python 3.9+的slice表示
            if hasattr(ast, 'Slice'):
                slice_node = node.slice
                if isinstance(slice_node, ast.Slice):
                    if slice_node.lower:
                        variables.update(self._extract_variables_from_node(slice_node.lower))
                    if slice_node.upper:
                        variables.update(self._extract_variables_from_node(slice_node.upper))
                    if slice_node.step:
                        variables.update(self._extract_variables_from_node(slice_node.step))
                elif isinstance(slice_node, ast.Index):
                    # 处理旧版本Index节点
                    variables.update(self._extract_variables_from_node(slice_node.value))
                elif isinstance(slice_node, (ast.Name, ast.Attribute, ast.Call)):
                    # 直接处理简单slice表达式
                    variables.update(self._extract_variables_from_node(slice_node))
            return variables

        # 处理各种操作符表达式
        if isinstance(node, ast.BinOp):
            variables.update(self._extract_variables_from_node(node.left))
            variables.update(self._extract_variables_from_node(node.right))
            return variables

        if isinstance(node, ast.UnaryOp):
            variables.update(self._extract_variables_from_node(node.operand))
            return variables

        if isinstance(node, ast.Compare):
            variables.update(self._extract_variables_from_node(node.left))
            for comparator in node.comparators:
                variables.update(self._extract_variables_from_node(comparator))
            return variables

        if isinstance(node, ast.BoolOp):
            for value in node.values:
                variables.update(self._extract_variables_from_node(value))
            return variables

        if isinstance(node, ast.IfExp):
            variables.update(self._extract_variables_from_node(node.test))
            variables.update(self._extract_variables_from_node(node.body))
            variables.update(self._extract_variables_from_node(node.orelse))
            return variables

        if isinstance(node, ast.Lambda):
            # Lambda表达式中的变量（排除参数）
            param_names = {param.arg for param in node.args.args}
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id not in param_names:
                    variables.add(child.id)
            return variables

        # 处理常量和其他不需要提取变量的表达式类型
        # 如：ast.Constant, ast.Num, ast.Str, etc.
        if isinstance(node, (ast.Constant, ast.Num, ast.Str, ast.Bytes,
                             ast.Ellipsis, ast.NameConstant)):
            return variables  # 常量不包含变量名

        # 处理星号表达式
        if isinstance(node, ast.Starred):
            variables.update(self._extract_variables_from_node(node.value))
            return variables

        # 处理海象运算符
        if isinstance(node, ast.NamedExpr):
            variables.update(self._extract_variables_from_node(node.target))
            variables.update(self._extract_variables_from_node(node.value))
            return variables

        return variables

    def _find_variables_in_crypto_functions(self, usages: List[ast.AST]) -> Set[str]:
        """
        查找在密码相关函数中使用的变量
        Args:
            usages: 密码API使用点列表
        Returns:
            在密码相关函数中使用的变量集合
        """
        # 查找所有与密码相关的函数定义
        crypto_function_vars = set()
        crypto_functions = set()
        for usage in usages:
            # 找到包含使用点的函数
            current = usage
            while current and not isinstance(current, ast.Module):
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    crypto_functions.add(current)
                    break
                current = self._find_parent(current, self.ast_tree)

        # 查找这些函数中使用的变量
        for func in crypto_functions:
            for node in ast.walk(func):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    crypto_function_vars.add(node.id)

        return crypto_function_vars

    def _find_variables_in_crypto_classes(self, usages: List[ast.AST]) -> Set[str]:
        """
        查找在密码相关类中使用的变量
        Args:
            usages: 密码API使用点列表
        Returns:
            在密码相关类中使用的变量集合
        """
        crypto_class_vars = set()
        # 查找所有与密码相关的类定义
        crypto_classes = set()
        for usage in usages:
            # 找到包含使用点的类
            current = usage
            while current and not isinstance(current, ast.Module):
                if isinstance(current, ast.ClassDef):
                    crypto_classes.add(current)
                    break
                current = self._find_parent(current, self.ast_tree)

        # 查找这些类中使用的变量
        for cls in crypto_classes:
            for node in ast.walk(cls):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    crypto_class_vars.add(node.id)

        return crypto_class_vars

    def _find_global_crypto_variables(self, crypto_imported_names: Set[str]) -> Set[str]:
        """
        查找全局变量中与密码相关的变量
        Args:
            crypto_imported_names: 密码相关的模块名及其标识符列表字典
        Returns:
            全局变量中与密码相关的变量集合
        """
        global_crypto_vars = set()
        # 提取所有密码相关的标识符
        all_identifiers = set(crypto_imported_names)

        # 检查全局变量是否依赖密码模块
        for var_name in self.global_vars:
            if var_name in self.var_dependencies:
                dependencies = self.var_dependencies[var_name]
                if any(dep in all_identifiers for dep in dependencies):
                    global_crypto_vars.add(var_name)

        return global_crypto_vars

    def _find_global_variables_usage(self, crypto_related_funcs: Set[ast.AST] = None) -> Set[str]:
        """
        查找被global关键字引用的全局变量
        如果提供了crypto_related_funcs，则只收集这些密码相关函数中的global变量
        如果未提供或为空集合，则返回空集（不收集无关的global变量）
        Args:
            crypto_related_funcs: 密码相关的函数定义节点集合
        Returns:
            被global关键字引用的变量名集合
        """
        global_vars = set()

        if crypto_related_funcs:
            # 只收集密码相关函数中的global变量
            for func_def in crypto_related_funcs:
                for node in ast.walk(func_def):
                    if isinstance(node, ast.Global):
                        global_vars.update(node.names)

        return global_vars

    def _find_env_var_related_names(self, usages: List[ast.AST], crypto_imported_names: Set[str]) -> Set[str]:
        """
        查找与密码API调用相关的环境变量赋值语句中涉及的所有模块别名
        如 os.environ['CURL_CA_BUNDLE'] = "" 会返回 {'os'}
        这样在模块级语句提取时能识别并保留这些环境变量赋值
        """
        related_names = set()
        # 获取所有密码相关的模块别名（包括os等非密码模块的别名）
        for node in ast.walk(self.ast_tree):
            if isinstance(node, ast.Assign):
                # 检查赋值左侧是否是 X.environ[...] 形式
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        # 检查 Subscript 的 value 是否是 X.environ 属性访问
                        sub_value = target.value
                        if (isinstance(sub_value, ast.Attribute) and
                                sub_value.attr == 'environ' and
                                isinstance(sub_value.value, ast.Name)):
                            module_alias = sub_value.value.id
                            # 检查该环境变量赋值是否与密码API调用在同一上下文中
                            # 策略：只要文件中有密码API使用，就保留所有 environ 赋值
                            # 因为环境变量通常很少，且都可能影响密码API行为
                            related_names.add(module_alias)
        return related_names

    def _is_builtin_or_keyword(self, var_name: str) -> bool:
        """
        检查变量名是否是Python内置函数或关键字
        Args:
            var_name: 变量名
        Returns:
            如果是内置函数或关键字返回True，否则返回False
        """
        # Python关键字列表
        keywords = {
            'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await',
            'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
            'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is',
            'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
            'try', 'while', 'with', 'yield'
        }

        # Python内置函数列表
        builtins = {
            'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'breakpoint', 'bytearray',
            'bytes', 'callable', 'chr', 'classmethod', 'compile', 'complex',
            'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate',
            'eval', 'exec', 'exit', 'filter', 'float', 'format', 'frozenset',
            'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input',
            'int', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list',
            'locals', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct',
            'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'repr',
            'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod',
            'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip'
        }

        return var_name in keywords or var_name in builtins

    def find_related_definitions(self, usage_node: ast.AST) -> Set[ast.AST]:
        """
        查找与密码API使用相关的所有定义（优化版，避免重复）
        Args:
            usage_node: 使用点AST节点
        Returns:
            相关定义的AST节点集合
        """
        if usage_node is None or self.ast_tree is None:
            return set()

        related_defs = set()

        # 查找包含使用点的函数或类
        current = usage_node
        while current and not isinstance(current, ast.Module):
            if isinstance(current, ast.ClassDef):
                related_defs.add(current)
                break
            elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                related_defs.add(current)
                # 沿着嵌套层级向上查找，直到找到类定义或到达模块级别
                ancestor = self._find_parent(current, self.ast_tree)
                while ancestor and not isinstance(ancestor, ast.Module):
                    if isinstance(ancestor, ast.ClassDef):
                        related_defs.add(ancestor)
                        break
                    elif isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        related_defs.add(ancestor)
                    ancestor = self._find_parent(ancestor, self.ast_tree)
                break
            current = self._find_parent(current, self.ast_tree)

            # 防止无限循环
            if current is usage_node:
                break

        # 查找所有被调用的函数和类
        called_defs = self.find_all_called_definitions(usage_node)

        # 使用名称去重
        called_defs = self._remove_duplicate_definitions(called_defs)
        related_defs.update(called_defs)

        # 查找与密码API相关的类实例化
        # 规则：仅当以下条件之一满足时，保留该类的定义：
        #   1. 实例化参数中包含密码API相关标识符
        #   2. 实例化发生在已识别的密码相关函数/类内部
        # 类内部包含密码API的情况会在上方的函数/类回溯中处理
        crypto_context_names = {def_node.name for def_node in related_defs
                                if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        instantiations = self.find_class_instantiations(self.ast_tree)
        for instantiation in instantiations:
            # 查找实例化的类定义
            if (instantiation is not None and
                    isinstance(instantiation.func, ast.Name) and
                    instantiation.func.id in self.class_defs):
                # 检查1: 实例化参数中是否包含密码API相关标识符
                if self._is_crypto_related_instantiation(instantiation):
                    related_defs.add(self.class_defs[instantiation.func.id])
                else:
                    # 检查2: 实例化是否发生在密码相关的上下文中
                    parent = self._find_parent(instantiation, self.ast_tree)
                    while parent and not isinstance(parent, ast.Module):
                        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            if parent.name in crypto_context_names:
                                related_defs.add(self.class_defs[instantiation.func.id])
                            break
                        parent = self._find_parent(parent, self.ast_tree)

        # 递归查找被调用函数和类中调用的其他函数和类
        visited_defs = set()

        def collect_related(def_node):
            if def_node is None or def_node in visited_defs:
                return 
            visited_defs.add(def_node)

            # 对于函数定义，查找其中的调用
            if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 检查这个函数是否是某个类的方法
                is_class_method = False
                parent = self._find_parent(def_node, self.ast_tree)
                while parent and not isinstance(parent, ast.Module):
                    if isinstance(parent, ast.ClassDef):
                        is_class_method = True
                        break
                    parent = self._find_parent(parent, self.ast_tree)

                # 如果是类方法，我们不单独收集，因为类定义已经包含了它
                if not is_class_method:
                    more_called_defs = self.find_all_called_definitions(def_node)
                    # 去重后再添加
                    more_called_defs = self._remove_duplicate_definitions(more_called_defs)
                    related_defs.update(more_called_defs)

                    # 递归处理新找到的定义
                    for new_def in more_called_defs:
                        collect_related(new_def)

            # 对于类定义，查找其中的方法
            elif isinstance(def_node, ast.ClassDef):
                # 类定义本身已经包含了方法，所以我们不需要单独添加类方法
                # 只需查找类中调用的其他函数
                for node in def_node.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        more_called_defs = self.find_all_called_definitions(node)
                        # 去重后再添加
                        more_called_defs = self._remove_duplicate_definitions(more_called_defs)
                        related_defs.update(more_called_defs)

                        # 递归处理新找到的定义（但不包括类方法本身）
                        for new_def in more_called_defs:
                            # 检查新定义是否是类方法
                            is_new_class_method = False
                            if isinstance(new_def, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                parent = self._find_parent(new_def, self.ast_tree)
                                while parent and not isinstance(parent, ast.Module):
                                    if isinstance(parent, ast.ClassDef):
                                        is_new_class_method = True
                                        break
                                    parent = self._find_parent(parent, self.ast_tree)

                            # 只收集非类方法的定义
                            if not is_new_class_method:
                                collect_related(new_def)

        # 对初始找到的定义进行递归收集
        for def_node in list(related_defs):
            collect_related(def_node)

        # 最后，移除所有类方法，只保留类定义本身
        final_defs = set()
        for def_node in related_defs:
            if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 检查是否是类方法
                is_class_method = False
                parent = self._find_parent(def_node, self.ast_tree)
                while parent and not isinstance(parent, ast.Module):
                    if isinstance(parent, ast.ClassDef):
                        is_class_method = True
                        break
                    parent = self._find_parent(parent, self.ast_tree)

                # 如果不是类方法，则保留
                if not is_class_method:
                    final_defs.add(def_node)
            else:
                # 非函数定义（类定义等）直接保留
                final_defs.add(def_node)

        return final_defs

    def find_all_called_definitions(self, usage_node: ast.AST) -> Set:
        """
        查找所有被调用的函数和类定义
        修复：不处理嵌套函数作为独立的函数定义
        Args:
            usage_node: 使用点AST节点
        Returns:
            被调用的函数和类的AST节点集合
        """
        if usage_node is None:
            return set()

        called_defs = set()

        # 遍历使用点及其子节点，查找所有函数调用和类实例化
        for node in ast.walk(usage_node):
            if node is None:
                continue

            if isinstance(node, ast.Call):
                # 查找被调用的函数或类
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    # 在函数定义中查找（排除嵌套函数）
                    if func_name in self.function_defs:
                        called_defs.add(self.function_defs[func_name])
                    # 在类定义中查找
                    if func_name in self.class_defs:
                        called_defs.add(self.class_defs[func_name])

                # 处理属性调用（如obj.method()）
                elif isinstance(node.func, ast.Attribute):
                    # 对于属性调用，我们可能需要查找类定义
                    if (isinstance(node.func.value, ast.Name) and
                            node.func.value.id in self.class_defs):
                        called_defs.add(self.class_defs[node.func.value.id])

        return called_defs

    def _remove_duplicate_definitions(self, definitions: Set[ast.AST]) -> Set[ast.AST]:
        """
        去除重复的定义节点
        Args:
            definitions: 定义节点集合
        Returns:
            去重后的定义节点集合
        """
        # 使用名称和源代码作为唯一标识符
        unique_defs = {}

        for def_node in definitions:
            if isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # 获取定义的名称
                name = def_node.name

                # 尝试获取源代码作为唯一标识符
                try:
                    code = ast.unparse(def_node)
                except:
                    code = str(def_node.lineno) if hasattr(def_node, 'lineno') else str(id(def_node))

                # 创建唯一键
                key = f"{name}_{hash(code)}"

                # 如果这个键已经存在，选择更完整的定义（行数更多的）
                if key in unique_defs:
                    existing_node = unique_defs[key]
                    existing_lines = self._count_lines(existing_node)
                    current_lines = self._count_lines(def_node)

                    # 选择行数更多的定义（假设更完整）
                    if current_lines > existing_lines:
                        unique_defs[key] = def_node
                else:
                    unique_defs[key] = def_node
            else:
                # 对于非定义节点，直接添加（使用对象ID作为键）
                key = f"other_{id(def_node)}"
                unique_defs[key] = def_node

        return set(unique_defs.values())

    def _count_lines(self, node: ast.AST) -> int:
        """
        计算AST节点对应的代码行数
        Args:
            node: AST节点
        Returns:
            代码行数
        """
        if hasattr(node, 'end_lineno') and hasattr(node, 'lineno'):
            return node.end_lineno - node.lineno + 1
        elif hasattr(node, 'lineno'):
            # 如果没有结束行号，估计为1行
            return 1
        else:
            return 0

    def _unparse_with_line_numbers(self, node: ast.AST) -> str:
        """
        从AST节点提取代码，并标注原始源文件行号前缀
        格式: "  N: code_text" (类似 cat -n)
        Args:
            node: AST节点
        Returns:
            带行号前缀的代码字符串
        """
        if not hasattr(node, 'lineno') or not hasattr(node, 'end_lineno'):
            return ast.unparse(node)

        start = node.lineno
        end = node.end_lineno

        if self.source_lines and 1 <= start <= len(self.source_lines):
            actual_end = min(end, len(self.source_lines))

            # 去除注释行
            stripped_lines = self._strip_comments_from_sourcelines(self.source_lines)
            valid_lines = self._reconstruct_lines_without_comments(
                self.source_lines, stripped_lines, start, actual_end)

            if not valid_lines:
                return ''  # 所有行都是注释

            # 计算行号宽度用于右对齐
            max_lineno = max(ln for ln, _ in valid_lines)
            width = len(str(max_lineno))

            result_lines = []
            for line_num, text in valid_lines:
                result_lines.append(f"{line_num:>{width}}: {text}")

            return '\n'.join(result_lines)

        # Fallback: 无法从源文件提取时使用 ast.unparse
        return ast.unparse(node)

    def _strip_comments_from_sourcelines(self, lines: list) -> list:
        """
        从源代码行列表中移除注释行和文档字符串行
        处理规则：
        1. 整行注释（strip后以#开头）→ 移除整行
        2. 行内注释（#前有空格且不在字符串内）→ 保留代码部分，移除#及之后内容
        3. 文档字符串（三引号块）→ 移除整个块
        Args:
            lines: 原始源代码行列表（每行含换行符）
        Returns:
            处理后的列表，被移除的整行替换为None，行内注释被截断的替换为截断后文本
        """
        result = list(lines)  # 浅拷贝
        in_triple_quote = None  # 当前处于的三引号类型: None, '"""', "'''"

        i = 0
        while i < len(result):
            line = result[i]

            if in_triple_quote:
                # 在三引号块内，检查是否有结束引号
                end_idx = line.find(in_triple_quote)
                if end_idx != -1:
                    # 找到结束引号，移除包含结束引号的行
                    result[i] = None
                    in_triple_quote = None
                else:
                    # 仍在三引号块内
                    result[i] = None
                i += 1
                continue

            # 不在三引号块内
            stripped = line.strip()

            # 跳过空行（保留）
            if not stripped:
                i += 1
                continue

            # 检查整行注释
            if stripped.startswith('#'):
                result[i] = None
                i += 1
                continue

            # 检查三引号文档字符串开始
            # 只处理整行以三引号开头的情况（docstring或独立多行字符串）
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    # 检查是否在同一行结束
                    count = stripped.count(quote)
                    if count >= 2 and stripped.endswith(quote):
                        # 单行文档字符串: """xxx""" 或 '''xxx'''
                        result[i] = None
                    else:
                        # 多行文档字符串开始
                        result[i] = None
                        in_triple_quote = quote
                    break
            else:
                # 不是文档字符串，检查行内注释
                # 简单策略：找到第一个不在字符串内的 #
                # 保守处理：只移除 # 前有空格的行内注释
                in_line_comment_pos = self._find_inline_comment_pos(stripped)
                if in_line_comment_pos is not None:
                    # 截断行内注释，保留代码部分
                    # 保持原始缩进
                    code_part = line[:line.index('#', in_line_comment_pos)].rstrip()
                    result[i] = code_part + '\n' if line.endswith('\n') else code_part

            i += 1

        return result

    def _find_inline_comment_pos(self, line: str):
        """
        在代码行中找到行内注释的#位置（保守策略：#前面至少有一个空格）
        避免误切字符串内的#（如URL中的#）
        Returns:
            #在stripped行中的位置，或None
        """
        in_string = None  # None, '"', "'"
        escape = False
        j = 0
        while j < len(line):
            ch = line[j]

            if escape:
                escape = False
                j += 1
                continue

            if ch == '\\':
                escape = True
                j += 1
                continue

            if in_string:
                if ch == in_string:
                    in_string = None
                j += 1
                continue

            if ch in ('"', "'"):
                # 检查是否是三引号
                if line[j:j+3] in ('"""', "'''"):
                    return None  # 三引号开头的行由外部处理
                in_string = ch
                j += 1
                continue

            if ch == '#':
                # 检查#前面是否有空格（保守策略）
                if j > 0 and line[j-1] == ' ':
                    return j
                # #在行首（经过strip后）说明是整行注释，已在外部处理
                # #紧跟在其他字符后（如dict_key#comment），保守不移除
                return None

            j += 1

        return None

    def _reconstruct_lines_without_comments(self, original_lines: list, stripped_lines: list,
                                             start: int, end: int) -> list:
        """
        从已去除注释的行列表中重建有效行
        Args:
            original_lines: 原始源代码行列表
            stripped_lines: 经过_strip_comments_from_sourcelines处理的列表
                            None表示整行移除，字符串表示截断行内注释后的文本，其他为原始行
            start: 起始行号（1-based）
            end: 结束行号（1-based）
        Returns:
            (line_num, line_text) 元组列表
        """
        result = []
        for i in range(start - 1, min(end, len(stripped_lines))):
            if stripped_lines[i] is None:
                continue
            line_num = i + 1
            # 使用处理后的行（可能是截断了行内注释的版本，或原始行）
            text = stripped_lines[i].rstrip('\n').rstrip('\r')
            result.append((line_num, text))
        return result

    def _find_method_in_class(self, class_def: ast.ClassDef, method_name: str) -> Optional[ast.AST]:
        """在类定义中查找指定方法"""
        for node in class_def.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name:
                return node
        return None

    def _extract_self_attributes(self, method_node: ast.AST) -> Set[str]:
        """提取方法中通过 self.xxx 访问的属性名"""
        attrs = set()
        for node in ast.walk(method_node):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'self':
                attrs.add(node.attr)
        return attrs

    def _get_crypto_related_methods(self, class_def: ast.ClassDef, usages: List[ast.AST], crypto_imported_names: Set[str]) -> Set[str]:
        """
        获取类中与密码API相关的方法名集合
        Args:
            class_def: 类定义AST节点
            usages: 密码API使用点列表
            crypto_imported_names: 密码相关标识符集合
        Returns:
            需要保留的方法名集合
        """
        kept_methods = set()

        # 第一步：找到直接包含密码API使用点的方法
        for method in class_def.body:
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                has_usage = False
                for usage in usages:
                    # 检查usage节点是否在此方法的行号范围内
                    if (hasattr(usage, 'lineno') and hasattr(method, 'lineno') and
                            hasattr(method, 'end_lineno') and
                            method.lineno <= usage.lineno <= method.end_lineno):
                        has_usage = True
                        break
                if has_usage:
                    kept_methods.add(method.name)

        # 第二步：通过标识符检查（补充：密码模块属性访问）
        for method in class_def.body:
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if method.name in kept_methods:
                    continue
                for node in ast.walk(method):
                    if isinstance(node, ast.Name) and node.id in crypto_imported_names:
                        kept_methods.add(method.name)
                        break
                    if isinstance(node, ast.Attribute):
                        if isinstance(node.value, ast.Name) and node.value.id in crypto_imported_names:
                            kept_methods.add(method.name)
                            break

        # 第三步：正向扩展类内调用链（kept方法调用了哪些其他方法）
        # 只做正向扩展：如果kept方法内部调用了另一个方法，则该方法也需要保留
        # 不做反向扩展：调用kept方法的方法不一定是密码相关的
        # 原因：parse_number使用re → arrange_for_graph调用parse_number →
        #       arrange_for_graph又调用几十个方法，反向扩展会导致几乎所有方法都被保留
        changed = True
        while changed:
            changed = False
            for method in class_def.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if method.name not in kept_methods:
                        continue
                    # 已保留的方法调用了哪些类内方法 → 也需要保留
                    for node in ast.walk(method):
                        if isinstance(node, ast.Call):
                            called_name = None
                            if isinstance(node.func, ast.Name):
                                called_name = node.func.id
                            elif (isinstance(node.func, ast.Attribute) and
                                  isinstance(node.func.value, ast.Name) and
                                  node.func.value.id == 'self'):
                                called_name = node.func.attr
                            if called_name and called_name not in kept_methods:
                                # 检查被调用的方法是否在此类中
                                if any(m.name == called_name for m in class_def.body
                                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))):
                                    kept_methods.add(called_name)
                                    changed = True

        # 第四步：条件保留 __init__
        # 如果保留了方法且 __init__ 中设置了被保留方法使用的 self 属性，则保留 __init__
        if kept_methods and '__init__' not in kept_methods:
            has_init = any(m.name == '__init__' for m in class_def.body
                          if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)))
            if has_init:
                init_method = self._find_method_in_class(class_def, '__init__')
                if init_method:
                    init_setter_attrs = set()
                    for node in ast.walk(init_method):
                        # __init__ 中通过 self.xxx = ... 赋值设置的属性
                        if isinstance(node, ast.Attribute):
                            if (isinstance(node.value, ast.Name) and node.value.id == 'self' and
                                    isinstance(node.ctx, ast.Store)):
                                init_setter_attrs.add(node.attr)
                    for kept_name in list(kept_methods):
                        kept_method = self._find_method_in_class(class_def, kept_name)
                        if kept_method:
                            method_user_attrs = self._extract_self_attributes(kept_method)
                            if init_setter_attrs & method_user_attrs:
                                kept_methods.add('__init__')
                                break

        # 第五步：跨作用域属性依赖 — 保留被类外部代码访问的 __init__ 属性
        # 场景1：模块级代码中 BaseRunner(argument) -> runner_object.argument
        #         __init__ 设置 self.argument，外部通过实例访问，参数传递链路不能断
        # 场景2：PickleKlass(os.system) -> __init__ 将 os.system 存入 self.argument
        #         __reduce__ 返回 self.argument，密码相关数据通过字段流经类
        if '__init__' not in kept_methods and self.ast_tree is not None:
            has_init = any(m.name == '__init__' for m in class_def.body
                          if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)))
            if has_init:
                # 1. 查找类外部代码中该类的实例变量名
                instance_var_names = set()
                for node in ast.walk(self.ast_tree):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if isinstance(node.value, ast.Call):
                                    if isinstance(node.value.func, ast.Name) and node.value.func.id == class_def.name:
                                        instance_var_names.add(target.id)

                # 2. 找到 __init__ 中设置的 self 属性
                init_method = self._find_method_in_class(class_def, '__init__')
                if init_method:
                    init_setter_attrs = set()
                    for node in ast.walk(init_method):
                        if isinstance(node, ast.Attribute):
                            if (isinstance(node.value, ast.Name) and node.value.id == 'self' and
                                    isinstance(node.ctx, ast.Store)):
                                init_setter_attrs.add(node.attr)

                    should_keep_init = False

                    # 场景1：外部代码通过实例变量访问属性
                    if instance_var_names:
                        accessed_ext_attrs = set()
                        for node in ast.walk(self.ast_tree):
                            if isinstance(node, ast.Attribute):
                                if (isinstance(node.value, ast.Name) and
                                        node.value.id in instance_var_names and
                                        isinstance(node.ctx, ast.Load)):
                                    accessed_ext_attrs.add(node.attr)
                        if init_setter_attrs & accessed_ext_attrs:
                            should_keep_init = True

                    # 场景2：实例化参数中包含密码相关标识符
                    # 如 PickleKlass(os.system)，os.system 通过 __init__ 传入并存储在 self 属性中
                    if not should_keep_init:
                        for node in ast.walk(self.ast_tree):
                            if isinstance(node, ast.Call):
                                if isinstance(node.func, ast.Name) and node.func.id == class_def.name:
                                    # 检查实例化参数中是否包含密码相关标识符
                                    for arg in node.args:
                                        for n in ast.walk(arg):
                                            if isinstance(n, ast.Name) and n.id in crypto_imported_names:
                                                should_keep_init = True
                                                break
                                            if isinstance(n, ast.Attribute):
                                                if isinstance(n.value, ast.Name) and n.value.id in crypto_imported_names:
                                                    should_keep_init = True
                                                    break
                                        if should_keep_init:
                                            break
                                if should_keep_init:
                                    break

                    if should_keep_init:
                        kept_methods.add('__init__')

                        # 场景2扩展：保留使用密码相关 self 属性的其他方法
                        # 如 __reduce__ 返回 self.argument，self.argument 存储了密码数据
                        crypto_related_self_attrs = set()
                        # 找 __init__ 的参数名到 self 属性的映射
                        for node in ast.walk(init_method):
                            if isinstance(node, ast.Assign):
                                # self.xxx = param 形式
                                if (len(node.targets) == 1 and
                                    isinstance(node.targets[0], ast.Attribute) and
                                    isinstance(node.targets[0].value, ast.Name) and
                                    node.targets[0].value.id == 'self' and
                                    isinstance(node.targets[0].ctx, ast.Store)):
                                    attr_name = node.targets[0].attr
                                    # 检查赋值右值是否使用了 __init__ 参数中含密码标识符的参数
                                    for n in ast.walk(node.value):
                                        if isinstance(n, ast.Name) and n.id in crypto_imported_names:
                                            crypto_related_self_attrs.add(attr_name)
                                            break
                                        if isinstance(n, ast.Attribute):
                                            if isinstance(n.value, ast.Name) and n.value.id in crypto_imported_names:
                                                crypto_related_self_attrs.add(attr_name)
                                                break

                        # 保留使用了这些密码相关 self 属性的方法
                        if crypto_related_self_attrs:
                            for method in class_def.body:
                                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                    if method.name in kept_methods:
                                        continue
                                    method_attrs = self._extract_self_attributes(method)
                                    if crypto_related_self_attrs & method_attrs:
                                        kept_methods.add(method.name)

        return kept_methods

    def _unparse_class_with_pruning(self, class_def: ast.ClassDef, kept_methods: Set[str]) -> str:
        """
        剪枝类定义，只保留相关方法和类级语句
        Args:
            class_def: 类定义AST节点
            kept_methods: 需要保留的方法名集合
        Returns:
            剪枝后的带行号前缀的类代码字符串
        """
        if not self.source_lines:
            return ast.unparse(class_def)

        # 收集需要保留的行号范围 [(start, end), ...]
        kept_line_ranges = []

        # 类头部：class 定义行本身（含装饰器）
        class_header_start = class_def.lineno
        if hasattr(class_def, 'decorator_list') and class_def.decorator_list:
            for dec in class_def.decorator_list:
                if hasattr(dec, 'lineno'):
                    class_header_start = min(class_header_start, dec.lineno)
        kept_line_ranges.append((class_header_start, class_def.lineno))

        # 收集 kept 方法中使用的所有名称，用于判断类级属性是否需要保留
        kept_method_used_names = set()
        for item in class_def.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in kept_methods:
                for node in ast.walk(item):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                        kept_method_used_names.add(node.id)

        # 非方法的类体项目：只保留被kept方法使用的类级属性
        for item in class_def.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(item, 'lineno') and hasattr(item, 'end_lineno'):
                    # 类级 pass 语句始终保留
                    if isinstance(item, ast.Pass):
                        kept_line_ranges.append((item.lineno, item.end_lineno))
                        continue
                    # 检查类级属性是否被kept方法使用
                    attr_used = False
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name) and target.id in kept_method_used_names:
                                attr_used = True
                                break
                    elif isinstance(item, ast.AnnAssign):
                        if isinstance(item.target, ast.Name) and item.target.id in kept_method_used_names:
                            attr_used = True
                    # 对于其他非赋值语句（如 Expr, If 等），检查是否包含 kept 方法使用的名称
                    if not attr_used and not isinstance(item, (ast.Assign, ast.AnnAssign, ast.Pass)):
                        for node in ast.walk(item):
                            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in kept_method_used_names:
                                attr_used = True
                                break
                    if attr_used:
                        kept_line_ranges.append((item.lineno, item.end_lineno))

        # 保留的方法的行范围
        for item in class_def.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in kept_methods:
                    start = item.lineno
                    if item.decorator_list:
                        for dec in item.decorator_list:
                            if hasattr(dec, 'lineno'):
                                start = min(start, dec.lineno)
                    kept_line_ranges.append((start, item.end_lineno))

        # 按行号排序
        kept_line_ranges.sort()

        # 从原始源文件提取保留的行
        max_lineno = len(self.source_lines)
        if not kept_line_ranges:
            return ast.unparse(class_def)

        # 去除注释行
        stripped_comment_lines = self._strip_comments_from_sourcelines(self.source_lines)

        all_valid_lines = []
        for start, end in kept_line_ranges:
            actual_start = max(1, start)
            actual_end = min(end, max_lineno)
            valid_lines = self._reconstruct_lines_without_comments(
                self.source_lines, stripped_comment_lines, actual_start, actual_end)
            all_valid_lines.extend(valid_lines)

        if not all_valid_lines:
            return ''

        max_ln = max(ln for ln, _ in all_valid_lines)
        width = len(str(max_ln))

        result_lines = []
        for line_num, text in all_valid_lines:
            result_lines.append(f"{line_num:>{width}}: {text}")

        return '\n'.join(result_lines)

    def _is_crypto_related_instantiation(self, instantiation: ast.Call) -> bool:
        """
        检查类实例化的参数中是否包含密码API相关标识符
        仅检查参数，上下文检查在调用方通过crypto_context_names处理
        """
        def _check_expr_for_crypto(node):
            """递归检查表达式节点是否包含密码模块引用"""
            if isinstance(node, ast.Name):
                return self.is_crypto_module(node.id)
            elif isinstance(node, ast.Attribute):
                # 追溯到属性链的根，如 ssl._create_unverified_context() → ssl
                root = node
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name):
                    return self.is_crypto_module(root.id)
            elif isinstance(node, ast.Call):
                # 如 DES.new(key) 或 ssl._create_unverified_context()
                if isinstance(node.func, ast.Name):
                    if self.is_crypto_module(node.func.id):
                        return True
                elif isinstance(node.func, ast.Attribute):
                    if _check_expr_for_crypto(node.func):
                        return True
                # 也检查参数
                for arg in node.args:
                    if _check_expr_for_crypto(arg):
                        return True
                for kw in node.keywords:
                    if _check_expr_for_crypto(kw.value):
                        return True
            return False

        # 检查位置参数
        for arg in instantiation.args:
            if _check_expr_for_crypto(arg):
                return True

        # 检查关键字参数
        for kw in instantiation.keywords:
            if _check_expr_for_crypto(kw.value):
                return True

        return False

    def find_class_instantiations(self, ast_tree: ast.AST) -> List:
        """
        查找所有的类实例化
        Args:
            ast_tree: AST根节点
        Returns:
            类实例化的AST节点列表
        """
        instantiations = []
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                # 检查是否是类实例化
                if node.func.id in self.class_defs:
                    instantiations.append(node)
        return instantiations

    def _sort_class_definitions(self, class_defs: Dict[str, ast.ClassDef]) -> List[ast.ClassDef]:
        """
        根据类之间的依赖关系对类定义进行排序
        Args:
            class_defs: 类名到类定义的映射
        Returns:
            排序后的类定义列表
        """
        # 构建依赖图
        graph = {}
        for class_name, class_def in class_defs.items():
            dependencies = set()
            # 查找类定义中使用的其他类
            for node in ast.walk(class_def):
                if isinstance(node, ast.Name) and node.id in class_defs:
                    dependencies.add(node.id)
            graph[class_name] = dependencies

        # 拓扑排序
        sorted_classes = []
        visited = set()

        def visit(class_name):
            if class_name in visited:
                return
            visited.add(class_name)
            for dependency in graph[class_name]:
                if dependency in class_defs:
                    visit(dependency)
            sorted_classes.append(class_defs[class_name])

        for class_name in class_defs:
            if class_name not in visited:
                visit(class_name)

        return sorted_classes

    def sliced_files(self, input_dir: str, output_dir: str) -> List[str]:
        """
        批量处理文件夹中的Python文件
        Args:
            input_dir: 输入文件夹路径
            output_dir: 输出文件夹路径
        """
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 查找所有Python文件
        python_files = glob.glob(os.path.join(input_dir, "**", "*.py"), recursive=True)

        # print(f"Found {len(python_files)} Python files in {input_dir}")
        sliced_file = []
        # 处理每个文件
        for file_path in python_files:
            # print(f"\nProcessing file: {file_path}")

            # 提取切片
            slices = self.extract_complete_slice(file_path)

            if not slices:
                # print(f"No crypto slices found in {file_path}")
                continue

            # 生成输出文件名
            rel_path = os.path.relpath(file_path, input_dir)
            output_path = os.path.join(output_dir, rel_path)

            # 确保输出目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 写入切片结果
            with open(output_path, 'w', encoding='utf-8') as f:
                for i, slice_code in enumerate(slices, 1):
                    lines = slice_code.count('\n') + 1
                    f.write(f"# --- Slice {i} ({lines} lines) ---\n")
                    f.write(slice_code)
                    f.write("\n\n")
            sliced_file.append(output_path)

        return sliced_file


if __name__ == "__main__":
    # # 初始化切片器
    start_time = time.time()
    slicer = PyCryptoAPISlicer()
    # slices = slicer.extract_complete_slice('./py_slice_test_dbg/imp_filter.py')
    # print(slices)
    # input_dir = './filtered_output'  # 输入文件夹
    # input_dir = './py_slice_test_dbg'  # 输入文件夹
    # output_dir = "./output_filter2slice"  # 输出文件夹

    # input_dir = './Filtered_Python_Projects'  # 输入文件夹
    # output_dir = "./output_Projects-8"  # 输出文件夹

    input_dir = './PyCryptoBench'  # 输入文件夹
    output_dir = "./output_bench-5"  # 输出文件夹

    slice_files = slicer.sliced_files(input_dir, output_dir)
    elapsed = round(time.time() - start_time, 2)

    print((f"切片耗时: {elapsed}秒\n\n"))
    print(f"✅ Successfully sliced {len(slice_files)} file(s) containing Cryptographic API usage to {output_dir}.")

    # 当前程序切片版本与代码筛选实现了更好地对齐，新增支持动态导入和延迟导入。现在的问题主要是切片的提取还需要优化。
