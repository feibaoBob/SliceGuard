import ast
import os
import re
import shutil
import time
from typing import List, Set, Dict, Tuple, Any, Optional

# 统一密码模块知识库 - 合并模块识别和导出函数信息
Crypto_API_Base = {
    # 标准库模块
    'hashlib': {
        'type': 'standard',
        'exports': {
            'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'blake2b', 'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128', 'shake_256', 'new', 'algorithms_guaranteed', 'algorithms_available', 'pbkdf2_hmac'
        },
        'submodules': {}
    },
    'hmac': {
        'type': 'standard',
        'exports': {'HMAC', 'compare_digest', 'digest', 'digest_size', 'new', 'trans_36', 'trans_5C'},
        'submodules': {}
    },
    'ssl': {
        'type': 'standard',
        'exports': {
            'create_default_context', 'wrap_socket'
        },
        'submodules': {}
    },
    'http.client': {
        'type': 'standard',
        'exports': {'HTTPConnection',  'HTTPSConnection'},
        'submodules': {}
    },
    'urllib': {
        'type': 'standard',
        'exports': {'request'},
        'submodules': {
            'request': {
                'exports': {'urlopen', 'Request', 'build_opener', 'HTTPSHandler'},  # context参数可配置不安全SSL设置
            }
        }
    },
    'urllib3': {
        'type': 'third_party',
        'exports': {
            'PoolManager', 'HTTPSConnectionPool', 'disable_warnings'
        }  # PoolManager/HTTPSConnectionPool通过verify=False参数禁用证书验证
    },
    'requests': {
        'type': 'third_party',
        'exports': {
            'get', 'post', 'request', 'Session'
        },  # 支持verify=False参数禁用SSL验证
        'submodules': {}
    },
    'random': {
        'type': 'standard',
        'exports': {
            'Random', 'betavariate', 'choice', 'choices', 'expovariate', 'gammavariate', 'gauss', 'getrandbits', 'lognormvariate', 'normalvariate', 'paretovariate', 'randint', 'random', 'randrange', 'sample', 'seed', 'setstate', 'shuffle', 'triangular', 'uniform', 'vonmisesvariate', 'weibullvariate'
        },  # 伪随机数生成器，不可用于安全目的
        'submodules': {}
    },
    'xml': {
        'type': 'standard',
        'exports': {'dom', 'parsers', 'sax', 'etree'},
        'submodules': {
             'sax': {
                'exports': {'parse', 'parseString', 'make_parser'},
            }
        }
    },
    'lxml': {
        'type': 'standard',
        'exports': {'dom', 'parsers', 'sax', 'etree'},
        'submodules': {}
    },
    'yaml': {
        'type': 'third_party',
        'exports': {'load', 'load_all', 'loader', 'dump', 'dump_all', 'dumper'},
        'submodules': {}
    },
    'pickle': {
        'type': 'standard',
        'exports': {'load', 'loads', 'dump', 'dumps'},
        'submodules': {}
    },
    're': {
        'type': 'standard',
        'exports': {'match', 'search', 'findall', 'finditer', 'sub', 'compile', 'escape'},
        'submodules': {}
    },
    'hash': {
        'type': 'standard',
        'exports': {'md5', 'sha1', 'sha256'},
        'submodules': {}
    },

    # 第三方密码库
    'cryptography': {
        'type': 'third_party',
        'exports': {
            'fernet', 'hazmat', 'x509', 'exceptions', 'utils'
        },
        'submodules': {
            'hazmat.primitives.hashes': {
                'exports': {'Hash', 'SHA256', 'SHA512', 'MD5', 'SHA1', 'BLAKE2b', 'BLAKE2s'}
            },
            'hazmat.primitives.kdf': {
                'exports': {'PBKDF2HMAC', 'Scrypt', 'HKDF', 'ConcatKDFHash'}
            },
            'hazmat.primitives.asymmetric': {
                'exports': {'rsa', 'dsa', 'ec', 'dh', 'ed25519', 'ed448', 'x25519', 'x448'}
            },
            'hazmat.primitives.ciphers': {
                'exports': {'Cipher', 'algorithms', 'modes'},
                'submodules': {
                            'algorithms': {'exports': {'AES', 'ChaCha20', 'Camellia'}},
                            'modes': {'exports': {'CBC', 'CFB', 'ECB', 'GCM'}}
                            }
            }
        }
    },
    'Crypto': {
        'type': 'third_party',
        'exports': {'Cipher', 'Hash', 'Protocol', 'PublicKey', 'Random', 'Util'},
        'submodules': {
            'Cipher': {
                'exports': {'AES', 'DES', 'DES3', 'RSA', 'ARC4', 'PKCS1_v1_5', 'PKCS1_OAEP'}
            },
            'Hash': {
                'exports': {'SHA256', 'SHA512', 'MD5', 'SHA', 'SHA1', 'HMAC', 'MD2', 'MD4', 'RIPEMD'}
            },
            'Protocol': {
                'exports': {'KDF', 'SecretSharing', 'AllOrNothing'}
            },
            'PublicKey': {
                'exports': {'RSA', 'DSA', 'ElGamal', 'ECC', 'importKey', 'generate'}
            },
            'Random': {
                'exports': {'random', 'get_random_bytes', 'new'}
            }
        }
    },
    'bcrypt': {
        'type': 'third_party',
        'exports': {'hashpw', 'checkpw', 'gensalt', 'kdf'},
        'submodules': {}
    },
    'pycryptodome': {
        'type': 'third_party',
        'exports': {'Cipher', 'Hash', 'Protocol'},
        'submodules': {
            'Cipher': {
                'exports': {'AES', 'DES', 'DES3', 'ARC4'}
            },
            'Hash': {
                'exports': {'SHA256', 'SHA512', 'MD5', 'SHA1'}
            }
        }
    },
    'jwt': {
        'type': 'third_party',
        'exports': {'encode', 'decode', 'get_unverified_header'},
        'submodules': {}
    },
    'pyjwt': {
        'type': 'third_party',
        'exports': {'encode', 'decode', 'get_unverified_header'},
        'submodules': {}
    },
    'passlib': {
        'type': 'third_party',
        'exports': {'hash', 'context', 'CryptContext'},
        'submodules': {
            'hash': {
                'exports': {
                    'md5_crypt', 'sha1_crypt', 'sha256_crypt', 'sha512_crypt',
                    'bcrypt', 'pbkdf2_sha256', 'pbkdf2_sha512', 'argon2'
                }
            },
            'context': {
                'exports': {'CryptContext'}
            }
        }
    },
    'argon2': {
        'type': 'third_party',
        'exports': {'hash_password', 'verify_password', 'PasswordHasher'},
        'submodules': {}
    },
    'itsdangerous': {
        'type': 'third_party',
        'exports': {'Serializer', 'URLSafeSerializer', 'TimestampSigner', 'BadSignature'},
        'submodules': {}
    },
    'pynacl': {
        'type': 'third_party',
        'exports': {'secret', 'public', 'utils', 'encoding'},
        'submodules': {}
    },
    'fernet': {
        'type': 'third_party',
        'exports': {'Fernet', 'MultiFernet', 'InvalidToken'},
        'submodules': {}
    },
    'pycrypto': {
        'type': 'third_party',
        'exports': {'Cipher', 'Hash', 'PublicKey', 'Random'},
        'submodules': {}
    },
    'crypt': {
        'type': 'third_party',
        'exports': {'crypt', 'mksalt', 'METHOD_MD5', 'METHOD_SHA256', 'METHOD_SHA512'},
        'submodules': {}
    },
    'M2Crypto': {
        'type': 'third_party',
        'exports': {'RSA', 'DSA', 'X509', 'SSL', 'm2'},
        'submodules': {}
    },
    'pyopenssl': {
        'type': 'third_party',
        'exports': {'SSL', 'crypto', 'rand'},
        'submodules': {}
    },
    'paramiko': {
        'type': 'third_party',
        'exports': {
            'RSAKey', 'DSSKey', 'ECDSAKey', 'Ed25519Key', 'Transport',
            'SSHClient', 'AutoAddPolicy', 'MissingHostKeyPolicy'
        },
        'submodules': {}
    },
    'nacl': {
        'type': 'third_party',
        'exports': {'secret', 'public', 'signing', 'encoding', 'utils'},
        'submodules': {}
    },
    'keyring': {
        'type': 'third_party',
        'exports': {'get_password', 'set_password', 'delete_password', 'get_keyring'},
        'submodules': {}
    },
    'gnupg': {
        'type': 'third_party',
        'exports': {'GPG', 'encrypt', 'decrypt', 'sign', 'verify', 'list_keys'},
        'submodules': {}
    },
    'pygpgme': {
        'type': 'third_party',
        'exports': {'Context', 'encrypt', 'decrypt', 'sign', 'verify'},
        'submodules': {}
    },
    'pyscard': {
        'type': 'third_party',
        'exports': {'Smartcard', 'Service', 'Session'},
        'submodules': {}
    },
    'pycryptodomex': {
        'type': 'third_party',
        'exports': {'Cipher', 'Hash', 'Protocol', 'PublicKey'},
        'submodules': {}
    },
    'cffi': {
        'type': 'third_party',
        'exports': {'FFI', 'verifier', 'CData', 'CType'},
        'submodules': {}
    },
    'OpenSSL': {
        'type': 'third_party',
        'exports': {'SSL', 'crypto', 'rand', 'version'},
        'submodules': {}
    },
    'sshlib': {
        'type': 'third_party',
        'exports': {'SSHClient', 'Transport', 'RSAKey'},
        'submodules': {}
    },

    # 网络协议相关
    'ldap': {
        'type': 'third_party',
        'exports': {'initialize', 'SCOPE_BASE', 'SCOPE_ONELEVEL', 'SCOPE_SUBTREE'},
        'submodules': {}
    },
    'ldap3': {
        'type': 'third_party',
        'exports': {'Server', 'Connection', 'ALL', 'ALL_ATTRIBUTES'},
        'submodules': {}
    },
    'ftplib': {
        'type': 'standard',
        'exports': {'FTP', 'FTP_TLS'},
        'submodules': {}
    },
    'telnetlib': {
        'type': 'standard',
        'exports': {'Telnet', 'IAC', 'DO', 'DONT', 'WILL', 'WONT'},
        'submodules': {}
    },
    'smtplib': {
        'type': 'standard',
        'exports': {'SMTP', 'SMTP_SSL', 'LMTP'},
        'submodules': {}
    },
    'imaplib': {
        'type': 'standard',
        'exports': {'IMAP4', 'IMAP4_SSL'},
        'submodules': {}
    },
    'poplib': {
        'type': 'standard',
        'exports': {'POP3', 'POP3_SSL'},
        'submodules': {}
    },
    'aiohttp': {
        'type': 'third_party',
        'exports': {'ClientSession', 'get', 'post', 'TCPConnector'},
        'submodules': {}
    },
    'httpx': {
        'type': 'third_party',
        'exports': {'Client', 'get', 'post', 'AsyncClient'},
        'submodules': {}
    },

    # 其他
    'xml.etree.ElementTree': {
        'type': 'standard',
        'exports': {'Element', 'SubElement', 'parse', 'fromstring', 'tostring'},
        'submodules': {}
    },
    'xml.dom.minidom': {
        'type': 'standard',
        'exports': {'parse', 'parseString', 'getDOMImplementation'},
        'submodules': {}
    },
    'lxml.etree': {
        'type': 'third_party',
        'exports': {'Element', 'SubElement', 'parse', 'fromstring', 'tostring'},
        'submodules': {}
    },
    'werkzeug': {
        'type': 'third_party',
        'exports': {'security', 'generate_password_hash', 'check_password_hash'},
        'submodules': {}
    },
    'gmssl': {
        'type': 'third_party',
        'exports': {'sm2', 'sm3', 'sm4', 'sm9'},
        'submodules': {}
    },
    'pysmx': {
        'type': 'third_party',
        'exports': {'SM2', 'SM3', 'SM4'},
        'submodules': {}
    },
    'ecdsa': {
        'type': 'third_party',
        'exports': {'SigningKey', 'VerifyingKey'},
        'submodules': {}
    },
    'zlib': {
        'type': 'standard',
        'exports': {'compress', 'decompress', 'adler32', 'crc32'},
        'submodules': {}
    },
}


class PythonCryptoAPIFilter:
    def __init__(self):
        """
        密码API过滤器
        Args:
            crypto_api_modules: 密码API相关模块名称列表
        """
        self.crypto_api_modules = self._generate_module_list()

    def _generate_module_list(self) -> Set[str]:
        """从知识库生成模块名列表"""
        modules = set()

        for module_name, module_info in Crypto_API_Base.items():
            modules.add(module_name)
            # 添加所有子模块
            for submodule_name in module_info.get('submodules', {}).keys():
                full_submodule = f"{module_name}.{submodule_name}"
                modules.add(full_submodule)

        return modules

    def extract_imports(self, tree: ast.AST) -> Tuple[Dict[str, str], Dict[str, Set[str]], Set[str], Dict[str, str]]:
        """
        导入提取，返回增加通配符导入信息

        Returns:
            tuple: (模块名到别名的映射, 模块到导入对象的映射, 通配符导入的模块集合, 动态导入映射)
        """
        if tree is not None:
            module_aliases: Dict[str, str] = {}
            from_imports: Dict[str, Set[str]] = {}
            wildcard_modules: Set[str] = set()
            dynamic_imports: Dict[str, str] = {}

            # 为节点添加父节点引用（辅助属性）这一步很关键，没有就提取不到动态导入
            self._add_parent_refs(tree)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name
                        actual_name = alias.asname if alias.asname else module_name.split('.')[-1]
                        module_aliases[module_name] = actual_name
                        # 针对类似import http.client情况
                        top_level = module_name.split('.')[0]
                        if top_level not in module_aliases:
                            module_aliases[top_level] = top_level

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module_name = node.module

                        if module_name not in from_imports:  # 占位
                            from_imports[module_name] = set()

                        for alias in node.names:
                            if alias.name == '*':  # 处理通配符导入
                                wildcard_modules.add(module_name)
                                # 对于通配符导入，添加模块的所有可能导出函数
                                exports = self._get_module_exports(module_name)  # 对于密码API知识库中的模块会导出所有方法，通配符导入在这里其实完成了筛选
                                if exports:
                                    from_imports[module_name].update(exports)
                            else:
                                imported_name = alias.name
                                actual_name = alias.asname if alias.asname else imported_name
                                from_imports[module_name].add(actual_name)

                # 检测动态导入
                elif isinstance(node, ast.Call):
                    dynamic_info = self._extract_dynamic_import(node)
                    if dynamic_info:
                        var_name, module_name = dynamic_info
                        dynamic_imports[var_name] = module_name

                # 检测赋值中的动态导入
                elif isinstance(node, ast.Assign):
                    self._check_assignment_for_dynamic_import(node, dynamic_imports)

            return module_aliases, from_imports, wildcard_modules, dynamic_imports

        else:
            return {}, {}, set(), {}

    def _add_parent_refs(self, tree: ast.AST) -> None:
        """为AST节点添加父节点引用"""
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child.parent = parent  # type: ignore

    def _extract_dynamic_import(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """优化版动态导入提取，支持更多模式"""
        try:
            # __import__
            if isinstance(node.func, ast.Name) and node.func.id == '__import__':
                if node.args and isinstance(node.args[0], ast.Constant):
                    module_name = node.args[0].value  # type: ignore
                    return self._get_variable_from_context(node, str(module_name))

            # importlib.import_module
            elif isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module':
                if node.args and isinstance(node.args[0], ast.Constant):
                    module_name = node.args[0].value  # type: ignore
                    return self._get_variable_from_context(node, str(module_name))

            # exec/eval动态导入
            elif isinstance(node.func, ast.Name) and node.func.id in ('exec', 'eval'):
                if node.args and isinstance(node.args[0], ast.Constant):
                    code_str = node.args[0].value  # type: ignore
                    # 在代码字符串中查找导入
                    import_match = re.search(r'(?:import|from)\s+([\w.]+)', str(code_str))
                    if import_match:
                        module_name = import_match.group(1)
                        return self._get_variable_from_context(node, module_name)

        except Exception as e:
            print(f"提取动态导入时出错: {e}")

        return None

    def _get_variable_from_context(self, node: ast.Call, module_name: str) -> Optional[Tuple[str, str]]:
        """从上下文获取变量名"""
        # 查找赋值语句
        parent = getattr(node, 'parent', None)
        while parent:
            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        return str(module_name), target.id
                    elif isinstance(target, ast.Tuple):
                        # 处理多重赋值
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                return str(module_name), elt.id
            parent = getattr(parent, 'parent', None)  # type: ignore

        return None

    def _check_assignment_for_dynamic_import(self, node: ast.Assign, dynamic_imports: Dict[str, str]) -> None:
        """检查赋值语句中的动态导入"""
        # 检查右侧是否是调用
        if isinstance(node.value, ast.Call):
            dynamic_info = self._extract_dynamic_import(node.value)
            if dynamic_info:
                var_name, module_name = dynamic_info
                dynamic_imports[var_name] = module_name

    def _get_module_exports(self, module_name: str) -> Set[str]:
        """从统一知识库获取模块的导出函数列表"""
        # 直接匹配
        if module_name in Crypto_API_Base:
            module_info = Crypto_API_Base[module_name]
            exports = module_info.get('exports', set())
            if exports:
                return exports

            # 如果是包，收集所有子模块的导出
            all_exports = set()
            for submodule_info in module_info.get('submodules', {}).values():
                sub_exports = submodule_info.get('exports', set())
                all_exports.update(sub_exports)
            return all_exports

        # 子模块匹配
        parts = module_name.split('.')
        for i in range(1, len(parts)):
            parent_module = '.'.join(parts[:i])
            if parent_module in Crypto_API_Base:
                module_info = Crypto_API_Base[parent_module]
                submodules = module_info.get('submodules', {})
                submodule = '.'.join(parts[i:])

                for submodule_name, submodule_info in submodules.items():
                    if submodule == submodule_name or submodule.startswith(submodule_name + '.'):
                        return submodule_info.get('exports', set())

        return set()

    def is_crypto_module(self, module_name: str) -> bool:
        """检查模块名是否为密码API模块"""
        if module_name in self.crypto_api_modules:
            return True

        # 只检查顶层包名，避免 homeassistant.util.yaml 等路径中
        # 碰巧包含密码模块名而被误判
        top_level = module_name.split('.')[0]
        if top_level in self.crypto_api_modules:
            return True

        return False

    def _is_name_in_definition(self, line: str, name: str) -> bool:
        """
        检查名称是否出现在函数/类定义中
        """
        # 检查是否是函数定义
        if re.match(r'def\s+\w+', line):
            # 提取函数名
            match = re.match(r'def\s+(\w+)', line)
            if match and match.group(1) == name:
                return True

        # 检查是否是类定义
        if re.match(r'class\s+\w+', line):
            # 提取类名
            match = re.match(r'class\s+(\w+)', line)
            if match and match.group(1) == name:
                return True

        # 检查是否是变量定义（如 x = ...）
        if re.match(r'\w+\s*=', line):
            # 提取变量名
            match = re.match(r'(\w+)\s*=', line)
            if match and match.group(1) == name:
                return True

        return False

    def check_module_usage(self, content: str, module_aliases: Dict[str, str], from_imports: Dict[str, Set[str]], wildcard_modules: Set[str], dynamic_imports: Dict[str, str]) -> bool:
        """
        增强版模块使用检测 - 修复：简化并专注于关键检测点
        """
        try:
            tree = ast.parse(content)

            # 创建密码模块相关的导入名称集合
            crypto_imported_names = set()

            # 筛选出密码模块相关的导入
            for module_name, alias in module_aliases.items():
                if self.is_crypto_module(module_name):
                    crypto_imported_names.add(module_name)
                    crypto_imported_names.add(alias)

            for module_name, imports in from_imports.items():
                if self.is_crypto_module(module_name):
                    crypto_imported_names.update(imports)

            for module_name, alias in dynamic_imports.items():
                if self.is_crypto_module(module_name):
                    crypto_imported_names.add(alias)

            # 如果有通配符导入的密码模块，需要特殊处理
            crypto_wildcard_modules = {mod for mod in wildcard_modules if self.is_crypto_module(mod)}
            wildcard_functions = set()
            if crypto_wildcard_modules:
                for module in crypto_wildcard_modules:
                    exports = self._get_module_exports(module)
                    wildcard_functions.update(exports)

            # 添加通配符导入的函数到密码模块相关的导入名称集合
            crypto_imported_names.update(wildcard_functions if 'wildcard_functions' in locals() else set())

            # 如果没有密码相关的导入，直接返回False
            if not crypto_imported_names:
                return False

            # 检查模块使用情况
            for node in ast.walk(tree):
                # 跳过导入语句本身
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue

                # print('Node:', ast.dump(node))
                for crypto_imported_name in crypto_imported_names:
                    if crypto_imported_name in ast.dump(node):
                        # 1. 检查函数调用
                        if isinstance(node, ast.Call):
                            # 直接检查调用本身
                            if self._check_call_usage(node, crypto_imported_names):
                                # print("函数调用")
                                return True

                        # 2. 检查属性访问
                        if isinstance(node, ast.Attribute):
                            if self._check_attribute_usage(node, crypto_imported_names):
                                # print("属性访问")
                                return True

                        # 3. 检查名称引用
                        if isinstance(node, ast.Name):
                            if self._check_name_usage(node, crypto_imported_names):
                                # print("名称引用")
                                return True

                        # 4. 检查赋值语句
                        if isinstance(node, ast.Assign):
                            if self._check_assign_usage(node, crypto_imported_names, tree):
                                # print("赋值语句")
                                return True

            return False

        except (SyntaxError, UnicodeDecodeError, Exception) as e:
            return False

    def _check_call_usage(self, node: ast.Call, imported_names: Set[str]) -> bool:
        """增强版函数调用检查 - 修复：直接检查参数中的模块使用"""
        # 检查直接调用：function() - 来自from imports
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            # 检查是否是导入的函数
            if func_name in imported_names:
                return True

        # 检查方法调用：module.function() 或 object.method()
        elif isinstance(node.func, ast.Attribute):
            # 检查 module.function 模式
            if isinstance(node.func.value, ast.Name):
                module_or_obj_name = node.func.value.id
                # 检查是否是导入的模块或对象
                if module_or_obj_name in imported_names:
                    return True

            # elif isinstance(node.func.value, ast.Call):
            #     if self._check_call_usage(node.func.value, imported_names):
            #         return True


        # 关键修复：检查函数调用的参数中是否包含密码模块
        # 这是检测跨过程调用的核心
        for arg in node.args:
            if isinstance(arg, ast.Name):
                # 如果参数是导入的模块名
                if arg.id in imported_names:
                    return True
            # 递归检查复杂表达式参数
            elif hasattr(arg, '_fields'):
                if self._check_expression_usage(arg, imported_names):
                    return True

        # 检查关键字参数的值
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Name):
                if keyword.value.id in imported_names:
                    return True
            elif hasattr(keyword.value, '_fields'):
                if self._check_expression_usage(keyword.value, imported_names):
                    return True

        return False

    def _check_assign_usage(self, node: ast.Assign, imported_names: Set[str], tree: ast.AST) -> bool:
        """检查赋值语句中的模块使用 - 修复：增强跨过程调用检测"""
        # 检查右侧是否包含模块使用
        for target in node.targets:
            if isinstance(target, ast.Name):
                # 检查是否将模块函数赋值给变量
                if isinstance(node.value, ast.Name):
                    if node.value.id in imported_names:
                        return True
                elif isinstance(node.value, ast.Attribute):
                    if self._check_attribute_usage(node.value, imported_names):
                        return True
                elif isinstance(node.value, ast.Call):
                    if self._check_call_usage(node.value, imported_names):
                        return True

        # 修复：使用tree参数进行更精确的上下文分析
        # 检查赋值语句是否在函数/类定义中，这可能影响使用判断
        if tree is not None:
            # 获取当前节点的父节点上下文
            for parent in ast.walk(tree):
                body = getattr(parent, 'body', None)
                if isinstance(body, (list, tuple)) and node in body:
                    # 如果赋值在函数/类定义中，可能需要更严格的检查
                    if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                        # 检查是否将密码函数赋值给局部变量
                        if (isinstance(node.value, ast.Name) and
                                node.value.id in imported_names):
                            return True
                    break

        return False

    def _check_attribute_usage(self, node: ast.Attribute, imported_names: Set[str]) -> bool:
        """增强版属性访问检查 - 修复：使用所有参数进行完整检查"""
        if isinstance(node.value, ast.Name):
            module_or_obj_name = node.value.id

            # 检查是否是导入的模块或对象
            if module_or_obj_name in imported_names:
                return True

        # 处理嵌套属性访问：obj.attr.subattr
        current = node
        while isinstance(current, ast.Attribute):
            if isinstance(current.value, ast.Name):
                name = current.value.id
                if name in imported_names:
                    return True
            current = current.value

        return False

    def _check_name_usage(self, node: ast.Name, imported_names: Set[str]) -> bool:
        """增强版名称引用检查 - 修复：排除赋值目标(Store上下文)，只统计实际使用(Load上下文)"""
        # 检查名称是否可能是模块或导入的函数/类
        name = node.id
        if name in imported_names:
            # 排除赋值目标（Store上下文），只有Load上下文才是实际使用
            # 例如 foo = __import__('hashlib') 中 foo 是 Store，不应算作使用
            if isinstance(node.ctx, ast.Store):
                return False
            # 排除导入语句中的名称
            if not self._is_name_in_import_statement(node):
                return True

        return False

    def _check_compare_usage(self, node: ast.Compare, imported_names: Set[str]) -> bool:
        """检查比较操作中的模块使用"""
        # 检查左操作数
        if self._check_expression_usage(node.left, imported_names):
            return True

        # 检查比较操作符和右操作数
        for comparator in node.comparators:
            if self._check_expression_usage(comparator, imported_names):
                return True

        return False

    def _check_expression_usage(self, node: Any, imported_names: Set[str]) -> bool:
        """通用表达式使用检查"""
        if isinstance(node, ast.Call):
            return self._check_call_usage(node, imported_names)
        elif isinstance(node, ast.Attribute):
            return self._check_attribute_usage(node, imported_names)
        elif isinstance(node, ast.Name):
            return self._check_name_usage(node, imported_names)
        elif isinstance(node, ast.Assign):
            return self._check_assign_usage(node, imported_names, None)
        elif isinstance(node, ast.Compare):
            return self._check_compare_usage(node, imported_names)
        return False

    def _is_name_in_import_statement(self, name_node: ast.Name) -> bool:
        """检查名称是否在导入语句中 - 修复：使用name_node参数进行实际检查"""
        if not hasattr(name_node, 'lineno') or not hasattr(name_node, 'col_offset'):
            return False

        try:
            # 获取节点的行号
            line_no = name_node.lineno

            # 如果行号较小（假设导入在前30行），可能是导入语句
            if line_no <= 30:
                # 检查名称是否看起来像模块名或标准导入
                name = name_node.id
                if (name in self.crypto_api_modules or
                        any(name in imports for imports in self._get_all_module_exports().values())):
                    return True

            # 检查父节点是否为导入相关节点
            parent = getattr(name_node, 'parent', None)
            while parent is not None:
                if isinstance(parent, (ast.Import, ast.ImportFrom)):
                    return True
                parent = getattr(parent, 'parent', None)

        except (AttributeError, Exception):
            # 如果检查过程中出错，保守返回False
            pass

        return False

    def _get_all_module_exports(self) -> Dict[str, Set[str]]:
        """获取所有模块的导出函数"""
        all_exports = {}
        for module_name, module_info in Crypto_API_Base.items():
            exports = module_info.get('exports', set())
            if exports:
                all_exports[module_name] = exports
            # 包含子模块的导出
            for submodule_name, submodule_info in module_info.get('submodules', {}).items():
                sub_exports = submodule_info.get('exports', set())
                if sub_exports:
                    full_name = f"{module_name}.{submodule_name}"
                    all_exports[full_name] = sub_exports
        return all_exports

    def filter_files(self, directory: str) -> List[str]:
        """筛选包含密码API使用的代码文件"""
        result_files = []

        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)

                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    try:
                        tree = ast.parse(content)
                    except (SyntaxError, UnicodeDecodeError, Exception) as e:
                        tree = None

                    # 提取导入信息（现在返回4个值）

                    module_aliases, from_imports, wildcard_modules, dynamic_imports = self.extract_imports(tree)

                    # 检查是否导入了密码API相关模块
                    imported_crypto_modules = set()

                    # 1. 先检查通配符导入（最高优先级）
                    for module_name in wildcard_modules:
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    # 2. 检查直接导入的模块
                    for module_name, alias in module_aliases.items():
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    # 3. 检查from imports的模块
                    for module_name in from_imports.keys():
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    # 4. 检查dynamic_imports的模块
                    for module_name, alias in dynamic_imports.items():
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    # 如果导入了密码API模块，检查是否被使用
                    if imported_crypto_modules != set():
                        is_used = self.check_module_usage(content, module_aliases, from_imports, wildcard_modules, dynamic_imports)
                        if is_used:
                            result_files.append(file_path)

        return result_files

    def copy_filtered_files(self, source_directory: str, output_directory: str) -> List[str]:
        """
        筛选包含密码API使用的代码文件，并将它们复制到输出目录

        Args:
            source_directory: 源目录路径
            output_directory: 输出目录路径

        Returns:
            List[str]: 筛选出的文件路径列表
        """
        # 创建输出目录
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
            print(f"📁 创建输出目录: {output_directory}")

        # 获取筛选结果
        filtered_files = self.filter_files(source_directory)

        # 复制文件到输出目录
        copied_files = []
        for file_path in filtered_files:
            # 获取相对路径
            relative_path = os.path.relpath(file_path, source_directory)
            output_path = os.path.join(output_directory, relative_path)

            # 创建目标目录（如果不存在）
            output_dir = os.path.dirname(output_path)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            # 复制文件
            try:
                shutil.copy2(file_path, output_path)
                copied_files.append(output_path)
            except Exception as e:
                print(f"❌ 复制文件失败: {file_path} -> {output_path}, 错误: {e}")

        return copied_files

    def get_filter_statistics(self, directory: str) -> Dict[str, any]:
        """
        获取筛选统计信息

        Args:
            directory: 要扫描的目录路径

        Returns:
            Dict[str, any]: 统计信息字典
        """
        total_files = 0
        imported_files = 0
        used_files = 0
        file_details = []  # 存储每个文件的详细信息

        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    try:
                        tree = ast.parse(content)
                    except (SyntaxError, UnicodeDecodeError, Exception) as e:
                        tree = None

                    # 使用增强版的导入提取方法（现在返回4个值）
                    module_aliases, from_imports, wildcard_modules, dynamic_imports = self.extract_imports(tree)

                    # 检查是否导入了密码API相关模块
                    has_crypto_import = False
                    imported_crypto_modules = set()

                    # 1. 先检查通配符导入（最高优先级）
                    for module_name in wildcard_modules:
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)
                            # print(f"🎯 通过通配符导入发现密码模块: {module_name}")

                    # 2. 检查直接导入的模块
                    for module_name, alias in module_aliases.items():
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    # 3. 检查from imports的模块
                    for module_name in from_imports.keys():
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    # 4. 检查dynamic_imports的模块
                    for module_name, alias in dynamic_imports.items():
                        if self.is_crypto_module(module_name):
                            imported_crypto_modules.add(module_name)

                    if imported_crypto_modules != set():
                        has_crypto_import = True

                    if has_crypto_import:
                        imported_files += 1

                        # 使用增强版的使用检测方法（现在需要4个参数）
                        is_used = self.check_module_usage(content, module_aliases, from_imports, wildcard_modules, dynamic_imports)

                        if is_used:
                            used_files += 1

                        # 记录文件详细信息
                        file_details.append({
                            'file_path': file_path,
                            'imported_modules': list(imported_crypto_modules),
                            'is_used': is_used
                        })

        # 计算筛除率
        filtered_out_rate = (total_files - used_files) / total_files if total_files > 0 else 0

        return {
            'total_files': total_files,
            'imported_files': imported_files,
            'used_files': used_files,
            'filtered_out_rate': filtered_out_rate,
            'file_details': file_details,  # 可选：包含每个文件的详细信息
            'filtered_out_count': total_files - used_files,
            'filtered_out_percentage': filtered_out_rate * 100
        }


def main():
    start_time = time.time()
    # 创建增强版过滤器
    crypto_filter = PythonCryptoAPIFilter()

    # source_directory = './Non-Test_Projects/scrapy-master'
    # output_directory = './Filtered_projects/scrapy-master'

    source_directory = './PyCryptoBench-LLM'
    output_directory = './Filtered_PyCryptoBench-LLM'

    # source_directory = './small_test'
    # output_directory = './Filtered_small_test_FL'

    print("=" * 60)
    print("Starting file filtering and copying...")
    print("=" * 60)

    # 1. Filter and Copy
    copied_files = crypto_filter.copy_filtered_files(source_directory, output_directory)
    print(f"✅ Successfully copied {len(copied_files)} file(s) containing Cryptographic API usage to {output_directory}.")
    elapsed = round(time.time() - start_time, 2)

    # 2. Statistics
    stats = crypto_filter.get_filter_statistics(source_directory)
    print(f"📊 Filter Statistics:")
    print(f"   Total files: {stats['total_files']}")
    print(f"   Files imported Cryptographic module: {stats['imported_files']}")
    print(f"   Files actively used Cryptographic module: {stats['used_files']}")
    print(f"   Filter-out Rate: {stats['filtered_out_rate']:.2%}")
    print(f"   Number of files filtered out: {stats['filtered_out_count']}")


    # 3. Report
    report_file = os.path.join(output_directory, 'scan_report.txt')
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("Cryptographic API Usage Scan Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Scan Directory: {source_directory}\n")
        f.write(f"Output Directory: {output_directory}\n")
        f.write(f"Scanning Time Elapsed: {elapsed} seconds\n\n")

        f.write("Filter Statistics:\n")
        f.write(f"  Total files: {stats['total_files']}\n")
        f.write(f"  Files importing Cryptographic module: {stats['imported_files']}\n")
        f.write(f"  Files actively using Cryptographic module: {stats['used_files']}\n")
        f.write(f"  Filter-out Rate: {stats['filtered_out_rate']:.2%}\n")
        f.write(f"  Number of files filtered out: {stats['filtered_out_count']}\n\n")

        f.write("Filtered Files:\n")
        for i, file_path in enumerate(copied_files, 1):
            f.write(f"  {i}. {file_path}\n")

    print(f"📝 Scan Report Successfully Save to: {report_file}")


if __name__ == "__main__":
    main()