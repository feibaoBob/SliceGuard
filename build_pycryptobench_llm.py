"""
PyCryptoBench-LLM Benchmark Builder

Builds the optimized PyCryptoBench-LLM benchmark from the original PyCryptoBench,
performing all optimization steps in a single run:

  1. Classify unsafe files into misuse_cases or trap_type2 (FP reclassification)
  2. Copy trap files to trap_type1 with Trap_ prefix
  3. Copy safe files to safe_type2
  4. Generate safe_type1 files (safe usage of crypto APIs)
  5. Generate new rule_16/rule_18 misuse cases (true misuses added back)
  6. Generate import variant misuse cases (alias/wildcard/dynamic) for all rules
  7. Add Trap_ prefix to reclassified trap_type2 filenames
  8. Generate metadata/benchmark_info.json and README.md

Categories:
  1. misuse_cases  - imported AND insecurely used (true misuses only)
  2. trap_type1    - imported only, not used at all
  3. trap_type2    - imported AND used, but NOT in a security-sensitive way
  4. safe_type1    - imported AND safely used
  5. safe_type2    - no crypto API import or usage

False positive reclassification:
  - rule_05 (12 files): random used for general purpose, not key/salt
  - rule_16 (12 files): yaml.dump (serialization), not yaml.load (deserialization)
  - rule_18 (12 files): static regex patterns, not dynamic input

Note: rule_00 files are omitted because they duplicate rule_05.
Note: rule_09 AES files are TRUE misuses (rule 9 explicitly covers fixed/predictable IVs).
"""

import re
import json
import shutil
import argparse
from pathlib import Path
from typing import Dict, List

PROJECT_DIR = Path(__file__).parent
SOURCE_DIR = PROJECT_DIR / "PyCryptoBench"
OUTPUT_DIR = PROJECT_DIR / "PyCryptoBench-LLM"

ALL_FP_RULES = {5, 16, 18}
OMITTED_RULES = {0}

IMPORT_VARIANT_NAMES = [
    "alias_import_0", "alias_import_1",
    "wildcard_import_0", "wildcard_import_1",
    "dynamic_import_0", "dynamic_import_1",
]

# ─── True Misuse Cases for rule_16 & rule_18 (added back) ──────────────────

NEW_MISUSE_CASES: Dict[int, Dict[str, str]] = {
    16: {
        "insecure_0": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n"
            'data = load("""\n'
            "name: John Doe\n"
            "age: 30\n"
            '\"\"\", Loader=Loader)\n'
            "print(data)\n"
        ),
        "insecure_1": (
            "import yaml\n"
            "\n"
            'data = yaml.load("""\n'
            "server:\n"
            "    host: localhost\n"
            "    port: 8080\n"
            '\"\"\", Loader=yaml.FullLoader)\n'
            "print(data)\n"
        ),
        "Field-Sensitive_0": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n\n"
            "class BaseRunner(object):\n"
            "\n"
            "    def __init__(self, argument):\n"
            "        self.argument = argument\n"
            "\n\n"
            "runner_object = BaseRunner(load)\n"
            'data = runner_object.argument("""\n'
            "name: John Doe\n"
            "age: 30\n"
            '\"\"\", Loader=Loader)\n'
            "print(data)\n"
        ),
        "Field-Sensitive_1": (
            "import yaml\n"
            "from yaml import load\n"
            "\n\n"
            "class BaseRunner(object):\n"
            "\n"
            "    def __init__(self, argument):\n"
            "        self.argument = argument\n"
            "\n\n"
            "runner_object = BaseRunner(yaml.load)\n"
            'data = runner_object.argument("""\n'
            "server:\n"
            "    host: localhost\n"
            "    port: 8080\n"
            '\"\"\", Loader=yaml.FullLoader)\n'
            "print(data)\n"
        ),
        "Global_0": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n"
            "x = load\n"
            "\n\n"
            "def starting_method():\n"
            "    global x\n"
            '    data = x("""\n'
            "name: John Doe\n"
            "age: 30\n"
            '\"\"\", Loader=Loader)\n'
            "    print(data)\n"
            "\n\n"
            "starting_method()\n"
        ),
        "Global_1": (
            "import yaml\n"
            "from yaml import load\n"
            "\n"
            "x = yaml.load\n"
            "\n\n"
            "def starting_method():\n"
            "    global x\n"
            '    data = x("""\n'
            "server:\n"
            "    host: localhost\n"
            "    port: 8080\n"
            '\"\"\", Loader=yaml.FullLoader)\n'
            "    print(data)\n"
            "\n\n"
            "starting_method()\n"
        ),
        "Interprocedural_0": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n\n"
            "def call_method(argument):\n"
            '    data = argument("""\n'
            "name: John Doe\n"
            "age: 30\n"
            '\"\"\", Loader=Loader)\n'
            "    print(data)\n"
            "\n\n"
            "def starting_method():\n"
            "    call_method(load)\n"
            "\n\n"
            "starting_method()\n"
        ),
        "Interprocedural_1": (
            "import yaml\n"
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n\n"
            "def call_method(argument):\n"
            '    data = argument.load("""\n'
            "server:\n"
            "    host: localhost\n"
            "    port: 8080\n"
            '\"\"\", Loader=Loader)\n'
            "    print(data)\n"
            "\n\n"
            "def starting_method():\n"
            "    call_method(yaml)\n"
            "\n\n"
            "starting_method()\n"
        ),
        "InterproceduralViaReturn_0": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n\n"
            "def call_method():\n"
            "\n"
            "    def starting_method(argument):\n"
            '        data = argument("""\n'
            "name: John Doe\n"
            "age: 30\n"
            '\"\"\", Loader=Loader)\n'
            "        print(data)\n"
            "\n"
            "    return starting_method\n"
            "\n\n"
            "call_method()(load)\n"
        ),
        "InterproceduralViaReturn_1": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "\n\n"
            "def call_method():\n"
            "\n"
            "    def starting_method():\n"
            '        data = load("""\n'
            "server:\n"
            "    host: localhost\n"
            "    port: 8080\n"
            '\"\"\", Loader=Loader)\n'
            "        print(data)\n"
            "\n"
            "    return starting_method\n"
            "\n\n"
            "call_method()()\n"
        ),
        "Path-Sensitive_0": (
            "from yaml import load\n"
            "try:\n"
            "    from yaml import CLoader as Loader\n"
            "except ImportError:\n"
            "    from yaml import Loader\n"
            "if True:\n"
            '    if str(input("Accept Path?")).lower() == "yes":\n'
            '        data = load("""\n'
            "name: John Doe\n"
            "age: 30\n"
            '\"\"\", Loader=Loader)\n'
            "        print(data)\n"
            "    else:\n"
            '        print("Didn\'t accept path")\n'
        ),
        "Path-Sensitive_1": (
            "import yaml\n"
            "if True:\n"
            '    if str(input("Accept Path?")).lower() == "yes":\n'
            '        data = yaml.load("""\n'
            "server:\n"
            "    host: localhost\n"
            "    port: 8080\n"
            '\"\"\", Loader=yaml.FullLoader)\n'
            "        print(data)\n"
            "    else:\n"
            '        print("Didn\'t accept path")\n'
        ),
    },
    18: {
        "insecure_0": (
            "import re\n"
            "\n"
            'user_input = input("Enter pattern: ")\n'
            're.search(user_input, "Sample String To Search For", re.M | re.I)\n'
        ),
        "insecure_1": (
            "import re\n"
            "\n"
            'user_input = input("Enter search pattern: ")\n'
            're.search(user_input, "Another sample string to look", re.M | re.I)\n'
        ),
        "Field-Sensitive_0": (
            "import re\n"
            "\n\n"
            "class BaseRunner(object):\n"
            "\n"
            "    def __init__(self, argument):\n"
            "        self.argument = argument\n"
            "\n\n"
            "runner_object = BaseRunner(re)\n"
            'user_input = input("Enter pattern: ")\n'
            'runner_object.argument.search(user_input, "Sample String To Search For", re.M | re.I)\n'
        ),
        "Field-Sensitive_1": (
            "import re\n"
            "\n\n"
            "class BaseRunner(object):\n"
            "\n"
            "    def __init__(self, argument):\n"
            "        self.argument = argument\n"
            "\n\n"
            "runner_object = BaseRunner(re.search)\n"
            'user_input = input("Enter pattern: ")\n'
            'runner_object.argument(user_input, "Sample String To Search For", re.M | re.I)\n'
        ),
        "Global_0": (
            "import re\n"
            "\n"
            "x = re\n"
            "\n\n"
            "def starting_method():\n"
            "    global x\n"
            '    user_input = input("Enter pattern: ")\n'
            '    x.search(user_input, "Sample String To Search For", re.M | re.I)\n'
            "\n\n"
            "starting_method()\n"
        ),
        "Global_1": (
            "import re\n"
            "\n"
            "x = re.search\n"
            "\n\n"
            "def starting_method():\n"
            "    global x\n"
            '    user_input = input("Enter pattern: ")\n'
            '    x(user_input, "Sample String To Search For", re.M | re.I)\n'
            "\n\n"
            "starting_method()\n"
        ),
        "Interprocedural_0": (
            "import re\n"
            "\n\n"
            "def call_method(argument):\n"
            '    user_input = input("Enter pattern: ")\n'
            '    argument(user_input, "Sample String To Search For", re.M | re.I)\n'
            "\n\n"
            "def starting_method():\n"
            "    call_method(re.search)\n"
            "\n\n"
            "starting_method()\n"
        ),
        "Interprocedural_1": (
            "import re\n"
            "\n\n"
            "def call_method(argument):\n"
            '    user_input = input("Enter pattern: ")\n'
            '    argument.search(user_input, "Sample String To Search For", re.M | re.I)\n'
            "\n\n"
            "def starting_method():\n"
            "    call_method(re)\n"
            "\n\n"
            "starting_method()\n"
        ),
        "InterproceduralViaReturn_0": (
            "import re\n"
            "\n\n"
            "def call_method(argument):\n"
            "\n"
            "    def starting_method(second_argument, third_argument):\n"
            "        argument(second_argument, third_argument)\n"
            "\n"
            "    return starting_method\n"
            "\n\n"
            'user_input = input("Enter pattern: ")\n'
            'call_method(re.search)(user_input, "Sample String To Search For")\n'
        ),
        "InterproceduralViaReturn_1": (
            "import re\n"
            "\n\n"
            "def call_method(argument):\n"
            "\n"
            "    def starting_method():\n"
            '        user_input = input("Enter pattern: ")\n'
            '        argument(user_input, "Sample String To Search For", re.M | re.I)\n'
            "\n"
            "    return starting_method\n"
            "\n\n"
            "call_method(re.search)()\n"
        ),
        "Path-Sensitive_0": (
            "import re\n"
            "if True:\n"
            '    if str(input("Accept Path?")).lower() == "yes":\n'
            '        user_input = input("Enter pattern: ")\n'
            '        re.search(user_input, "Sample String To Search For", re.M | re.I)\n'
            "    else:\n"
            '        print("Didn\'t accept path")\n'
        ),
        "Path-Sensitive_1": (
            "import re\n"
            "if True:\n"
            '    if str(input("Accept Path?")).lower() == "yes":\n'
            '        user_input = input("Enter pattern: ")\n'
            '        re.search(user_input, "Another sample string to look", re.M | re.I)\n'
            "    else:\n"
            '        print("Didn\'t accept path")\n'
        ),
    },
}

# ─── Import Variant Definitions ─────────────────────────────────────────────

IMPORT_VARIANTS: Dict[int, List[Dict[str, str]]] = {
    1: [
        {"imports": "import requests as req", "body": "req.request('GET', 'https://google.com', verify=False)"},
        {"imports": "from requests import request as rreq", "body": "rreq('GET', 'https://google.com', verify=False)"},
        {"imports": "from requests import *", "body": "request('GET', 'https://google.com', verify=False)"},
        {"imports": "from requests import *", "body": "get('https://google.com', verify=False)"},
        {"imports": "req = __import__('requests')", "body": "req.request('GET', 'https://google.com', verify=False)"},
        {"imports": "import importlib\nreq = importlib.import_module('requests')", "body": "req.request('GET', 'https://google.com', verify=False)"},
    ],
    2: [
        {"imports": "import requests as req\nimport os as operating_system", "body": "operating_system.environ['CURL_CA_BUNDLE'] = \"\"\nreq.get('https://google.com')"},
        {"imports": "from os import environ as env\nfrom requests import get as rget", "body": "env['CURL_CA_BUNDLE'] = \"\"\nrget('https://google.com')"},
        {"imports": "from os import *\nfrom requests import *", "body": "environ['CURL_CA_BUNDLE'] = \"\"\nget('https://google.com')"},
        {"imports": "from requests import *\nfrom os import *", "body": "environ['CURL_CA_BUNDLE'] = None\nget('https://google.com')"},
        {"imports": "req = __import__('requests')\nos_mod = __import__('os')", "body": "os_mod.environ['CURL_CA_BUNDLE'] = \"\"\nreq.get('https://google.com')"},
        {"imports": "import importlib\nreq = importlib.import_module('requests')\nos_mod = importlib.import_module('os')", "body": "os_mod.environ['CURL_CA_BUNDLE'] = \"\"\nreq.get('https://google.com')"},
    ],
    3: [
        {"imports": "import ssl as secure_socket_layer\nimport urllib.request as url_req", "body": "context = secure_socket_layer._create_unverified_context()\nurl_req.urlopen(\"https://google.com\", context=context)"},
        {"imports": "from ssl import _create_unverified_context as make_ctx\nfrom urllib.request import urlopen as url_open", "body": "context = make_ctx()\nurl_open(\"https://google.com\", context=context)"},
        {"imports": "from ssl import *\nfrom urllib.request import *", "body": "context = _create_unverified_context()\nurlopen(\"https://google.com\", context=context)"},
        {"imports": "from ssl import *\nimport urllib.request", "body": "context = _create_unverified_context()\nurllib.request.urlopen(\"https://google.com\", context=context)"},
        {"imports": "ssl_mod = __import__('ssl')\nurllib_req = __import__('urllib.request', fromlist=['request'])", "body": "context = ssl_mod._create_unverified_context()\nurllib_req.urlopen(\"https://google.com\", context=context)"},
        {"imports": "import importlib\nssl_mod = importlib.import_module('ssl')\nurllib_req = importlib.import_module('urllib.request')", "body": "context = ssl_mod._create_unverified_context()\nurllib_req.urlopen(\"https://google.com\", context=context)"},
    ],
    4: [
        {"imports": "import urllib.request as url_req", "body": "req = url_req.urlopen('http://google.com').read()\nprint(req)"},
        {"imports": "from urllib.request import urlopen as url_open", "body": "req = url_open('http://google.com').read()\nprint(req)"},
        {"imports": "from urllib.request import *", "body": "req = urlopen('http://google.com').read()\nprint(req)"},
        {"imports": "from urllib.request import *", "body": "req = Request('http://google.com')\nprint(req)"},
        {"imports": "urllib_req = __import__('urllib.request', fromlist=['request'])", "body": "req = urllib_req.urlopen('http://google.com').read()\nprint(req)"},
        {"imports": "import importlib\nurllib_req = importlib.import_module('urllib.request')", "body": "req = urllib_req.urlopen('http://google.com').read()\nprint(req)"},
    ],
    6: [
        {"imports": "from hashlib import pbkdf2_hmac as derive_key", "body": "hash_val = derive_key('sha256', b'SomePasswordThatExceeds32CharactersInLength',\n                   b'D8VxSmTZt2E2YV454mkqAY5e', 100000)"},
        {"imports": "import hashlib as hl", "body": "hash_val = hl.pbkdf2_hmac('sha256', b'SomePasswordThatExceeds32CharactersInLength',\n                   b'D8VxSmTZt2E2YV454mkqAY5e', 100000)"},
        {"imports": "from hashlib import *", "body": "hash_val = pbkdf2_hmac('sha256', b'SomePasswordThatExceeds32CharactersInLength',\n                   b'D8VxSmTZt2E2YV454mkqAY5e', 100000)"},
        {"imports": "from hashlib import *", "body": "hash_val = pbkdf2_hmac('sha256', b'SomePasswordThatExceeds32CharactersInLength',\n                   b'NotLong', 100000)"},
        {"imports": "hl = __import__('hashlib')", "body": "hash_val = hl.pbkdf2_hmac('sha256', b'SomePasswordThatExceeds32CharactersInLength',\n                   b'D8VxSmTZt2E2YV454mkqAY5e', 100000)"},
        {"imports": "import importlib\nhl = importlib.import_module('hashlib')", "body": "hash_val = hl.pbkdf2_hmac('sha256', b'SomePasswordThatExceeds32CharactersInLength',\n                   b'D8VxSmTZt2E2YV454mkqAY5e', 100000)"},
    ],
    7: [
        {"imports": "from cryptography.hazmat.primitives.ciphers import Cipher as Cph, algorithms as algo, modes as m", "body": "cipher = Cph(algo.AES(b'1234123412341234'), m.ECB())"},
        {"imports": "import cryptography.hazmat.primitives.ciphers as ciphers_mod", "body": "cipher = ciphers_mod.Cipher(ciphers_mod.algorithms.AES(b'1234123412341234'), ciphers_mod.modes.ECB())"},
        {"imports": "from cryptography.hazmat.primitives.ciphers import *", "body": "cipher = Cipher(algorithms.AES(b'1234123412341234'), modes.ECB())"},
        {"imports": "from cryptography.hazmat.primitives.ciphers import *", "body": "_mode = modes.ECB()\ncipher = Cipher(algorithms.AES(b'1234123412341234'), _mode)"},
        {"imports": "ciphers_mod = __import__('cryptography.hazmat.primitives.ciphers', fromlist=['ciphers'])", "body": "cipher = ciphers_mod.Cipher(ciphers_mod.algorithms.AES(b'1234123412341234'), ciphers_mod.modes.ECB())"},
        {"imports": "import importlib\nciphers_mod = importlib.import_module('cryptography.hazmat.primitives.ciphers')", "body": "cipher = ciphers_mod.Cipher(ciphers_mod.algorithms.AES(b'1234123412341234'), ciphers_mod.modes.ECB())"},
    ],
    8: [
        {"imports": "from hashlib import pbkdf2_hmac as derive_key\nimport os as operating_system", "body": "hash_val = derive_key('sha256', b\"someveryveryveryveryverylongpassword\",\n                   operating_system.urandom(45), 100)"},
        {"imports": "import hashlib as hl\nfrom os import urandom as get_random", "body": "hash_val = hl.pbkdf2_hmac('sha256', b\"someveryveryveryveryverylongpassword\",\n                   get_random(45), 100)"},
        {"imports": "from hashlib import *\nimport os", "body": "hash_val = pbkdf2_hmac('sha256', b\"someveryveryveryveryverylongpassword\",\n                   os.urandom(45), 100)"},
        {"imports": "from hashlib import *\nfrom os import *", "body": "hash_val = pbkdf2_hmac('sha256', b\"someveryveryveryveryverylongpassword\",\n                   urandom(45), 100)"},
        {"imports": "hl = __import__('hashlib')\nos_mod = __import__('os')", "body": "hash_val = hl.pbkdf2_hmac('sha256', b\"someveryveryveryveryverylongpassword\",\n                   os_mod.urandom(45), 100)"},
        {"imports": "import importlib\nhl = importlib.import_module('hashlib')\nos_mod = importlib.import_module('os')", "body": "hash_val = hl.pbkdf2_hmac('sha256', b\"someveryveryveryveryverylongpassword\",\n                   os_mod.urandom(45), 100)"},
    ],
    9: [
        {"imports": "from Crypto import Random as Rnd\nfrom Crypto.Cipher import AES as AdvancedAES", "body": "key = b'Sixteen byte key'\niv = Rnd.new().read(AdvancedAES.block_size)\ncipher = AdvancedAES.new(key, AdvancedAES.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b'Attack at dawn')\nprint(cipher.decrypt(msg))"},
        {"imports": "import Crypto.Cipher.AES as aes_cipher\nfrom Crypto import Random as Rnd", "body": "key = b'Sixteen byte key'\niv = Rnd.new().read(aes_cipher.block_size)\ncipher = aes_cipher.new(key, aes_cipher.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b'Attack at dawn')\nprint(cipher.decrypt(msg))"},
        {"imports": "from Crypto.Cipher import *\nfrom Crypto import Random", "body": "key = b'Sixteen byte key'\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b'Attack at dawn')\nprint(cipher.decrypt(msg))"},
        {"imports": "from Crypto import *\nfrom Crypto.Cipher import *", "body": "key = b'Sixteen byte key'\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b'Attack at dawn')\nprint(cipher.decrypt(msg))"},
        {"imports": "crypto_cipher = __import__('Crypto.Cipher', fromlist=['Cipher'])\ncrypto_random = __import__('Crypto.Random', fromlist=['Random'])", "body": "AES = crypto_cipher.AES\nRandom = crypto_random.Random\nkey = b'Sixteen byte key'\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b'Attack at dawn')\nprint(cipher.decrypt(msg))"},
        {"imports": "import importlib\ncrypto_cipher = importlib.import_module('Crypto.Cipher')\ncrypto_random = importlib.import_module('Crypto.Random')", "body": "AES = crypto_cipher.AES\nRandom = crypto_random.Random\nkey = b'Sixteen byte key'\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b'Attack at dawn')\nprint(cipher.decrypt(msg))"},
    ],
    10: [
        {"imports": "from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod", "body": "private_key = rsa_mod.generate_private_key(\n    public_exponent=65537,\n    key_size=512,\n)\nprint(private_key)"},
        {"imports": "import cryptography.hazmat.primitives.asymmetric as asym", "body": "private_key = asym.rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=512,\n)\nprint(private_key)"},
        {"imports": "from cryptography.hazmat.primitives.asymmetric import *", "body": "private_key = rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=512,\n)\nprint(private_key)"},
        {"imports": "from cryptography.hazmat.primitives.asymmetric import *", "body": "private_key = dsa.generate_private_key(key_size=1024)\nprint(private_key)"},
        {"imports": "asym = __import__('cryptography.hazmat.primitives.asymmetric', fromlist=['asymmetric'])", "body": "private_key = asym.rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=512,\n)\nprint(private_key)"},
        {"imports": "import importlib\nasym = importlib.import_module('cryptography.hazmat.primitives.asymmetric')", "body": "private_key = asym.rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=512,\n)\nprint(private_key)"},
    ],
    11: [
        {"imports": "from Crypto.Hash import MD5 as WeakHash", "body": "h = WeakHash.new()\nh.update(b'Hello')\nprint(h.hexdigest())"},
        {"imports": "import Crypto.Hash as crypto_hash", "body": "h = crypto_hash.MD5.new()\nh.update(b'Hello')\nprint(h.hexdigest())"},
        {"imports": "from Crypto.Hash import *", "body": "h = MD5.new()\nh.update(b'Hello')\nprint(h.hexdigest())"},
        {"imports": "from Crypto.Hash import *", "body": "h = SHA.new()\nh.update(b'Hello')\nprint(h.hexdigest())"},
        {"imports": "crypto_hash = __import__('Crypto.Hash', fromlist=['Hash'])", "body": "h = crypto_hash.MD5.new()\nh.update(b'Hello')\nprint(h.hexdigest())"},
        {"imports": "import importlib\ncrypto_hash = importlib.import_module('Crypto.Hash')", "body": "h = crypto_hash.MD5.new()\nh.update(b'Hello')\nprint(h.hexdigest())"},
    ],
    12: [
        {"imports": "import jwt as json_web_token", "body": "json_web_token.decode(\"\", verify=False)"},
        {"imports": "from jwt import decode as jwt_decode", "body": "jwt_decode(\"\", verify=False)"},
        {"imports": "from jwt import *", "body": "decode(\"\", verify=False)"},
        {"imports": "from jwt import *", "body": "decode(\"\", \"\", options={\"verify_signature\": False})"},
        {"imports": "jwt_mod = __import__('jwt')", "body": "jwt_mod.decode(\"\", verify=False)"},
        {"imports": "import importlib\njwt_mod = importlib.import_module('jwt')", "body": "jwt_mod.decode(\"\", verify=False)"},
    ],
    13: [
        {"imports": "import ssl as secure_socket", "body": "secure_socket.wrap_socket(ssl_version=secure_socket.PROTOCOL_SSLv2)\nsecure_socket.wrap_socket()"},
        {"imports": "from ssl import wrap_socket as wrap_sock, PROTOCOL_SSLv2 as SSL_V2", "body": "wrap_sock(ssl_version=SSL_V2)\nwrap_sock()"},
        {"imports": "from ssl import *", "body": "wrap_socket(ssl_version=PROTOCOL_SSLv2)\nwrap_socket()"},
        {"imports": "from ssl import *", "body": "wrap_socket(ssl_version=PROTOCOL_TLSv1)\nwrap_socket()"},
        {"imports": "ssl_mod = __import__('ssl')", "body": "ssl_mod.wrap_socket(ssl_version=ssl_mod.PROTOCOL_SSLv2)\nssl_mod.wrap_socket()"},
        {"imports": "import importlib\nssl_mod = importlib.import_module('ssl')", "body": "ssl_mod.wrap_socket(ssl_version=ssl_mod.PROTOCOL_SSLv2)\nssl_mod.wrap_socket()"},
    ],
    14: [
        {"imports": "import ldap as ldap_client", "body": "l = ldap_client.initialize(\"ldap://my_ldap_server.my_domain\")\nl.simple_bind_s(\"\", \"\")"},
        {"imports": "from ldap import initialize as ldap_init", "body": "l = ldap_init(\"ldap://my_ldap_server.my_domain\")\nl.simple_bind_s(\"\", \"\")"},
        {"imports": "from ldap import *", "body": "l = initialize(\"ldap://my_ldap_server.my_domain\")\nl.simple_bind_s(\"\", \"\")"},
        {"imports": "from ldap import *", "body": "l = initialize(\"ldap://my_ldap_server.my_domain\")\nl.simple_bind(\"\", \"\")"},
        {"imports": "ldap_mod = __import__('ldap')", "body": "l = ldap_mod.initialize(\"ldap://my_ldap_server.my_domain\")\nl.simple_bind_s(\"\", \"\")"},
        {"imports": "import importlib\nldap_mod = importlib.import_module('ldap')", "body": "l = ldap_mod.initialize(\"ldap://my_ldap_server.my_domain\")\nl.simple_bind_s(\"\", \"\")"},
    ],
    15: [
        {"imports": "import xml.sax as xml_sax", "body": "parser = xml_sax.make_parser(\"base_xml_file.xml\")"},
        {"imports": "from xml.sax import make_parser as create_parser", "body": "parser = create_parser(\"base_xml_file.xml\")"},
        {"imports": "from xml.sax import *", "body": "parser = make_parser(\"base_xml_file.xml\")"},
        {"imports": "from xml.dom.minidom import *", "body": "DOMTree = parse(\"base_xml_file.xml\")"},
        {"imports": "xml_sax = __import__('xml.sax', fromlist=['sax'])", "body": "parser = xml_sax.make_parser(\"base_xml_file.xml\")"},
        {"imports": "import importlib\nxml_sax = importlib.import_module('xml.sax')", "body": "parser = xml_sax.make_parser(\"base_xml_file.xml\")"},
    ],
    16: [
        {"imports": "import yaml as yml", "body": "data = yml.load(\"\"\"\nname: John Doe\nage: 30\n\"\"\", Loader=yml.FullLoader)\nprint(data)"},
        {"imports": "from yaml import load as yml_load", "body": "data = yml_load(\"\"\"\nname: John Doe\nage: 30\n\"\"\", Loader=yaml.FullLoader)\nprint(data)"},
        {"imports": "from yaml import *", "body": "data = load(\"\"\"\nname: John Doe\nage: 30\n\"\"\", Loader=FullLoader)\nprint(data)"},
        {"imports": "from yaml import *", "body": "data = load(\"\"\"\nserver:\n    host: localhost\n    port: 8080\n\"\"\")\nprint(data)"},
        {"imports": "yml = __import__('yaml')", "body": "data = yml.load(\"\"\"\nname: John Doe\nage: 30\n\"\"\", Loader=yml.FullLoader)\nprint(data)"},
        {"imports": "import importlib\nyml = importlib.import_module('yaml')", "body": "data = yml.load(\"\"\"\nname: John Doe\nage: 30\n\"\"\", Loader=yml.FullLoader)\nprint(data)"},
    ],
    17: [
        {"imports": "import pickle as pkl\nimport os as operating_system", "body": "class PickleKlass(object):\n    def __reduce__(self):\n        return operating_system.system, ('echo \"Hello World\"',)\n\nraw = pkl.dumps(PickleKlass())\npkl.loads(raw)"},
        {"imports": "from pickle import dumps as pkl_dumps, loads as pkl_loads\nfrom os import system as run_cmd", "body": "class PickleKlass(object):\n    def __reduce__(self):\n        return run_cmd, ('echo \"Hello World\"',)\n\nraw = pkl_dumps(PickleKlass())\npkl_loads(raw)"},
        {"imports": "from pickle import *\nimport os", "body": "class PickleKlass(object):\n    def __reduce__(self):\n        return os.system, ('echo \"Hello World\"',)\n\nraw = dumps(PickleKlass())\nloads(raw)"},
        {"imports": "from pickle import *\nfrom os import *", "body": "class PickleKlass(object):\n    def __reduce__(self):\n        return system, ('echo \"Hello World\"',)\n\nraw = dumps(PickleKlass())\nloads(raw)"},
        {"imports": "pkl = __import__('pickle')\nos_mod = __import__('os')", "body": "class PickleKlass(object):\n    def __reduce__(self):\n        return os_mod.system, ('echo \"Hello World\"',)\n\nraw = pkl.dumps(PickleKlass())\npkl.loads(raw)"},
        {"imports": "import importlib\npkl = importlib.import_module('pickle')\nos_mod = importlib.import_module('os')", "body": "class PickleKlass(object):\n    def __reduce__(self):\n        return os_mod.system, ('echo \"Hello World\"',)\n\nraw = pkl.dumps(PickleKlass())\npkl.loads(raw)"},
    ],
    18: [
        {"imports": "import re as regex", "body": "user_input = input(\"Enter pattern: \")\nregex.search(user_input, \"Sample String To Search For\", regex.M | regex.I)"},
        {"imports": "from re import search as regex_search, M as RE_M, I as RE_I", "body": "user_input = input(\"Enter pattern: \")\nregex_search(user_input, \"Sample String To Search For\", RE_M | RE_I)"},
        {"imports": "from re import *", "body": "user_input = input(\"Enter pattern: \")\nsearch(user_input, \"Sample String To Search For\", M | I)"},
        {"imports": "from re import *", "body": "user_input = input(\"Enter search pattern: \")\nsearch(user_input, \"Another sample string to look\", M | I)"},
        {"imports": "regex = __import__('re')", "body": "user_input = input(\"Enter pattern: \")\nregex.search(user_input, \"Sample String To Search For\", regex.M | regex.I)"},
        {"imports": "import importlib\nregex = importlib.import_module('re')", "body": "user_input = input(\"Enter pattern: \")\nregex.search(user_input, \"Sample String To Search For\", regex.M | regex.I)"},
    ],
}

# ─── Safe Type1 Templates ───────────────────────────────────────────────────

SAFE_TYPE1_TEMPLATES: Dict[int, Dict[str, str]] = {
    1: {
        "rule_01_safe_type1_0.py": 'import requests\n\nresponse = requests.get("https://example.com/api", verify=True)\nprint(response.status_code)\n',
        "rule_01_safe_type1_1.py": 'import requests\n\nsession = requests.Session()\nsession.verify = True\nresponse = session.get("https://api.example.com/data")\nprint(response.text)\n',
    },
    3: {
        "rule_03_safe_type1_0.py": 'import ssl\n\ncontext = ssl.create_default_context()\nwith context:\n    print("Using verified SSL context")\n',
        "rule_03_safe_type1_1.py": 'import ssl\nimport urllib.request\n\ncontext = ssl.create_default_context()\nresponse = urllib.request.urlopen("https://example.com", context=context)\nprint(response.read().decode())\n',
    },
    5: {
        "rule_05_safe_type1_0.py": 'import secrets\n\nkey = secrets.token_bytes(32)\nprint(f"Generated secure key: {key.hex()}")\n',
        "rule_05_safe_type1_1.py": 'import secrets\n\nsalt = secrets.token_hex(16)\ntoken = secrets.token_urlsafe(32)\nprint(f"Salt: {salt}, Token: {token}")\n',
    },
    6: {
        "rule_06_safe_type1_0.py": 'import os\nimport hashlib\n\nsalt = os.urandom(16)\nkey = hashlib.pbkdf2_hmac("sha256", b"password", salt, 100000)\nprint("Secure key derived with random salt")\n',
        "rule_06_safe_type1_1.py": 'import secrets\nimport hashlib\n\nsalt = secrets.token_bytes(16)\nkey = hashlib.pbkdf2_hmac("sha256", b"my_password", salt, 100000)\nprint("Key derived securely")\n',
    },
    7: {
        "rule_07_safe_type1_0.py": 'from Crypto.Cipher import AES\nfrom Crypto import Random\n\nkey = Random.new().read(32)\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_CBC, iv)\nprint("Using CBC mode instead of ECB")\n',
        "rule_07_safe_type1_1.py": 'from Crypto.Cipher import AES\nfrom Crypto import Random\n\nkey = Random.new().read(32)\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_GCM, iv)\nprint("Using GCM mode (authenticated encryption)")\n',
    },
    8: {
        "rule_08_safe_type1_0.py": 'import os\nimport hashlib\n\nkey = hashlib.pbkdf2_hmac("sha256", b"password", os.urandom(32), 100000)\nprint("Using 100000 iterations (>= 1000)")\n',
        "rule_08_safe_type1_1.py": 'import secrets\nimport hashlib\n\nkey = hashlib.pbkdf2_hmac("sha256", b"password", secrets.token_bytes(32), 200000)\nprint("Using 200000 iterations for stronger security")\n',
    },
    9: {
        "rule_09_safe_type1_0.py": 'from Crypto.Cipher import AES\nfrom Crypto import Random\n\nkey = Random.new().read(32)\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_CFB, iv)\nmsg = iv + cipher.encrypt(b"Secret message")\nprint("Using AES (recommended cipher) with random key and IV")\n',
        "rule_09_safe_type1_1.py": 'from Crypto.Cipher import AES\nfrom Crypto import Random\n\nkey = Random.new().read(32)\niv = Random.new().read(AES.block_size)\ncipher = AES.new(key, AES.MODE_GCM, iv)\nciphertext, tag = cipher.encrypt_and_digest(b"Attack at dawn")\nprint("AES-GCM with proper random key")\n',
    },
    10: {
        "rule_10_safe_type1_0.py": 'from Crypto.PublicKey import RSA\n\nkey = RSA.generate(4096)\nprint(f"Using RSA with {key.size_in_bits()} bits (>= 2048)")\n',
        "rule_10_safe_type1_1.py": 'from Crypto.PublicKey import RSA\n\nkey = RSA.generate(2048)\npublic_key = key.publickey()\nprint(f"RSA key size: {key.size_in_bits()} bits")\n',
    },
    11: {
        "rule_11_safe_type1_0.py": 'import hashlib\n\ndigest = hashlib.sha256(b"message").hexdigest()\nprint(f"SHA-256 digest: {digest}")\n',
        "rule_11_safe_type1_1.py": 'import hashlib\n\ndigest = hashlib.sha512(b"Important data").hexdigest()\nprint(f"SHA-512 digest: {digest}")\n',
    },
    12: {
        "rule_12_safe_type1_0.py": 'import jwt\n\npayload = {"user": "alice", "role": "admin"}\ntoken = jwt.encode(payload, "secret_key", algorithm="HS256")\ndecoded = jwt.decode(token, "secret_key", algorithms=["HS256"])\nprint(decoded)\n',
        "rule_12_safe_type1_1.py": 'import jwt\n\ntoken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ"\ntry:\n    decoded = jwt.decode(token, "secret_key", algorithms=["HS256"])\n    print(decoded)\nexcept jwt.InvalidTokenError:\n    print("Invalid token")\n',
    },
    13: {
        "rule_13_safe_type1_0.py": 'import ssl\n\ncontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\ncontext.minimum_version = ssl.TLSVersion.TLSv1_2\nprint("Using TLS 1.2+ (secure version)")\n',
        "rule_13_safe_type1_1.py": 'import ssl\n\ncontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\ncontext.maximum_version = ssl.TLSVersion.TLSv1_3\ncontext.minimum_version = ssl.TLSVersion.TLSv1_2\nprint("Using TLS 1.2-1.3 (secure versions)")\n',
    },
    14: {
        "rule_14_safe_type1_0.py": 'import ssl\nimport ldap3\n\nserver = ldap3.Server("ldaps://ldap.example.com", use_ssl=True)\nconn = ldap3.Connection(server, user="cn=admin", password="secret")\nprint("Using LDAPS (secure LDAP) with credentials")\n',
        "rule_14_safe_type1_1.py": 'import smtplib\n\nwith smtplib.SMTP("smtp.example.com", 587) as server:\n    server.starttls()\n    server.login("user@example.com", "password")\n    print("Using SMTP with STARTTLS")\n',
    },
    16: {
        "rule_16_safe_type1_0.py": 'import yaml\n\ndata = yaml.safe_load("key: value")\nprint(data)\n',
        "rule_16_safe_type1_1.py": 'from yaml import safe_load, safe_dump\n\nconfig = safe_load(open("config.yaml"))\nprint(safe_dump(config))\n',
    },
    17: {
        "rule_17_safe_type1_0.py": 'import hmac\nimport hashlib\n\nkey = b"secret_key"\nmessage = b"Important data"\nsignature = hmac.new(key, message, hashlib.sha256).hexdigest()\nprint(f"HMAC signature: {signature}")\n',
        "rule_17_safe_type1_1.py": 'import json\n\ndata = {"user": "alice", "role": "admin"}\nserialized = json.dumps(data)\nprint(serialized)\n',
    },
    18: {
        "rule_18_safe_type1_0.py": 'import re\n\nuser_input = input("Enter search term: ")\nsafe_pattern = re.escape(user_input)\nresult = re.search(safe_pattern, "Sample text to search")\nprint(result)\n',
        "rule_18_safe_type1_1.py": 'import re\n\nuser_input = input("Enter pattern: ")\nescaped = re.escape(user_input)\ncompiled = re.compile(escaped)\nmatches = compiled.findall("Some text to search in")\nprint(matches)\n',
    },
}


# ─── Utilities ───────────────────────────────────────────────────────────────

def extract_rule_id(filename: str) -> int:
    m = re.match(r"(?:Trap_)?(?:Import_.*?_)?rule_(\d+)[_]", filename)
    return int(m.group(1)) if m else -1


def fp_reason(rule_id: int) -> str:
    reasons = {
        5: "Uses random.randint() for general-purpose numbers, NOT for key/salt generation per rule definition",
        16: "Uses yaml.dump/dump_all (serialization), NOT yaml.load (deserialization) per rule definition",
        18: "Uses static hardcoded regex patterns, NOT dynamic user input per rule definition",
    }
    return reasons.get(rule_id, "False positive per rule definition")


def _load_rule_groups() -> dict:
    rule_file = PROJECT_DIR / "rule_source_py.py"
    if not rule_file.exists():
        return {}
    ns: dict = {}
    exec(rule_file.read_text(encoding="utf-8"), ns)
    return ns.get("rule_groups", {})


# ─── Main Builder ────────────────────────────────────────────────────────────

class BenchmarkBuilder:
    def __init__(self, source_dir: Path, output_dir: Path):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.stats: Dict[str, List[dict]] = {
            "misuse_cases": [],
            "trap_type1": [],
            "trap_type2": [],
            "safe_type1": [],
            "safe_type2": [],
        }
        self.reclassification_log: List[dict] = []
        self.generated_log: List[dict] = []

    def clean_output(self):
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)

    def create_dirs(self):
        for cat in self.stats:
            (self.output_dir / cat).mkdir(parents=True, exist_ok=True)
        (self.output_dir / "metadata").mkdir(parents=True, exist_ok=True)

    # ── Step 1: Classify and copy unsafe files ──────────────────────────

    def process_unsafe_files(self):
        unsafe_dir = self.source_dir / "misuse_cases"
        if not unsafe_dir.exists():
            print(f"  [WARN] {unsafe_dir} does not exist")
            return

        for f in sorted(unsafe_dir.glob("*.py")):
            filename = f.name
            rule_id = extract_rule_id(filename)

            if rule_id in OMITTED_RULES:
                continue

            if rule_id in ALL_FP_RULES:
                dest_cat = "trap_type2"
                new_name = f"Trap_{filename}"
                shutil.copy2(f, self.output_dir / dest_cat / new_name)
                self.reclassification_log.append({
                    "filename": new_name,
                    "original_filename": filename,
                    "rule_id": rule_id,
                    "original_category": "misuse_cases (unsafe)",
                    "new_category": "trap_type2",
                    "reason": fp_reason(rule_id),
                })
            else:
                dest_cat = "misuse_cases"
                new_name = filename
                shutil.copy2(f, self.output_dir / dest_cat / new_name)

            entry = {
                "filename": new_name,
                "rule_id": rule_id,
                "source": "misuse_cases",
                "category": dest_cat,
            }
            self.stats[dest_cat].append(entry)

    # ── Step 2: Copy trap files (trap_type1) ────────────────────────────

    def process_trap_files(self):
        trap_dir = self.source_dir / "trap_cases"
        if not trap_dir.exists():
            print(f"  [WARN] {trap_dir} does not exist")
            return

        for f in sorted(trap_dir.glob("*.py")):
            filename = f.name
            shutil.copy2(f, self.output_dir / "trap_type1" / filename)

            m = re.search(r"rule_(\d+)_trapfile", filename)
            rule_id = int(m.group(1)) if m else -1

            entry = {
                "filename": filename,
                "rule_id": rule_id,
                "source": "trap_cases",
                "category": "trap_type1",
            }
            self.stats["trap_type1"].append(entry)

    # ── Step 3: Copy safe files (safe_type2) ────────────────────────────

    def process_safe_files(self):
        safe_dir = self.source_dir / "safe_cases"
        if not safe_dir.exists():
            print(f"  [WARN] {safe_dir} does not exist")
            return

        for f in sorted(safe_dir.glob("*.py")):
            filename = f.name
            shutil.copy2(f, self.output_dir / "safe_type2" / filename)

            m = re.search(r"rule_(\d+)_safefile", filename)
            rule_id = int(m.group(1)) if m else -1

            entry = {
                "filename": filename,
                "rule_id": rule_id,
                "source": "safe_cases",
                "category": "safe_type2",
            }
            self.stats["safe_type2"].append(entry)

    # ── Step 4: Generate safe_type1 files ───────────────────────────────

    def generate_safe_type1_files(self):
        dest_dir = self.output_dir / "safe_type1"
        for rule_id, templates in SAFE_TYPE1_TEMPLATES.items():
            for filename, content in templates.items():
                filepath = dest_dir / filename
                filepath.write_text(content, encoding="utf-8", newline="\n")

                entry = {
                    "filename": filename,
                    "rule_id": rule_id,
                    "source": "generated_safe_type1",
                    "category": "safe_type1",
                }
                self.stats["safe_type1"].append(entry)

    # ── Step 5: Generate new rule_16/rule_18 misuse cases ───────────────

    def generate_new_misuse_cases(self):
        dest_dir = self.output_dir / "misuse_cases"
        for rule_id, variants in NEW_MISUSE_CASES.items():
            for variant_name, content in variants.items():
                filename = f"rule_{rule_id:02d}_{variant_name}.py"
                filepath = dest_dir / filename
                filepath.write_text(content, encoding="utf-8", newline="\n")

                entry = {
                    "filename": filename,
                    "rule_id": rule_id,
                    "source": "generated_misuse",
                    "category": "misuse_cases",
                }
                self.stats["misuse_cases"].append(entry)
                self.generated_log.append({
                    "type": "new_misuse",
                    "filename": filename,
                    "rule_id": rule_id,
                    "variant": variant_name,
                })

    # ── Step 6: Generate import variant misuse cases ────────────────────

    def generate_import_variants(self):
        dest_dir = self.output_dir / "misuse_cases"
        for rule_id, variants in sorted(IMPORT_VARIANTS.items()):
            for i, variant in enumerate(variants):
                filename = f"rule_{rule_id:02d}_{IMPORT_VARIANT_NAMES[i]}.py"
                content = variant["imports"] + "\n\n" + variant["body"] + "\n"
                filepath = dest_dir / filename
                filepath.write_text(content, encoding="utf-8", newline="\n")

                entry = {
                    "filename": filename,
                    "rule_id": rule_id,
                    "source": "generated_import_variant",
                    "category": "misuse_cases",
                }
                self.stats["misuse_cases"].append(entry)
                self.generated_log.append({
                    "type": "import_variant",
                    "filename": filename,
                    "rule_id": rule_id,
                    "variant": IMPORT_VARIANT_NAMES[i],
                })

    # ── Step 7: Generate metadata ───────────────────────────────────────

    def generate_metadata(self) -> dict:
        counts = {cat: len(entries) for cat, entries in self.stats.items()}

        source_misuse = len([e for e in self.stats["misuse_cases"] if e["source"] == "misuse_cases"])
        source_trap2 = len([e for e in self.stats["trap_type2"] if e["source"] == "misuse_cases"])
        gen_misuse = len([e for e in self.stats["misuse_cases"] if e["source"] == "generated_misuse"])
        gen_import = len([e for e in self.stats["misuse_cases"] if e["source"] == "generated_import_variant"])

        metadata = {
            "benchmark_name": "PyCryptoBench-LLM",
            "description": (
                "Optimized Python cryptographic API misuse detection benchmark "
                "for evaluating LLM-based detection. Built from PyCryptoBench "
                "with false positive removal, 5-category classification, "
                "new misuse case generation, and import variant augmentation."
            ),
            "categories": {
                "misuse_cases": {
                    "description": "Imported insecure crypto API AND used insecurely (true misuses only)",
                    "count": counts["misuse_cases"],
                },
                "trap_type1": {
                    "description": "Imported insecure crypto API but NOT used at all",
                    "count": counts["trap_type1"],
                },
                "trap_type2": {
                    "description": "Imported AND used crypto API, but NOT in a security-sensitive way",
                    "count": counts["trap_type2"],
                },
                "safe_type1": {
                    "description": "Imported crypto API AND used it safely",
                    "count": counts["safe_type1"],
                },
                "safe_type2": {
                    "description": "No crypto API import or usage",
                    "count": counts["safe_type2"],
                },
            },
            "total_files": sum(counts.values()),
            "source_stats": {
                "misuse_cases_source_misuse": source_misuse,
                "misuse_cases_reclassified_trap2": source_trap2,
                "trap_cases": counts["trap_type1"],
                "safe_cases": counts["safe_type2"],
                "generated_misuse_rule16_18": gen_misuse,
                "generated_import_variants": gen_import,
                "generated_safe_type1": counts["safe_type1"],
            },
            "false_positive_rules": {
                "rule_05": "Using random for general purposes, not for key/salt generation per rule definition",
                "rule_16": "Using yaml.dump (serialization), not yaml.load (deserialization) per rule definition",
                "rule_18": "Using static regex patterns, not dynamic user input per rule definition",
            },
            "omitted_rules": {
                "rule_00": "Duplicates rule_05 (same random module usage, same false positive reason)",
            },
            "reclassification_log": self.reclassification_log,
            "generation_log": self.generated_log,
            "files_by_category": {
                cat: sorted(e["filename"] for e in entries)
                for cat, entries in self.stats.items()
            },
            "files_by_rule": self._group_by_rule(),
        }

        meta_path = self.output_dir / "metadata" / "benchmark_info.json"
        meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
        return metadata

    # ── Step 8: Generate README ─────────────────────────────────────────

    def generate_readme(self, metadata: dict):
        lines = [
            "# PyCryptoBench-LLM: Optimized Benchmark for LLM-based Crypto API Misuse Detection",
            "",
            "## Overview",
            "",
            "This benchmark is derived from PyCryptoBench with key improvements for LLM evaluation:",
            "",
            "1. **False positive removal**: Files that do not genuinely violate rule definitions are reclassified.",
            "2. **5-category classification** (instead of original 3).",
            "3. **New misuse case generation**: True misuse cases added for rules 16 and 18.",
            "4. **Import variant augmentation**: Alias, wildcard, and dynamic import variants for all rules.",
            "",
            "| Category | Description | Count |",
            "|----------|-------------|-------|",
        ]
        for cat, info in metadata["categories"].items():
            lines.append(f"| {cat} | {info['description']} | {info['count']} |")

        lines += [
            "",
            f"**Total files: {metadata['total_files']}**",
            "",
            "## False Positive Analysis",
            "",
            "The following rules had files reclassified from misuse to trap_type2 (false positive removal):",
            "",
            "| Rule | Issue | Reclassified Count |",
            "|------|-------|--------------------|",
        ]

        fp_counts: Dict[int, int] = {}
        for entry in self.reclassification_log:
            rid = entry["rule_id"]
            fp_counts[rid] = fp_counts.get(rid, 0) + 1
        for rid in sorted(fp_counts.keys()):
            reason = metadata["false_positive_rules"].get(f"rule_{rid:02d}", "See log")
            lines.append(f"| rule_{rid:02d} | {reason} | {fp_counts[rid]} |")

        import_variant_count = len([e for e in self.generated_log if e["type"] == "import_variant"])
        lines += [
            "",
            "## Misuse Case Augmentation",
            "",
            "### New True Misuse Cases (rules 16 & 18)",
            "",
            "After reclassifying false positives for rules 16 and 18, new true misuse cases",
            "were generated to restore rule coverage. Each rule has 12 new misuse cases",
            "(2 insecure base + 5 analysis variants x 2 each).",
            "",
            "### Import Variant Misuse Cases",
            "",
            "For each rule's base misuse case, 6 import variant files were generated:",
            "",
            "| Variant | Description |",
            "|---------|-------------|",
            "| alias_import_0 | `import module as alias` |",
            "| alias_import_1 | `from module import sub as alias` |",
            "| wildcard_import_0 | `from module import *` (variant 1) |",
            "| wildcard_import_1 | `from module import *` (variant 2) |",
            "| dynamic_import_0 | `module = __import__('module')` |",
            "| dynamic_import_1 | `importlib.import_module('module')` |",
            "",
            f"**Total import variant files: {import_variant_count}** ({len(IMPORT_VARIANTS)} rules x 6 variants)",
            "",
            "## Rule Coverage",
            "",
            "| Rule ID | Rule Name | Misuse | Trap1 | Trap2 | Safe1 | Safe2 |",
            "|---------|-----------|--------|-------|-------|-------|-------|",
        ]

        all_rules = sorted(set(
            e["rule_id"]
            for entries in self.stats.values()
            for e in entries
            if e["rule_id"] >= 0
        ))

        rule_groups = _load_rule_groups()
        for rid in all_rules:
            name = rule_groups.get(rid, {}).get("name", "N/A")
            rule_counts = {cat: 0 for cat in self.stats}
            for cat, entries in self.stats.items():
                for e in entries:
                    if e["rule_id"] == rid:
                        rule_counts[cat] += 1
            lines.append(
                f"| {rid} | {name} | {rule_counts['misuse_cases']} | "
                f"{rule_counts['trap_type1']} | {rule_counts['trap_type2']} | "
                f"{rule_counts['safe_type1']} | {rule_counts['safe_type2']} |"
            )

        lines += [
            "",
            "## Filename Conventions",
            "",
            "| Category | Pattern | Example |",
            "|----------|---------|---------|",
            "| misuse_cases | `rule_{NN}_{variant}_{idx}.py` | `rule_01_insecure_0.py`, `rule_16_alias_import_1.py` |",
            "| trap_type1 | `Trap_Import_{lib}_rule_{NN}_trapfile_{idx}.py` | `Trap_Import_ssl_rule_1_trapfile_3.py` |",
            "| trap_type2 | `Trap_rule_{NN}_{variant}_{idx}.py` | `Trap_rule_05_Field-Sensitive_0.py` |",
            "| safe_type1 | `rule_{NN}_safe_type1_{idx}.py` | `rule_01_safe_type1_0.py` |",
            "| safe_type2 | `Trap_Import_{lib}_rule_{NN}_safefile_{idx}.py` | `Trap_Import_ssl_rule_1_safefile_3.py` |",
            "",
            "## Evaluation Metrics",
            "",
            "- **True Positive (TP)**: LLM correctly flags a `misuse_cases` file",
            "- **False Positive (FP)**: LLM incorrectly flags a non-misuse file",
            "- **True Negative (TN)**: LLM correctly does NOT flag a non-misuse file",
            "- **False Negative (FN)**: LLM fails to flag a `misuse_cases` file",
            "",
            "Fine-grained metrics:",
            "- Precision = TP / (TP + FP)",
            "- Recall = TP / (TP + FN)",
            "- F1 Score = 2 * Precision * Recall / (Precision + Recall)",
            "- Trap Type1 FP Rate: fraction of trap_type1 incorrectly flagged",
            "- Trap Type2 FP Rate: fraction of trap_type2 incorrectly flagged",
            "- Safe Type1 FP Rate: fraction of safe_type1 incorrectly flagged",
            "- Safe Type2 FP Rate: fraction of safe_type2 incorrectly flagged",
        ]

        readme_path = self.output_dir / "README.md"
        readme_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")

    # ── Helpers ──────────────────────────────────────────────────────────

    def _group_by_rule(self) -> dict:
        result: Dict[int, Dict[str, int]] = {}
        for cat, entries in self.stats.items():
            for e in entries:
                rid = e["rule_id"]
                if rid not in result:
                    result[rid] = {}
                result[rid][cat] = result[rid].get(cat, 0) + 1
        return {str(k): v for k, v in sorted(result.items())}

    # ── Main runner ──────────────────────────────────────────────────────

    def run(self):
        print("=" * 60)
        print("PyCryptoBench-LLM Benchmark Builder")
        print("=" * 60)

        self.clean_output()
        self.create_dirs()

        print("\n[1/8] Processing unsafe files (classify misuse vs trap_type2)...")
        self.process_unsafe_files()
        n_src_misuse = len([e for e in self.stats["misuse_cases"] if e["source"] == "misuse_cases"])
        print(f"  Misuse (from source): {n_src_misuse}")
        print(f"  Reclassified as trap_type2: {len(self.stats['trap_type2'])}")

        print("\n[2/8] Processing trap files (trap_type1)...")
        self.process_trap_files()
        print(f"  Trap type1: {len(self.stats['trap_type1'])}")

        print("\n[3/8] Processing safe files (safe_type2)...")
        self.process_safe_files()
        print(f"  Safe type2: {len(self.stats['safe_type2'])}")

        print("\n[4/8] Generating safe_type1 files...")
        self.generate_safe_type1_files()
        print(f"  Safe type1: {len(self.stats['safe_type1'])}")

        print("\n[5/8] Generating new rule_16/rule_18 misuse cases...")
        self.generate_new_misuse_cases()
        n_gen_misuse = len([e for e in self.stats["misuse_cases"] if e["source"] == "generated_misuse"])
        print(f"  New misuse (rule 16/18): {n_gen_misuse}")

        print("\n[6/8] Generating import variant misuse cases...")
        self.generate_import_variants()
        n_import = len([e for e in self.stats["misuse_cases"] if e["source"] == "generated_import_variant"])
        print(f"  Import variants: {n_import}")

        print("\n[7/8] Generating metadata...")
        metadata = self.generate_metadata()
        print(f"  Total files: {metadata['total_files']}")

        print("\n[8/8] Generating README...")
        self.generate_readme(metadata)

        # Summary
        print(f"\n{'=' * 60}")
        print("Build complete!")
        print(f"Output: {self.output_dir}")
        for cat, entries in self.stats.items():
            print(f"  {cat}: {len(entries)}")
        total = sum(len(v) for v in self.stats.values())
        print(f"  TOTAL: {total}")
        return metadata


def main():
    parser = argparse.ArgumentParser(
        description="Build PyCryptoBench-LLM benchmark from PyCryptoBench source"
    )
    parser.add_argument(
        "--source-dir", type=Path, default=SOURCE_DIR,
        help="Path to original PyCryptoBench directory"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=OUTPUT_DIR,
        help="Path to output PyCryptoBench-LLM directory"
    )
    args = parser.parse_args()

    builder = BenchmarkBuilder(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
    )
    builder.run()


if __name__ == "__main__":
    main()
