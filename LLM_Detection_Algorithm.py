import argparse
import json
import os
import csv
import re
import time
from datetime import datetime

import pandas as pd
import requests
import rule_source_py as ru
from pathlib import Path
from tqdm import tqdm
import random
import LLM_Cost_Statistics as lcs


def read_code_file(file_path: str) -> str:
    try:
        path = Path(file_path)
        if not path.is_file():
            raise ValueError("Path is not files")
        if path.suffix not in ['.py']:
            raise ValueError("Only support .py files")

        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # numbered_lines = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
        # content = ''.join(numbered_lines)

        content = ''.join(lines)

        return content

    except Exception as e:
        raise RuntimeError(f"Fail read files: {str(e)}")


def prepare_prompt(source_code: str, CoT: bool, custom_rules: str) -> list:
    rule_descriptions = []
    rule_groups = ru.rule_groups
    for i, rules in rule_groups.items():
        group_id, group_info = i, rules
        rule_desc = (
            f"Rule Number: {group_id}\n"
            f"Rule Name: {group_info.get('name', 'UNKNOW')} \n"
            f"Rule Description: {group_info.get('Message', 'UNKNOW')} \n"
            "------"
        )
        rule_descriptions.append(rule_desc)
    if custom_rules == '':
        rules_str = "\n".join(rule_descriptions)
    else:
        rules_str = custom_rules

    instruction = []

    if CoT:
        system_prompt = f"""
[Task Requirements]
You are a professional Python code security auditor. Strictly execute the [Detection Steps] to detect Cryptographic API misuse in the [Code to be Detected]. To ensure the interpretability of the detection results, please output your detection steps.

[Detection Steps]
[1] Analyze and understand the code semantics:
Analyze and understand the code semantics to ensure a correct understanding of the purpose of each code block. Distinguish between import module statements and main code (dynamic import modules are special cases and reside in the main code).

[2] Identify and locate import modules related to the [Misuse Rule List]:
Identify import module statements (including dynamic imports) that are related to the [Misuse Rule List]. Locate the usage of these modules in the main code, and record the rule numbers associated with the imported modules.

[3] Trace function calls, class instantiations, and variable/parameter transfers involving the modules identified in step [2]:
Trace function calls, class instantiations, and variable/parameter transfers involving the modules identified in step [2]. In practice, modules may receive variables and parameters, or may be passed as parameters to other functions or classes.

[4] Locate the rules recorded in Step [2]: 
Based on the rule numbers recorded in Step [2], locate the corresponding rule names and descriptions in the [Misuse Rule List]. Accurately understand the conditions for triggering cryptographic API misuse in these rules. For example, merely importing an insecure cryptographic API module does not constitute cryptographic API misuse, and using Pseudo Random Number Generator (PRNG) in a non-cryptographic scenario likewise does not constitute cryptographic API misuse.

[5] Draw conclusions:
Based on the above analysis steps, compare the rules recorded in step [4] with the Cryptographic API usage in the code to draw conclusions. Record the line numbers of misuse, the misused modules, and the corresponding rule numbers. 
If the main code does not use any relevant modules, must conclude that there is no misuse.

[6] Format and summarize the conclusions from step [5]:
Summarize the final conclusions from step [5] according to the [Detection Result Output Format].

[Detection Result Output Format]:
Misuse Line Numbers: (Example: 1,3,5. Output actual misuse line numbers. Only if the conclusion in step [5] is no misuse, output: None)
Misused Modules: (Separate multiple modules with '|'. Output the misused modules in the misuse lines. Only if the conclusion in step [5] is no misuse, output: UNKNOWN)
Rule Numbers: (Separate different misuse rules with '|'. Output the rule numbers corresponding to the misused modules. Only if the conclusion in step [5] is no misuse, output: -1)
Rule Names: (Separate multiple rule names with '|'. Output the rule names corresponding to the rule numbers. Only if the conclusion in step [5] is no misuse, output: UNKNOWN)
Placeholder Line: Please keep it.
            """
        instruction.append(system_prompt)

    else:
        system_prompt = f"""
[Task Requirements]
You are a professional Python code security auditor. Please analyze the [Code to be Detected] and evaluate the password API misuse in the code against the [Misuse Rule List].

[Detection Result Output Requirements]:
1. Misuse line numbers should be separated by commas ','.
2. Rule numbers and names must correspond to the misuse cases in the code at the respective misuse line numbers. If multiple misuse rules are violated, consolidate the output.
3. Different misuse rules should be separated by '|'; for misuse line numbers under the same misuse rule, continue to separate them with commas ','.
4. Strictly adhere to the [Detection Result Output Format] (retain the titles and the ':' after them).
5. After analyzing the [Code to be Detected], output the detection results according to the [Detection Result Output Format].

[Detection Result Output Format]:
Misuse Line Numbers: (Example: 1,3,5. Output actual misuse line numbers. Only if the detection conclusion is no misuse, output: None)
Misused Modules: (Separate multiple modules with '|'. Output the misused modules in the misuse lines. Only if the detection conclusion is no misuse, output: UNKNOWN)
Rule Numbers: (Separate different misuse rules with '|'. Output the rule numbers corresponding to the misused modules. Only if the detection conclusion is no misuse, output: -1)
Rule Names: (Separate multiple rule names with '|'. Output the rule names corresponding to the rule numbers. Only if the detection conclusion is no misuse, output: UNKNOWN)
Placeholder Line: Please keep it.
        """
        instruction.append(system_prompt)
    user_prompt = f'''
        [Code to be Detected]
        {source_code}
        [Misuse Rule List]
        {rules_str}
        '''
    instruction.append(user_prompt)

    return instruction


def parse_analysis_result(text: str, file_path: str) -> dict:
    result = {
        "file_path": '',
        "Misuse Line Numbers": '',
        "Rule Numbers": '',
        "Rule Names": '',
        "Misused Modules": ''
    }
    result["file_path"] = file_path
    patterns = [
        r'Misuse Line Numbers[:]\s*([^.\n]+?)\s*\n',
        r'Rule Numbers[:]\s*([\d\s,\|\-]+)\n',
        r'Rule Names[:]\s*([^.\n]+?)\s*\n',
        r'Misused Modules[:]\s*([^\n]+?)\s*\n'
    ]

    match1 = re.search(patterns[0], text)
    if match1:
        result['Misuse Line Numbers'] = f"\t{match1.group(1)}"
    match2 = re.search(patterns[1], text)
    if match2:
        result['Rule Numbers'] = f"\t{match2.group(1)}"
    match3 = re.search(patterns[2], text)
    if match3:
        result['Rule Names'] = f"\t{match3.group(1)}"
    match4 = re.search(patterns[3], text)
    if match4:
        result['Misused Modules'] = f"\t{match4.group(1)}"

    return result


def analyze_with_llm(prompt: list, model_name: str, API_Key: str, API_Url: str, timeout: int = 60):
    """
    Use LLMs by API
    Suggest LLMs：
    SiliconFlow：THUDM/GLM-4-32B-0414
    OpenAI：GPT4.1、GPT4
    """
    endpoint = API_Url  # siliconflow request adress
    headers = {
        "Authorization": f"Bearer {API_Key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": prompt[0]},
            {"role": "user", "content": prompt[1]}
        ],
        "temperature": 0,
        # "enable_thinking": True
        "enable_thinking": False
    }

    max_retries = 10
    base_delay = 1
    retry_count = 0

    while retry_count <= max_retries:
        try:
            start_time = time.time()
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            result = response.json()

            # print("模型响应：", result)

            # 提取模型生成的文本内容
            content_str = result['choices'][0]['message'].get('content', '')

            if '```json' in content_str:
                json_part = content_str.split('```json')[1].split('```')[0].strip()
                cleaned_json = json_part.replace('"', '').replace('{', '').replace('}', '').replace('*', '').replace(
                    '#', '')
            else:
                cleaned_json = content_str.replace('"', '').replace('{', '').replace('}', '').replace('*', '').replace(
                    '#', '').replace('```', '').replace('‘’‘', '').replace('[', '').replace(']', '')

            final_output = cleaned_json

            detection_time = round(time.time() - start_time, 2)

            # 提取Token使用量 - 支持多种API响应格式
            token_usage = {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0
            }

            # 检查是否为Ollama API响应格式
            if 'prompt_eval_count' in result:
                # Ollama格式: prompt_eval_count 和 eval_count
                token_usage["input_tokens"] = result.get('prompt_eval_count', 0)
                token_usage["output_tokens"] = result.get('eval_count', 0)
                token_usage["total_tokens"] = token_usage["input_tokens"] + token_usage["output_tokens"]
            elif 'usage' in result:
                # OpenAI兼容格式: usage字段
                usage = result.get('usage', {})
                token_usage["input_tokens"] = usage.get('prompt_tokens', 0)
                token_usage["output_tokens"] = usage.get('completion_tokens', 0)
                token_usage["total_tokens"] = usage.get('total_tokens', 0)
            elif 'prompt_tokens' in result:
                # 其他可能的API格式
                token_usage["input_tokens"] = result.get('prompt_tokens', 0)
                token_usage["output_tokens"] = result.get('completion_tokens', result.get('generated_tokens', 0))
                token_usage["total_tokens"] = result.get('total_tokens',
                                                         token_usage["input_tokens"] + token_usage["output_tokens"])

            return final_output, token_usage, detection_time

        except requests.exceptions.Timeout as e:
            retry_count += 1
            if retry_count > max_retries:
                raise RuntimeError(f"API timeout after {max_retries} retries: {str(e)}")

            # 超时后等待5秒再重试
            wait_time = (2 ** retry_count) * base_delay + random.uniform(0, 0.5)
            print(f"⚠️ Request timeout, {retry_count}/{max_retries} times retry，waiting {wait_time:.2f} seconds...")
            time.sleep(wait_time)
            continue

        except requests.exceptions.ConnectionError as e:
            retry_count += 1
            if retry_count > max_retries:
                raise RuntimeError(f"API connection error after {max_retries} retries: {str(e)}")
            wait_time = (2 ** retry_count) * base_delay + random.uniform(0, 0.5)
            print(f"⚠️ Connection error, {retry_count}/{max_retries} retry, waiting {wait_time:.2f} seconds...")
            time.sleep(wait_time)
            continue

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                retry_count += 1
                retry_after = e.response.headers.get('Retry-After')
                if retry_after and retry_after.isdigit():
                    wait_time = int(retry_after)
                else:
                    wait_time = (4 ** retry_count) * base_delay + random.uniform(0, 0.5)
                print(
                    f"⚠️ Triggle speed limit(429), {retry_count}/{max_retries} times retry，waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                if retry_count > max_retries:
                    raise RuntimeError(f"API error: retry invalid")

            else:
                error_msg = f"HTTP error {e.response.status_code}"
                if e.response.status_code == 401:
                    error_msg += " | API Key invalid"
                raise RuntimeError(f"API error: {error_msg}")

        except Exception as e:
            raise RuntimeError(f"Fail use LLMs: {str(e)}")


def process_single_file(file_path: Path, model_name: str, API_Key: str, API_Url: str, CoT: bool,
                        custom_rules: str) -> dict:
    """process single files and return a dict result"""
    try:
        code_content = read_code_file(str(file_path))
        prompt = prepare_prompt(code_content, CoT, custom_rules)
        raw_result, token_usage, detection_time = analyze_with_llm(prompt, model_name, API_Key, API_Url)
        result = parse_analysis_result(raw_result, str(file_path))
        result["Detection Time/s"] = detection_time
        # 添加Token消耗信息
        result["Input_Tokens"] = f"{token_usage['input_tokens']}"
        result["Output_Tokens"] = f"{token_usage['output_tokens']}"
        result["Total_Tokens"] = f"{token_usage['total_tokens']}"
        return result
    except Exception as e:
        return {
            "file_path": file_path,
            "Misuse Line Numbers": 'miss',
            "Rule Numbers": 'miss',
            "Rule Names": 'miss',
            "Misused Modules": str(e),
            "Detection Time/s": '0.01',
            "Input_Tokens": f"Error: {str(e)}"
        }


def save_to_csv(results: list[dict], output_path: str):
    """save structure result to CSV"""
    fieldnames = ["file_path", "Misuse Line Numbers", "Rule Numbers", "Rule Names", "Misused Modules", "Detection Time/s", "Input_Tokens", 'Output_Tokens', 'Total_Tokens']

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def batch_analyze(folder_path: str, model_name: str, API_Key: str, API_Url: str, CoT: bool, custom_rules: str):
    py_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".py"):
                py_files.append(Path(root) / file)
    if not py_files:
        raise ValueError("No Found .py files")
    code_files = py_files
    results = []
    progress_bar = tqdm(code_files, desc="analyze progress", unit="file")
    for file_path in progress_bar:
        start_time = time.time()
        progress_bar.set_postfix({"current file": file_path.name})
        try:
            file_results = process_single_file(
                file_path=file_path,
                model_name=model_name,
                API_Key=API_Key,
                API_Url=API_Url,
                CoT=CoT,
                custom_rules=custom_rules
            )
        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            error_result = {
                "file_path": file_path,
                "Misuse Line Numbers": 'miss',
                "Rule Numbers": 'miss',
                "Rule Names": 'miss',
                "Misused Modules": str(e),
                "Detection Time/s": f"{elapsed}",
                "Token consumption": f"Error: {str(e)}"
            }
            file_results = error_result
        results.append(file_results)
    # Save result to CSV
    timestamp = datetime.now().strftime("%H%M%S")
    if CoT:
        if ':' in model_name:
            output_csv = Path(folder_path) / f"analysis_result_by_{model_name.replace(':', '_')}-withCoT_{timestamp}.csv"
        else:
            output_csv = Path(folder_path) / f"analysis_result_by_{model_name.replace('/', '_')}-withCoT_{timestamp}.csv"
    else:
        if ':' in model_name:
            output_csv = Path(folder_path) / f"analysis_result_by_{model_name.replace(':', '_')}-withoutCoT_{timestamp}.csv"
        else:
            output_csv = Path(folder_path) / f"analysis_result_by_{model_name.replace('/', '_')}-withoutCoT_{timestamp}.csv"

    save_to_csv(results, str(output_csv))

    return output_csv


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LLM-based Cryptographic API Misuse Detection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # folder_path = './PyCryptoBench-LLM-simple'
    folder_path = './PyCryptoBench'
    # folder_path = './small_test'
    # folder_path = './small_test2'

    # model_name = 'Pro/zai-org/GLM-5'
    # model_name = 'Pro/zai-org/GLM-5.1'
    model_name = 'Pro/moonshotai/Kimi-K2.6'
    # model_name = 'deepseek-ai/DeepSeek-V4-Flash'
    # model_name = 'Qwen/Qwen3.5-35B-A3B'
    # model_name = 'Qwen/Qwen3.5-27B'
    # model_name = 'Qwen/Qwen3-Coder-30B-A3B-Instruct'

    API_Key = 'sk-cvjjwtyuumoakjnidraimcdlxnmcrxifzpdnshjgtqofefgs'
    API_Url = 'https://api.siliconflow.cn/v1/chat/completions'

    # # model_name = 'qwen3-next:80b-cloud'
    # model_name = 'qwen3-coder-next:cloud'
    # API_Key = os.environ.get('OLLAMA_API_KEY')
    # API_Url = "http://localhost:11434/v1/chat/completions"

    # model_name = 'qwen3-next-80b-a3b-instruct'
    # # model_name = 'qwen3-coder-next'
    # API_Key = 'sk-bb641b50f491432cbc41e90bf1b1a4b4'
    # API_Url = 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions'

    # cot = False
    cot = True
    custom_rules = ''
    csv_file = batch_analyze(folder_path, model_name, API_Key, API_Url, cot, custom_rules)
    print(f"\n Analysis has been completed！Results save to：{csv_file} \n\n")
    try:
        stats_with_cost = lcs.calculate_cost_statistics(csv_file, model_name)

        print("\n=== LLM Detection Cost Statistics ===\n")

        print(f"Total detection time: {stats_with_cost['total_detection_time']:.2f} (seconds)\n")

        print(f"Total tokens: {stats_with_cost['total_tokens']}")
        print(f"    Total input tokens: {stats_with_cost['total_input_tokens']}")
        print(f"    Total output tokens: {stats_with_cost['total_output_tokens']}\n")

        print(f"Total cost: {stats_with_cost['total_cost']:.3f} (¥)")
        print(f"  input cost: {stats_with_cost['input_cost']:.3f} (¥)")
        print(f"  output cost: {stats_with_cost['output_cost']:.3f} (¥)\n")

        df = pd.read_csv(csv_file, encoding='utf-8-sig')
        avg_detection_time = stats_with_cost['total_detection_time'] / len(df)
        avg_input_per_file = stats_with_cost['total_input_tokens'] / len(df)
        avg_output_per_file = stats_with_cost['total_output_tokens'] / len(df)
        avg_token_per_file = stats_with_cost['total_tokens'] / len(df)

        print(f"Average detection time per file: {avg_detection_time:.2f} (seconds)")
        print(f"Average tokens cost per file: {avg_token_per_file:.0f}")
        print(f"    Average input tokens per file: {avg_input_per_file:.0f}")
        print(f"    Average output tokens per file: {avg_output_per_file:.0f}")

        # LLM Detection Report
        mn = model_name.replace('/', '_').replace(':', '_')
        if cot:
            report_file = os.path.join(folder_path, f'{mn}_withCoT_Detection_log.txt')
        else:
            report_file = os.path.join(folder_path, f'{mn}_withoutCoT_Detection_log.txt')
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("LLM Detection Log:\n\n")
            f.write("-" * 50 + "\n\n")
            f.write("LLM Detection Cost Statistics: \n")
            f.write(f"      Total detection time: {stats_with_cost['total_detection_time']:.2f} (seconds)\n")
            f.write(f"      Total tokens: {stats_with_cost['total_tokens']}\n")
            f.write(f"          Total input tokens: {stats_with_cost['total_input_tokens']}\n")
            f.write(f"          Total output tokens: {stats_with_cost['total_output_tokens']}\n")
            f.write(f"      Total cost: {stats_with_cost['total_cost']:.3f} (¥)\n")
            f.write(f"          input cost: {stats_with_cost['input_cost']:.3f} (¥)\n")
            f.write(f"          output cost: {stats_with_cost['output_cost']:.3f} (¥)\n")
            f.write(f"      Average detection time per file: {avg_detection_time:.2f} (seconds)\n")
            f.write(f"      Average tokens cost per file: {avg_token_per_file:.0f}\n")
            f.write(f"          Average input tokens per file: {avg_input_per_file:.0f}\n")
            f.write(f"          Average output tokens per file: {avg_output_per_file:.0f}\n")
            f.write("-" * 50 + "\n")

        print(f"📝 LLM Detection Report Successfully Save to: {report_file}")

    except FileNotFoundError:
        print(f"Error: UNFOUNDED '{csv_file}'")
    except Exception as e:
        print(f"Error occurred while processing the csv file: {e}")

    # model_name = 'qwen3-next-80b-a3b-instruct'
    # # model_name = 'qwen3-30b-a3b-instruct-2507'
    # # model_name = 'qwen3-coder-30b-a3b-instruct'
    # API_Key = 'sk-bb641b50f491432cbc41e90bf1b1a4b4'
    # API_Url = 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions'

    # # model_name = 'Pro/zai-org/GLM-5'
    # model_name = 'Qwen/Qwen3.5-35B-A3B'
    #
    # API_Key = 'sk-cvjjwtyuumoakjnidraimcdlxnmcrxifzpdnshjgtqofefgs'
    # API_Url = 'https://api.siliconflow.cn/v1/chat/completions'
    #
    # file_path = './PyCryptoBench-LLM-simple/trap_type1\Trap_Import_md5_rule_11_trapfile_9.py'
    # # file_path = './PyCryptoBench-LLM-simple/trap_type2\Trap_rule_16_Interprocedural_1.py'
    # # file_path = './PyCryptoBench-LLM-simple/trap_type2\Trap_rule_16_Path-Sensitive_0.py'
    # # file_path = './PyCryptoBench-LLM-simple/trap_type2\Trap_rule_16_Global_0.py'
    #
    # # file_path = './motivating_study_v3/bucket1_50/rule_06_insecure_0_B.py'
    #
    # code_content = read_code_file(str(file_path))
    # code_type = 'py'
    # cot = True
    # # cot = False
    # custom_rules = ''
    # print(code_content)
    # prompt = prepare_prompt(code_content, cot, custom_rules)  # 传入rule_groups
    # # print(rule_groups)
    # print(prompt[0])
    # print(prompt[1])
    # text, token_usage, detection_time = analyze_with_llm(prompt, model_name, API_Key, API_Url)
    #
    # print("*" * 10)
    # print(text)
    #
    # fd = parse_analysis_result(text, file_path)
    # print(fd)
    # print(token_usage)
    #
    # minutes = int(detection_time // 60)
    # seconds = detection_time % 60
    #
    # if minutes > 0:
    #     print(f"Detection Time: {minutes}分{seconds:.2f}秒")
    # else:
    #     print(f"Detection Time: {seconds:.2f}秒")