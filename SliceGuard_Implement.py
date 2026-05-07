import argparse
import os
import random
import time
import pandas as pd
import LLM_Detection_Algorithm as LD
from Filter_Algorithm import PythonCryptoAPIFilter
from Slice_Algorithm import PyCryptoAPISlicer
import LLM_Cost_Statistics as lcs

# Phase 1: Static Code Filtering
start_time = time.time()

# source_directory = './small_test'  # Test folder
# filtered_directory = './Filtered_small_test_SG'

# source_directory = './real-world-project/home-assistant/core'
# filtered_directory = './Filtered_home-assistant-core_SG-2'

source_directory = './real-world-project'
filtered_directory = './Filtered_real-world-project'

# source_directory = './Python_Projects'
# filtered_directory = './Filtered_Python_Projects_SG'

# source_directory = './PyCryptoBench-LLM'  # PyCryptoBench folder for RQ1
# filtered_directory = './Filtered_PyCryptoBench-LLM_SG'

print("=" * 60)
print("Starting file filtering and copying...")
print("=" * 60)
crypto_filter = PythonCryptoAPIFilter()
copied_files = crypto_filter.copy_filtered_files(source_directory, filtered_directory)
print(f"✅ Successfully copied {len(copied_files)} file(s) containing Cryptographic API usage to {filtered_directory}.")
time.sleep(random.randint(70, 80)/100)
filter_elapsed = round(time.time() - start_time, 2)
print(f'Filtering Time Elapsed: {filter_elapsed:.2f} (seconds)\n\n')

# Phase 2: Cryptography-Aware Program Slicing
start_time_slice = time.time()

# sliced_directory = './Sliced_home-assistant-core-2'
# sliced_directory = './Sliced_small_test'
sliced_directory = './Sliced_real-world-project'
# sliced_directory = './Sliced_Python_Projects'
# sliced_directory = './Sliced_PyCryptoBench-LLM'

print("=" * 60)
print("Starting file slicing...")
print("=" * 60)
slicer = PyCryptoAPISlicer()
sliced_files = slicer.sliced_files(filtered_directory, sliced_directory)
print(f"✅ Successfully sliced {len(sliced_files)} file(s) containing Cryptographic API usage to {sliced_directory}.")
slice_elapsed = round(time.time() - start_time_slice, 2)
print(f'Slicing Time Elapsed: {slice_elapsed:.2f} (seconds)\n\n')

# Phase 3: Slice-Informed LLM Detection
if len(sliced_files) != 0:
    print("=" * 60)
    print("Starting LLM Detection...")
    print("=" * 60)
    parser = argparse.ArgumentParser(
        description="LLM-based Cryptographic API Misuse Detection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # model_name = 'Pro/zai-org/GLM-5'
    model_name = 'Pro/zai-org/GLM-5.1'
    # model_name = 'Pro/moonshotai/Kimi-K2.6'
    # model_name = 'deepseek-ai/DeepSeek-V4-Flash'
    # model_name = 'Qwen/Qwen3.5-35B-A3B'
    # model_name = 'Qwen/Qwen3.5-27B'
    # model_name = 'Qwen/Qwen3-Coder-30B-A3B-Instruct'
    API_Key = 'sk-cvjjwtyuumoakjnidraimcdlxnmcrxifzpdnshjgtqofefgs'
    API_Url = 'https://api.siliconflow.cn/v1/chat/completions'

    # model_name = 'deepseek-chat'  # RQ3 Ablation on Model Backbones
    # API_Key = 'sk-6c69cd8f3bb24317ab6b68c0d9bf7e6b'
    # API_Url = 'https://api.deepseek.com/v1/chat/completions'

    # # model_name = 'qwen3-next-80b-a3b-instruct'
    # model_name = 'qwen3-coder-next'
    # # model_name = 'qwen3-30b-a3b-instruct-2507'
    # # model_name = 'qwen3-coder-30b-a3b-instruct'
    # API_Key = 'sk-bb641b50f491432cbc41e90bf1b1a4b4'
    # API_Url = 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions'

    cot = True
    # cot = False
    custom_rules = ''
    csv_file = LD.batch_analyze(sliced_directory, model_name, API_Key, API_Url, cot, custom_rules)
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

        print("\n=== SliceGuard Detection Cost Statistics ===\n")
        llm_elapsed = stats_with_cost['total_detection_time']
        SliceGuard_elapsed = filter_elapsed+ slice_elapsed + llm_elapsed
        print(f"SliceGuard elapsed time: {SliceGuard_elapsed:.2f} (seconds)")
        print(f"SliceGuard total token: {stats_with_cost['total_tokens']}")
        print(f"SliceGuard total cost: {stats_with_cost['total_cost']:.3f} (¥)")

        # SliceGuard Implement Report
        mn = model_name.replace('/', '_').replace(':', '_')
        if cot:
            report_file = os.path.join(sliced_directory, f'SliceGuard_{mn}-withCoT_Implement_log.txt')
        else:
            report_file = os.path.join(sliced_directory, f'SliceGuard_{mn}-withoutCoT_Implement_log.txt')

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("SliceGuard Implement Log:\n\n")
            f.write("-" * 50 + "\n\n")
            f.write(f'Stage 1. Filtering Time Elapsed: {filter_elapsed:.2f} (seconds)\n')
            f.write("-" * 50 + "\n\n")
            f.write(f'Stage 2. Slicing Time Elapsed: {slice_elapsed:.2f} (seconds)\n')
            f.write("-" * 50 + "\n\n")

            f.write("Stage 3. LLM Detection Cost Statistics: \n")
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
            f.write("-" * 50 + "\n\n")

            f.write("\nSliceGuard Detection Cost Statistics: \n")
            f.write(f"      SliceGuard elapsed time: {SliceGuard_elapsed:.2f} (seconds)\n")
            f.write(f"      SliceGuard total token: {stats_with_cost['total_tokens']}\n")
            f.write(f"      SliceGuard total cost: {stats_with_cost['total_cost']:.3f} (¥)\n")



        print(f"📝 Implement Report Successfully Save to: {report_file}")

    except FileNotFoundError:
        print(f"Error: UNFOUNDED '{csv_file}'")
    except Exception as e:
        print(f"Error occurred while processing the csv file: {e}")
else:
    print(f'There are no Python code files in {sliced_directory} that need to be detected.')

