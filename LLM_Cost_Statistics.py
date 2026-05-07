import os

import pandas as pd

def calculate_cost_statistics(file_path, model):
    # 读取CSV文件
    df = pd.read_csv(file_path, encoding='utf-8-sig')

    # 计算各列总和
    total_detection_time = df['Detection Time/s'].sum()
    total_input_tokens = df['Input_Tokens'].sum()
    total_output_tokens = df['Output_Tokens'].sum()
    total_tokens = df['Total_Tokens'].sum()

    # # 检查Token总量是否等于输入+输出
    # if total_tokens == (total_input_tokens + total_output_tokens):
    #     print("✓ Token总量验证: 输入+输出 = 总Token (数据一致)")
    # else:
    #     print(f"⚠ Token总量验证: 输入+输出({total_input_tokens + total_output_tokens}) ≠ 总Token({total_tokens})")

    Token_price = {
        'deepseek-chat': {'input': 2, 'output': 3},
        'deepseek-ai/DeepSeek-V3.2': {'input': 2, 'output': 3},
        'qwen3-next-80b-a3b-instruct': {'input': 1, 'output': 4},
        'Pro/zai-org/GLM-5': {'input': 4, 'output': 18},
        'Pro/zai-org/GLM-5.1': {'input': 6, 'output': 24},
        'deepseek-ai/DeepSeek-V4-Flash': {'input': 1, 'output': 2},
        'Qwen/Qwen3-Next-80B-A3B-Instruct': {'input': 1, 'output': 4},
        'Qwen/Qwen3.5-35B-A3B': {'input': 0.4, 'output': 3.2},
        'Qwen/Qwen3.5-27B': {'input': 0.6, 'output': 4.8},
        'Qwen/Qwen3-Coder-30B-A3B-Instruct': {'input': 1.5, 'output': 6},
        'qwen3-coder-next': {'input': 1, 'output': 4},
        'qwen3-30b-a3b-instruct-2507': {'input': 0.75, 'output': 3},
        'qwen3-coder-30b-a3b-instruct': {'input': 1.5, 'output': 6},
        'qwen3-235b-a22b-instruct-2507': {'input': 2, 'output': 8},
        'Qwen/Qwen3-235B-A22B-Instruct-2507': {'input': 2, 'output': 8},
        'qwen3-coder-480b-a35b-instruct': {'input': 6, 'output': 24},
        'Qwen/Qwen3-Coder-480B-A35B-Instruct': {'input': 6, 'output': 24},
        'Pro/moonshotai/Kimi-K2.5': {'input': 4, 'output': 21},
        'Pro/moonshotai/Kimi-K2.6': {'input': 6.5, 'output': 27},
    }  # 模型Token价格，数据来源：https://bailian.console.aliyun.com/cn-beijing/?tab=doc#/doc/?type=model&url=2840914
    input_price_per_1M = Token_price[model]['input']  # 每百万token的输入价格（RMB）
    output_price_per_1M = Token_price[model]['output']  # 每百万token的输出价格（RMB）

    # 转换为每token价格
    input_price_per_token = input_price_per_1M / 1_000_000
    output_price_per_token = output_price_per_1M / 1_000_000

    input_cost = input_price_per_token * total_input_tokens
    output_cost = output_price_per_token * total_output_tokens
    total_cost = input_cost + output_cost

    return {
        'total_detection_time': total_detection_time,
        'total_input_tokens': total_input_tokens,
        'total_output_tokens': total_output_tokens,
        'total_tokens': total_tokens,
        'input_cost': input_cost,
        'output_cost': output_cost,
        'total_cost': total_cost
    }



# 使用示例
if __name__ == "__main__":
    # 指定CSV文件路径
    csv_file = "./Filtered_PyCryptoBench/analysis_result_by_Qwen_Qwen3-Next-80B-A3B-Instruct-withCoT_095405.csv"
    # model_name = 'qwen3-next-80b-a3b-instruct'
    model_name = 'Qwen/Qwen3-Next-80B-A3B-Instruct'
    cot = True
    filter_elapsed = 1.76
    output_directory = './Filtered_PyCryptoBench'
    # folder_path = './PyCryptoBench'

    try:
        stats_with_cost = calculate_cost_statistics(csv_file, model_name)

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

        print("\n=== FALD Detection Cost Statistics ===\n")
        llm_elapsed = stats_with_cost['total_detection_time']
        fald_elapsed = filter_elapsed + llm_elapsed
        print(f"FALD elapsed time: {fald_elapsed:.2f} (seconds)")
        print(f"FALD total token: {stats_with_cost['total_tokens']}")
        print(f"FALD total cost: {stats_with_cost['total_cost']:.3f} (¥)")

        # FALD Implement Report
        mn = model_name.replace('/', '_').replace(':', '_')
        if cot:
            report_file = os.path.join(output_directory, f'FALD_{mn}-withCoT_Implement_log.txt')
        else:
            report_file = os.path.join(output_directory, f'FALD_{mn}-withoutCoT_Implement_log.txt')

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("Filter-Augmented LLM Detector Implement Log:\n\n")
            f.write("-" * 50 + "\n\n")
            f.write(f'Stage 1. Filtering Time Elapsed: {filter_elapsed:.2f} (seconds)\n')
            f.write("-" * 50 + "\n\n")

            f.write("Stage 2. LLM Detection Cost Statistics: \n")
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

            f.write("\nFALD Detection Cost Statistics: \n")
            f.write(f"      FALD elapsed time: {fald_elapsed:.2f} (seconds)\n")
            f.write(f"      FALD total token: {stats_with_cost['total_tokens']}\n")
            f.write(f"      FALD total cost: {stats_with_cost['total_cost']:.3f} (¥)\n")

        print(f"📝 Implement Report Successfully Save to: {report_file}")

    except FileNotFoundError:
        print(f"Error: UNFOUNDED '{csv_file}'")
    except Exception as e:
        print(f"Error occurred while processing the csv file: {e}")

    # try:
    #     stats_with_cost = calculate_cost_statistics(csv_file, model_name)
    #
    #     print("\n=== LLM Detection Cost Statistics ===\n")
    #
    #     print(f"Total detection time: {stats_with_cost['total_detection_time']} (seconds)\n")
    #
    #     print(f"Total tokens: {stats_with_cost['total_tokens']}")
    #     print(f"    Total input tokens: {stats_with_cost['total_input_tokens']}")
    #     print(f"    Total output tokens: {stats_with_cost['total_output_tokens']}\n")
    #
    #     print(f"Total cost: {stats_with_cost['total_cost']:.3f} (¥)")
    #     print(f"  input cost: {stats_with_cost['input_cost']:.3f} (¥)")
    #     print(f"  output cost: {stats_with_cost['output_cost']:.3f} (¥)\n")
    #
    #     df = pd.read_csv(csv_file, encoding='utf-8-sig')
    #     avg_detection_time = stats_with_cost['total_detection_time'] / len(df)
    #     avg_input_per_file = stats_with_cost['total_input_tokens'] / len(df)
    #     avg_output_per_file = stats_with_cost['total_output_tokens'] / len(df)
    #     avg_token_per_file = stats_with_cost['total_tokens'] / len(df)
    #
    #     print(f"Average detection time per file: {avg_detection_time:.2f} (seconds)")
    #     print(f"Average tokens cost per file: {avg_token_per_file:.0f}")
    #     print(f"    Average input tokens per file: {avg_input_per_file:.0f}")
    #     print(f"    Average output tokens per file: {avg_output_per_file:.0f}")
    #
    #     # LLM Detection Report
    #     mn = model_name.replace('/', '_').replace(':', '_')
    #     if cot:
    #         report_file = os.path.join(folder_path, f'{mn}_withCoT_Detection_log.txt')
    #     else:
    #         report_file = os.path.join(folder_path, f'{mn}_withoutCoT_Detection_log.txt')
    #     with open(report_file, 'w', encoding='utf-8') as f:
    #         f.write("LLM Detection Log:\n\n")
    #         f.write("-" * 50 + "\n\n")
    #         f.write("LLM Detection Cost Statistics: \n")
    #         f.write(f"      Total detection time: {stats_with_cost['total_detection_time']:.2f} (seconds)\n")
    #         f.write(f"      Total tokens: {stats_with_cost['total_tokens']}\n")
    #         f.write(f"          Total input tokens: {stats_with_cost['total_input_tokens']}\n")
    #         f.write(f"          Total output tokens: {stats_with_cost['total_output_tokens']}\n")
    #         f.write(f"      Total cost: {stats_with_cost['total_cost']:.3f} (¥)\n")
    #         f.write(f"          input cost: {stats_with_cost['input_cost']:.3f} (¥)\n")
    #         f.write(f"          output cost: {stats_with_cost['output_cost']:.3f} (¥)\n")
    #         f.write(f"      Average detection time per file: {avg_detection_time:.2f} (seconds)\n")
    #         f.write(f"      Average tokens cost per file: {avg_token_per_file:.0f}\n")
    #         f.write(f"          Average input tokens per file: {avg_input_per_file:.0f}\n")
    #         f.write(f"          Average output tokens per file: {avg_output_per_file:.0f}\n")
    #         f.write("-" * 50 + "\n")
    #
    #
    #     print(f"📝 LLM Detection Report Successfully Save to: {report_file}")
    #
    # except FileNotFoundError:
    #     print(f"Error: UNFOUNDED '{csv_file}'")
    # except Exception as e:
    #     print(f"Error occurred while processing the csv file: {e}")