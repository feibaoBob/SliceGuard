#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统计指定文件夹中所有Python代码行数总和
直接运行，粘贴文件夹路径即可
"""

import os
from pathlib import Path

# ============================================================
#   在这里粘贴你要统计的文件夹路径
# ============================================================
TARGET_DIR = r"./real-world-project"
# TARGET_DIR = r"./Filtered_real-world-project"
# TARGET_DIR = r"./Sliced_real-world-project"
# ============================================================

IGNORE_DIRS = {'__pycache__', '.git', '.idea', 'venv', 'env', 'node_modules'}


def count_python_lines(directory: str) -> None:
    directory = Path(directory)
    if not directory.exists():
        print(f"目录不存在: {directory}")
        return

    total_lines = 0
    total_files = 0
    file_details = []

    for py_file in directory.rglob('*.py'):
        if IGNORE_DIRS & set(py_file.parts):
            continue
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                lines = len(f.readlines())
                total_lines += lines
                total_files += 1
                file_details.append((str(py_file.relative_to(directory)), lines))
        except Exception as e:
            print(f"无法读取文件 {py_file}: {e}")

    file_details.sort(key=lambda x: x[1], reverse=True)

    print(f"\n{'='*60}")
    print(f"目录: {directory.resolve()}")
    print(f"Python文件数: {total_files}")
    print(f"总行数: {total_lines}")
    if total_files > 0:
        print(f"平均每文件: {total_lines / total_files:.1f} 行")

    print(f"\n--- 行数最多的前10个文件 ---")
    for i, (path, lines) in enumerate(file_details[:10], 1):
        print(f"{i:3d}. {lines:6d} 行 | {path}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    target = TARGET_DIR.strip()
    if not target:
        target = input("请粘贴要统计的文件夹路径: ").strip().strip('"').strip("'")
    count_python_lines(target)
