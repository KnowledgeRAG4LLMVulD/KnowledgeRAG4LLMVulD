#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
from pathlib import Path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from common.constant import DATA_DIR, OUTPUT_DIR, LOGS_DIR, COMMON_DIR


class PathUtil:
    @staticmethod
    def orig_data_dir():
        path = Path(DATA_DIR) / 'orig_data'
        path.mkdir(parents = True, exist_ok = True)
        return str(path)

    @staticmethod
    def orig_data(filename: str, ext: str):
        path = Path(DATA_DIR) / 'orig_data'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def processed_data_dir():
        path = Path(DATA_DIR) / 'processed_data'
        path.mkdir(parents = True, exist_ok = True)
        return str(path)

    @staticmethod
    def processed_data(filename: str, ext: str):
        path = Path(DATA_DIR) / 'processed_data'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def fina_data_dir():
        path = Path(DATA_DIR) / 'final_data'
        path.mkdir(parents = True, exist_ok = True)
        return str(path)

    @staticmethod
    def final_data(filename: str, ext: str):
        path = Path(DATA_DIR) / 'final_data'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def test_data(filename: str, ext: str):
        path = Path(DATA_DIR) / 'testset'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def clean_data(filename: str, ext: str):
        path = Path(DATA_DIR) / 'clean_data'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def output_models(model_name: str):
        path = Path(OUTPUT_DIR) / 'model'
        path.mkdir(parents = True, exist_ok = True)
        path = path / model_name
        return str(path)

    @staticmethod
    def output(filename: str, ext: str):
        path = Path(OUTPUT_DIR)
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def log_file_name_with_current_time():
        path = Path(LOGS_DIR)
        path.mkdir(parents = True, exist_ok = True)
        path = path / '{}.log'.format(time.strftime("%Y%m%d%H", time.localtime()))
        return str(path)

    @staticmethod
    def knowledge_extraction_output(filename: str, ext: str):
        path = Path(OUTPUT_DIR) / 'vul_knowledge_data'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def vul_detection_output(
        filename: str,
        ext: str,
        detection_model_name: str,
        summary_model_name: str,
        model_settings: str
    ):
        path = (
            Path(OUTPUT_DIR) / 'vul_detection_data' /
            f"{detection_model_name}_{summary_model_name}" /
            model_settings
        )
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)

    @staticmethod
    def vul_detection_baseline_output(
        filename: str,
        ext: str,
        model_name: str = None,
        baseline_settings: str = None
    ):
        path = Path(OUTPUT_DIR) / 'vul_detection_baseline_data'
        path.mkdir(parents = True, exist_ok = True)
        if model_name:
            path = path / model_name
            path.mkdir(parents = True, exist_ok = True)
            if baseline_settings:
                path = path / baseline_settings
                path.mkdir(parents = True, exist_ok = True)

        elif baseline_settings:
            raise ValueError("Please provide model_name along with baseline_settings")

        path = path / f'{filename}.{ext}'
        return str(path)
    
    @staticmethod
    def api_keys_data(filename: str, ext: str):
        path = Path(COMMON_DIR) / 'api_keys'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)
    
    @staticmethod
    def checkpoint_data(filename: str, ext: str):
        path = Path(DATA_DIR) / 'checkpoint'
        path.mkdir(parents = True, exist_ok = True)
        path = path / f'{filename}.{ext}'
        return str(path)
   
    @staticmethod
    def check_file_exists(filename:str):
        path = Path(filename)
        return path.exists()
    
