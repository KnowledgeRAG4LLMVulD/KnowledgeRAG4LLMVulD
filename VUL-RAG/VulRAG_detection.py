import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from tqdm import tqdm
import os
from common import config as cfg
from common.util import common_util
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from common import constant
import logging
import argparse
from components.VulRAG import VulRAGDetector

def parse_command_line_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cwe-list', 
        nargs = '*', 
        type = str, 
        help = 'The list of CWEs to detect.',
        default = []
    )

    parser.add_argument(
        "--model-name",
        type = str,
        required = True,
        help = "The name of the model used for VUL-RAG detection.",
    )

    parser.add_argument(
        "--summary-model-name",
        type = str,
        default = cfg.DEFAULT_BEHAVIOR_SUMMARY_MODEL,
        help = "The name of the model used for summarize code purpose and function.",
    )

    parser.add_argument(
        '--model-settings',
        type = str,
        default = None,
        help = (
            'The settings of the model, format is a key-value pair separated by ";". '
            'e.g. "temperature=0.2;max_tokens=1024;stream=true"'
        )
    )

    parser.add_argument(
        '--retrieve_by_code', 
        action = 'store_true', 
        help = 'Whether to retrieve by code or not.'
    )

    parser.add_argument(
        '--retrieval_top_k',
        type = int,
        default = cfg.DEFAULT_RETRIEVAL_TOP_K,
        help = "The number of retrieval results to return."
    )

    parser.add_argument(
        '--resume',
        action = 'store_true',
        help = 'Whether to resume from a checkpoint.'
    )

    parser.add_argument(
        '--no-explanation',
        action = 'store_true',
        help = 'Use the prompt without explanation.'
    )

    args = parser.parse_args()

    if args.model_settings:
        args.model_settings_dict = common_util.parse_kv_string_to_dict(args.model_settings)
    else:
        args.model_settings_dict = {}
        args.model_settings = "default-settings"

    if args.retrieve_by_code:
        args.model_settings += "_retrieval_by_code"

    if args.no_explanation:
        args.model_settings += "_no_explanation"

    return args

if __name__ == '__main__':

    args = parse_command_line_arguments()
    result_dir_list = []

    for cwe_id in args.cwe_list:
        logging.info(f"Start detecting {cwe_id}...")

        knowledge_path = PathUtil.knowledge_extraction_output(
            constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                model_name = cfg.DEFAULT_BEHAVIOR_SUMMARY_MODEL,
                cwe_id = cwe_id
            ), "json"
        )
        VulD = VulRAGDetector(args.model_name, args.summary_model_name, knowledge_path)

        result_file_name = constant.VULRAG_DETECTION_RESULT_FILE_NAME.format(
            cwe_id = cwe_id, 
            model_name = args.model_name,
            summary_model_name = args.summary_model_name,
            model_settings = args.model_settings
        )
        checkpoint_path = PathUtil.checkpoint_data(result_file_name, "pkl")
        output_path = PathUtil.vul_detection_output(
            result_file_name,
            "json",
            args.model_name,
            args.summary_model_name,
            args.model_settings
        )

        result_dir_list.append(os.path.dirname(output_path))

        cve_list = []
        test_clean_data_path = PathUtil.test_data(constant.TEST_DATA_FILE_NAME.format(cwe_id = cwe_id), "json")
        test_clean_data = DataUtils.load_json(test_clean_data_path)
        for _, v in test_clean_data.items():
            cve_list.extend(v['item'])
        logging.info(f"Start detecting {len(cve_list)} samples for {cwe_id}...")

        vul_list = []
        non_vul_list = []
        ckpt_cve_list = []
        if args.resume:
            if os.path.exists(checkpoint_path):
                ckpt_cve_list = list(DataUtils.load_data_from_pickle_file(checkpoint_path))
                if os.path.exists(output_path):
                    data = DataUtils.load_json(output_path)
                    vul_list = data['vul_data']
                    non_vul_list = data['non_vul_data']
            else:
                # to avoid overwriting the existing output file
                raise FileNotFoundError(f"Checkpoint file {checkpoint_path} not found.")
        
        try:
            for cve_item in tqdm(cve_list):
                if cve_item['id'] in ckpt_cve_list:
                    continue
                if args.retrieve_by_code:
                    vul_detect_result = VulD.detect_pipeline_retrival_by_code(
                        cve_item['code_before_change'], 
                        cwe_id,
                        args.retrieval_top_k,
                        sample_id = cve_item['id'],
                        model_settings_dict = args.model_settings_dict,
                        cve_id = cve_item['cve_id']
                    )
                    non_vul_detect_result = VulD.detect_pipeline_retrival_by_code(
                        cve_item['code_after_change'],
                        cwe_id,
                        args.retrieval_top_k,
                        sample_id = cve_item['id'],
                        model_settings_dict = args.model_settings_dict,
                        cve_id = cve_item['cve_id']
                    )
                else:
                    vul_detect_result = VulD.detection_pipeline(
                        cve_item['code_before_change'],
                        "code_before_change",
                        cwe_id,
                        args.retrieval_top_k,
                        sample_id = cve_item['id'],
                        model_settings_dict = args.model_settings_dict,
                        cve_id = cve_item['cve_id'],
                        no_explanation = args.no_explanation
                    )
                    non_vul_detect_result = VulD.detection_pipeline(
                        cve_item['code_after_change'],
                        "code_after_change",
                        cwe_id,
                        args.retrieval_top_k,
                        sample_id = cve_item['id'],
                        model_settings_dict = args.model_settings_dict,
                        cve_id = cve_item['cve_id'],
                        no_explanation = args.no_explanation
                    )
                vul_list.append(vul_detect_result)
                non_vul_list.append(non_vul_detect_result)
                ckpt_cve_list.append(cve_item['id'])
                DataUtils.save_json(output_path, {"vul_data": vul_list, "non_vul_data": non_vul_list})

        except Exception as e:
            DataUtils.write_data_to_pickle_file(ckpt_cve_list, checkpoint_path)
            logging.error(f"CVE ID: {cve_item['cve_id']}")
            logging.error(f"Error: {e}")
            logging.error(f"Detection for {cwe_id} failed. Checkpoint saved.")

        else:
            if os.path.exists(checkpoint_path) and constant.ROOT_DIR in checkpoint_path:
                os.remove(checkpoint_path)
            logging.info(f"Detection for {cwe_id} finished.")
            DataUtils.save_json(output_path, {"vul_data": vul_list, "non_vul_data": non_vul_list})
            common_util.calculate_VD_metrics(output_path)

    logging.info(f"Detection for all CWEs finished.")
    result_dir_list = list(set(result_dir_list))
    assert len(result_dir_list) == 1
    for result_dir in result_dir_list:
        common_util.calculate_VD_metrics(result_dir)
    logging.info(f"Metrics calculation finished.")

# python VUL-RAG\VulRAG_detection.py --cwe-list CWE-119 --model-name qwen2.5-coder-32b-instruct --summary-model-name gpt-3.5-turbo