import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from common.util import common_util
from common import constant
from tqdm import tqdm
from common import common_prompt
import argparse
import logging
from common.model_manager import ModelManager

def convert_detection_result_to_number(detection_result: str) -> int:
    """
    Converts a detection result string to a numerical value.

    Args:
        detection_result (str): The detection result string, expected to contain "YES" or "NO".

    Returns:
        int: Returns 1 if "YES" is in the detection result and "NO" is not.
             Returns 0 if "NO" is in the detection result and "YES" is not.
             Returns -1 if neither or both "YES" and "NO" are in the detection result.
    """
    if constant.LLMResponseKeywords.NEG_ANS.value in detection_result and constant.LLMResponseKeywords.POS_ANS.value not in detection_result:
        return 0
    elif constant.LLMResponseKeywords.POS_ANS.value in detection_result and constant.LLMResponseKeywords.NEG_ANS.value not in detection_result:
        return 1
    return -1

def parse_command_line_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cwe-list', 
        nargs = '*', 
        type = str, 
        help = 'The list of CWEs to detect for baseline.',
        default = []
    )

    parser.add_argument(
        "--model-name",
        type = str,
        default = 'gpt-3.5-turbo',
        help = "The name of the model used for baseline inference.",
    )

    parser.add_argument(
        "--prompt-type",
        type = int,
        default = 0,
        choices=[0, 1, 2, 3, 4],
        help = (
            "The prompt type used for inference, 0 for a basic prompt "
            "without the need for an explanation, 1 for a prompt with "
            "the need for an explanation, 2 for a COT prompt, 3 for an"
            "advanced COT prompt, and 4 for a prompt with CWE description."
        ),
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

    args = parser.parse_args()

    if args.model_settings:
        args.model_settings_dict = common_util.parse_kv_string_to_dict(args.model_settings)
    else:
        args.model_settings_dict = {}
        args.model_settings = "default-settings"

    return args


if __name__ == "__main__":

    args = parse_command_line_arguments()
    model_instance = ModelManager.get_model_instance(args.model_name)
    result_dir_list = []

    for cwe_id in args.cwe_list:
        logging.info(f"Start detecting CWE-{cwe_id}...")

        test_clean_data_path = PathUtil.test_data(constant.TEST_DATA_FILE_NAME.format(cwe_id = cwe_id), "json")
        test_clean_data = DataUtils.load_json(test_clean_data_path)
        output_path = PathUtil.vul_detection_baseline_output(
            constant.BASELINE_RESULT_FILE_NAME.format(
                cwe_id = cwe_id, 
                model_name = args.model_name,
                baseline_settings = f"{args.model_settings}_{constant.BASELINE_PROMPT_TYPE_DESCRIPTION_MAP[args.prompt_type]}"
            ), "json", args.model_name, f"{args.model_settings}_{constant.BASELINE_PROMPT_TYPE_DESCRIPTION_MAP[args.prompt_type]}"
        )

        result_dir_list.append(os.path.dirname(output_path))

        cve_code = []
        for _, value in test_clean_data.items():
            item = value['item'] # a list of samples
            cve_code.extend(item)

        vul_list = []
        non_vul_list = []

        for sample in tqdm(cve_code):
            try:
                code_before_change = sample['code_before_change']
                prpt = common_prompt.BaselinePrompt.generate_baseline_prompt(
                    args.prompt_type,
                    code_snippet = code_before_change,
                    cwe_id = cwe_id
                )
                detect_result = model_instance.get_response_with_messages(
                    messages = model_instance.get_messages(prpt, constant.DEFAULT_SYS_PROMPT),
                    **args.model_settings_dict
                )
                vul_list.append({
                    "id": sample['id'],
                    "cve_id": sample['cve_id'], 
                    "prompt": prpt,
                    "code_snippet": code_before_change,
                    "detect_result": detect_result,
                    "used_model": args.model_name,
                    "model_settings": args.model_settings_dict,
                    "final_result": convert_detection_result_to_number(detect_result)
                })

            except Exception as e:
                logging.error(f"Error: {e}")
                logging.error(f"Error sample: {sample}")
                vul_list.append({
                    "id": sample['id'],
                    "cve_id": sample['cve_id'], 
                    "prompt": prpt,
                    "code_snippet": code_before_change,
                    "detect_result": None,
                    "used_model": args.model_name,
                    "model_settings": args.model_settings_dict,
                    "error": str(e)
                })

            try:
                code_after_change = sample['code_after_change']
                prpt = common_prompt.BaselinePrompt.generate_baseline_prompt(
                    args.prompt_type,
                    code_snippet = code_after_change,
                    cwe_id = cwe_id
                )
                detect_result = model_instance.get_response_with_messages(
                    messages = model_instance.get_messages(prpt, constant.DEFAULT_SYS_PROMPT),
                    **args.model_settings_dict
                )
                non_vul_list.append({
                    "id": sample['id'],
                    "cve_id": sample['cve_id'], 
                    "prompt": prpt,
                    "code_snippet": code_after_change,
                    "detect_result": detect_result,
                    "used_model": args.model_name,
                    "model_settings": args.model_settings_dict,
                    "final_result": convert_detection_result_to_number(detect_result)
                })

            except Exception as e:
                logging.error(f"Error: {e}")
                logging.error(f"Error sample: {sample}")
                non_vul_list.append({
                    "id": sample['id'],
                    "cve_id": sample['cve_id'], 
                    "prompt": prpt,
                    "code_snippet": code_after_change,
                    "detect_result": None,
                    "used_model": args.model_name,
                    "model_settings": args.model_settings_dict,
                    "error": str(e)
                })

            DataUtils.save_json(output_path, {"vul_data": vul_list, "non_vul_data": non_vul_list})

        logging.info(f"Finish detecting CWE-{cwe_id}.\n")
        common_util.calculate_VD_metrics(output_path)

    logging.info(f"Finish detecting all CWEs.")
    result_dir_list = list(set(result_dir_list))
    assert len(result_dir_list) == 1
    for result_dir in result_dir_list:
        common_util.calculate_VD_metrics(result_dir)
    logging.info(f"Metrics calculation finished.")