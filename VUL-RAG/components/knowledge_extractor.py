import json
from tqdm import tqdm
from common.util.path_util import PathUtil
from common.util.data_utils import DataUtils
from es_retrival import LLM4DetectionRetrieval
from common import constant
from common.util import common_util

import common.constant as constant
from common.constant import KnowledgeDocumentName as kdn
from common.model_manager import ModelManager
import logging
import pdb
from common.common_prompt import ExtractionPrompt

# "CWE-416": "Use After Free", !!
# "CWE-125": "Out-of-bounds Read",
# "CWE-787": "Out-of-bounds Write",
# "CWE-476": "NULL Pointer Dereference",
# "CWE-401": "Missing Release of Memory after Effective Lifetime",
# "CWE-190": "Integer Overflow or Wraparound", !!
# "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"
# "CWE-122": "Heap-based Buffer Overflow",
# "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer", !!
# "CWE-120": "Buffer Copy without Checking Size of Input ('Classic  ')",

class KnowledgeExtractor:
    def __init__(self, model_name):
        self.model_instance = ModelManager.get_model_instance(model_name)
        self.data_lst = []

    def get_dict(self, vul_knowledge_output):
        vul_knowledge_output = vul_knowledge_output.split("\"vulnerability_behavior\"")[1]
        vul_knowledge_output = "{\"vulnerability_behavior\"" + vul_knowledge_output
        if "\n```" in vul_knowledge_output:
            vul_knowledge_output = vul_knowledge_output.split("\n```")[0]
        return json.loads(vul_knowledge_output)

    def format_knowledge_file(self, path):
        kno_dict = DataUtils.load_json(path)
        answer = {}
        for cve in kno_dict:
            answer[cve] = []
            for item in kno_dict[cve]:
                item[kdn.PRECONDITIONS.value] = item[kdn.VUL_BEHAVIOR.value][kdn.PRECONDITIONS.value]
                item[kdn.TRIGGER.value] = item[kdn.VUL_BEHAVIOR.value][kdn.TRIGGER.value]
                item[kdn.CODE_BEHAVIOR.value] = item[kdn.VUL_BEHAVIOR.value][kdn.CODE_BEHAVIOR.value]
                if kdn.SOLUTION.value in item[kdn.VUL_BEHAVIOR.value]:
                    item[kdn.SOLUTION.value] = item[kdn.VUL_BEHAVIOR.value][kdn.SOLUTION.value]
                answer[cve].append(item)

        DataUtils.save_json(path, answer)

    def extract_knowledge_from_cwe(self, CWE_name, extract_only_once, resume, **kwargs):
        try:
            self.data_lst = DataUtils.load_json(PathUtil.clean_data(
                constant.CLEAN_DATA_FILE_NAME.format(cwe_id = CWE_name), "json"
            ))
        except Exception as e:
            logging.error(f"Error in loading data: {e}")

        model_settings_dict = kwargs.get("model_settings_dict", {})
        output_path = PathUtil.knowledge_extraction_output(
            constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                model_name = self.model_instance.get_model_name(), 
                cwe_id = CWE_name
            ),
            "json"
        )

        if PathUtil.check_file_exists(output_path) and resume:
            current_knowledge_pattern = DataUtils.load_json(output_path)
            output_list = current_knowledge_pattern
        else:
            output_list = {}

        for item in tqdm(self.data_lst):
            if item["cve_id"] not in output_list.keys():
                output_list[item["cve_id"]] = []
            else:
                if extract_only_once:
                    continue
            (
                purpose_prompt, 
                function_prompt, 
                analysis_prompt, 
                knowledge_extraction_prompt
            ) = ExtractionPrompt.generate_extract_prompt(
                item["cve_id"], 
                item["cve_description"], 
                item["function_modified_lines"], 
                item["code_before_change"], 
                item["code_after_change"]
            )
            try:
                # get purpose
                purpose_messages = self.model_instance.get_messages(purpose_prompt, constant.DEFAULT_SYS_PROMPT)
                purpose_output = self.model_instance.get_response_with_messages(purpose_messages, **model_settings_dict)

                # get function
                function_messages = self.model_instance.get_messages(function_prompt, constant.DEFAULT_SYS_PROMPT)
                function_output = self.model_instance.get_response_with_messages(function_messages, **model_settings_dict)

                # get analysis
                messages = self.model_instance.get_messages(analysis_prompt, constant.DEFAULT_SYS_PROMPT)
                analysis_output = self.model_instance.get_response_with_messages(messages, **model_settings_dict)
                messages.append({"role": "assistant", "content": analysis_output})
                messages.append({"role": "user", "content": knowledge_extraction_prompt})
                vul_knowledge_output = self.model_instance.get_response_with_messages(messages, **model_settings_dict)
                output_dict = self.get_dict(vul_knowledge_output)
                output_dict["GPT_analysis"] = analysis_output
                output_dict["GPT_purpose"] = common_util.extract_LLM_response_by_prefix(
                    purpose_output,
                    constant.LLMResponseSeparator.FUN_PURPOSE_SEP.value
                )
                output_dict["GPT_function"] = common_util.extract_LLM_response_by_prefix(
                    function_output,
                    constant.LLMResponseSeparator.FUN_FUNCTION_SEP.value
                )
                output_dict["CVE_id"] = item["cve_id"]
                output_dict["code_before_change"] = item["code_before_change"]
                output_dict["code_after_change"] = item["code_after_change"]
                output_dict["modified_lines"] = item["function_modified_lines"]
                output_list[item["cve_id"]].append(output_dict)

            except Exception as e:
                logging.error(f"Error in extracting knowledge for {item['cve_id']}: {e}")
                pdb.set_trace()

            DataUtils.save_json(output_path, output_list)
            self.format_knowledge_file(output_path)

    def document_store(self, cwe_name_list):
        for cwe_name in cwe_name_list:
            doc_path = PathUtil.knowledge_extraction_output(
                constant.VUL_KNOWLEDGE_PATTERN_FILE_NAME.format(
                    model_name = self.model_instance.get_model_name(), 
                    cwe_id = cwe_name
                ), 
                "json"
            )
            for document_name in constant.KnowledgeDocumentName.get_es_document_values():
                es_retrieval = LLM4DetectionRetrieval(
                    constant.ES_INDEX_NAME_TEMPLATE.format(
                        lower_cwe_id = cwe_name.lower(), 
                        lower_document_name = document_name.lower()
                    ),
                    document_name
                )
                es_retrieval.update_new_documents(doc_path = doc_path)
