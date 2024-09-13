import pdb
from typing import List, Dict, Tuple
import json
import openai
from tqdm import tqdm

from util.path_util import PathUtil
from util.data_utils import DataUtils
from util.file_util import FileUtil
from LLM4Detection.es_retrival import ESRetrieval, LLM4DetectionRetrieval

openai.organization = ""
openai.api_key = ""


model_name = "gpt-3.5-turbo"
# model_name = "gpt-4"

CWE_name = "CWE-119"
ROUND = 2

if ROUND == 1:
    DATA_PATH = PathUtil.clean_data("Linux_kernel_" + CWE_name + "_clean_data", "json")
else:
    DATA_PATH = PathUtil.clean_data("a_Linux_kernel_" + CWE_name + "_clean_data_new_knowledge", "json")

output_name = "_316_pattern_all"


output_path = PathUtil.knowledge_extraction_output(model_name + "_" + CWE_name + output_name, "json")


KnowledgeExtractionPrompt = """\nI want you to act as a vulnerability detection expert and organize vulnerability knowledge based on the above vulnerability repair information. Please summarize the generalizable specific behavior of the code that leads to the vulnerability and the specific solution to fix it. Format your findings in JSON.\nHere are some examples to guide you on the level of detail expected in your extraction:\n Example 1:\n {"vulnerability_behavior": {'preconditions_for_vulnerability': 'Lack of proper handling for asynchronous events during device removal process.', 'trigger_condition': 'A physically proximate attacker unplugs a device while the removal function is executing, leading to a race condition and use-after-free vulnerability.', 'specific_code_behavior_causing_vulnerability': 'The code does not cancel pending work associated with a specific functionality before proceeding with further cleanup during device removal. This can result in a use-after-free scenario if the device is unplugged at a critical moment.'}, 'solution': 'To mitigate the vulnerability, it is necessary to cancel any pending work related to the specific functionality before proceeding with further cleanup during device removal. This ensures that the code handles asynchronous events properly and prevents the use-after-free vulnerability. In this case, the solution involves adding a line to cancel the pending work associated with the specific functionality before continuing with the cleanup process.'}\n Please be mindful to omit specific resource names in your descriptions to ensure the knowledge remains generalized. For example, instead of writing mutex_lock(&dmxdev->mutex), simply use mutex_lock. """


class KnowledgeExtractor:
    def __init__(self, model_name):
        self.data_lst = DataUtils.load_json(DATA_PATH)
        self.model_name = model_name

    def generate_extract_prompt(self, CVE_id, CVE_description, modified_lines, code_before_change, code_after_change):
        str = f"""This is a code snippet with a vulnerability {CVE_id}:\n'''\n{code_before_change}\n'''\nThe vulnerability is described as follows:\n{CVE_description}\n"""

        # extract purpose prompt
        purpose_prompt = str + """What is the purpose of the function in the above code snippet? Please summarize the answer in one sentence with following format: Function purpose: \"\""""

        # extract function prompt
        function_prompt = str + """Please summarize the functions of the above code snippet in the list format without other explanation: \"The functions of the code snippet are: 1. 2. 3.\""""

        # extract analysis prompt
        analysis_prompt = str + """The correct way to fix it is by adding/deleting\n'''\n{modified_lines}\n'''\n."""

        if modified_lines["added"] != []:
            analysis_prompt += f"""The code after modification is as follows:\n'''\n{code_after_change}\n'''\n"""

        analysis_prompt += """Why is the above modification necessary?"""

        knowledge_extraction_prompt = KnowledgeExtractionPrompt


        return purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt

    def get_messages(self, prompt):
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]

        return messages

    def get_response(self, messages, model_name):
        response = openai.ChatCompletion.create(
            max_tokens=2048,
            temperature=0.2,
            model=model_name,
            messages=messages
        )

        return response.choices[0]["message"]["content"]

    def get_purpose_info(self, purpose_output):
        if "Function purpose: " in purpose_output:
            return purpose_output.split("Function purpose: ")[1]
        else:
            return purpose_output

    def get_function_info(self, function_output):
        if "The functions of the code snippet are:" in function_output:
            return function_output.split("The functions of the code snippet are:")[1]
        else:
            return function_output

    def get_dict(self, vul_knowledge_output):
        # 截取"vulnerability_behavior"之后的内容
        vul_knowledge_output = vul_knowledge_output.split("\"vulnerability_behavior\"")[1]
        vul_knowledge_output = "{\"vulnerability_behavior\"" + vul_knowledge_output
        if "\n```" in vul_knowledge_output:
            vul_knowledge_output = vul_knowledge_output.split("\n```")[0]
        # pdb.set_trace()
        return json.loads(vul_knowledge_output)

    def format_knowledge_file(self, path):
        kno_dict = FileUtil.load_data_list_from_json_file(path)
        answer = {}
        for cve in kno_dict:
            answer[cve] = []
            for item in kno_dict[cve]:
                item["preconditions_for_vulnerability"] = item["vulnerability_behavior"][
                    "preconditions_for_vulnerability"]
                item["trigger_condition"] = item["vulnerability_behavior"]["trigger_condition"]
                item["specific_code_behavior_causing_vulnerability"] = item["vulnerability_behavior"][
                    "specific_code_behavior_causing_vulnerability"]
                if "solution" in item["vulnerability_behavior"]:
                    item["solution"] = item["vulnerability_behavior"]["solution"]
                answer[cve].append(item)

        FileUtil.write_data_list_to_json_file(answer, path)

    def extract_knowledge_from_cwe(self):

        if PathUtil.check_file_exists(output_path):
            current_knowledge_pattern = DataUtils.load_json(output_path)
            output_list = current_knowledge_pattern
        else:
            output_list = {}

        for item in tqdm(self.data_lst):
            if item["cve_id"] not in output_list.keys():
                output_list[item["cve_id"]] = []
            else:
                if ROUND == 1:
                    continue
            purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt = self.generate_extract_prompt(item["cve_id"], item["cve_description"], item["function_modified_lines"], item["code_before_change"], item["code_after_change"])

            try:
                # get purpose
                purpose_messages = self.get_messages(purpose_prompt)
                purpose_output = self.get_response(purpose_messages, "gpt-3.5-turbo")

                # get function
                function_messages = self.get_messages(function_prompt)
                function_output = self.get_response(function_messages, "gpt-3.5-turbo")

                # get analysis
                messages = self.get_messages(analysis_prompt)
                analysis_output = self.get_response(messages, self.model_name)
                messages.append({"role": "assistant", "content": analysis_output})
                messages.append({"role": "user", "content": knowledge_extraction_prompt})
                vul_knowledge_output = self.get_response(messages, self.model_name)
                output_dict = self.get_dict(vul_knowledge_output)
                output_dict["GPT_analysis"] = analysis_output
                output_dict["GPT_purpose"] = self.get_purpose_info(purpose_output)
                output_dict["GPT_function"] = self.get_function_info(function_output)
                output_dict["CVE_id"] = item["cve_id"]
                output_dict["code_before_change"] = item["code_before_change"]
                output_dict["code_after_change"] = item["code_after_change"]
                output_dict["modified_lines"] = item["function_modified_lines"]
                output_list[item["cve_id"]].append(output_dict)

            except Exception as e:
                print(e)

            DataUtils.save_json(output_path, output_list)
            self.format_knowledge_file(output_path)

    def document_store(self, cwe_name_list):
        document_name_list = ["preconditions_for_vulnerability", "trigger_condition", "specific_code_behavior_causing_vulnerability", "solution", "GPT_purpose", "GPT_function", "code_before_change","code_after_change"]
        # document_name_list = ["solution"]
        for cwe_name in cwe_name_list:
            doc_path = PathUtil.knowledge_extraction_output(model_name + "_" + cwe_name + "_316_pattern_all", "json")
            for document_name in document_name_list:
                es_retrieval = LLM4DetectionRetrieval("gpt3_316" + cwe_name.lower() + "_" + document_name.lower(),
                                                      document_name)
                es_retrieval.update_new_document(doc_path=doc_path)



if __name__ == '__main__':

    KnowledgeE = KnowledgeExtractor(model_name=model_name)
    KnowledgeE.extract_knowledge_from_cwe()
    KnowledgeE.document_store([CWE_name])
