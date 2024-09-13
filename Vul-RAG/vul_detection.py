from util.path_util import PathUtil
from util.data_utils import DataUtils
import openai
import pdb
from LLM4Detection.es_retrival import ESRetrieval, LLM4DetectionRetrieval
from tqdm import tqdm
import os

openai.organization = ""
openai.api_key = ""

def read_cve_list(clean_data, CWE_name):
    cve_set = set()
    for cve in clean_data:
        if CWE_name in cve["cwe_id"]:
            cve_set.add(cve["cve_id"])
    return list(cve_set)

# CWE-416-example
CWE_name = "CWE-416"
clean_data_path = PathUtil.clean_data("test_training_data", "json")
clean_data = DataUtils.load_json(clean_data_path)
cve_list = read_cve_list(clean_data, CWE_name)

model_name = "gpt-4"
RETRIEVE_BY_CODE = False

KNOWLEDGE_PATH = PathUtil.knowledge_extraction_output(model_name + "_" + CWE_name, "json")

output_path = PathUtil.vul_detection_output(CWE_name + "_pattern_" + model_name, "json")

non_vul_output_path = PathUtil.vul_detection_output(model_name, "json")

class VulDetector:
    def __init__(self, model_name, knowledge_path):
        self.vul_knowledge = DataUtils.load_json(knowledge_path)
        self.model_name = model_name

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

    def get_info_from_knowledge_base(self, cve_id, code_snippet, info_type, code_state):
        cve_knowledge = self.vul_knowledge[cve_id]
        for item in cve_knowledge:
            if code_snippet == item[code_state]:
                return item[info_type]
        print(cve_id, "not found in knowledge base")
        return ""

    def generate_extract_prompt(self, code_snippet):
        str = f"""This is a code snippet: \n {code_snippet}"""

        # extract purpose prompt
        purpose_prompt = str + """What is the purpose of the function in the above code snippet? Please summarize the answer in one sentence with following format: Function purpose: \"\""""

        # extract function prompt
        function_prompt = str + """Please summarize the functions of the above code snippet in the list format without other explanation: \"The functions of the code snippet are: 1. 2. 3.\""""

        return purpose_prompt, function_prompt
    
    
    def rerank_by_rank(self, purpose_result: [], function_result: [], code_result: []):
        '''
        rerank the cve_id by the rank of three results
        :param purpose_result:
        :param function_result:
        :param code_result:
        :return:
        '''
        cve_id_list = []
        cve_id_list.extend(function_result)
        cve_id_list.extend(purpose_result)
        cve_id_list.extend(code_result)
        weight = [1,1,1]
        cve_id_dict = {}
        for cve_id in cve_id_list:
            try:
                cve_id_dict[cve_id] = 0

                if cve_id in purpose_result:
                    cve_id_dict[cve_id] += purpose_result.index(cve_id) * weight[0]
                else:
                    cve_id_dict[cve_id] += len(purpose_result) * weight[0]
                if cve_id in function_result:
                    cve_id_dict[cve_id] += function_result.index(cve_id) * weight[1]
                else:
                    cve_id_dict[cve_id] += len(function_result) * weight[1]
                if cve_id in code_result:
                    cve_id_dict[cve_id] += code_result.index(cve_id) * weight[2]
                else:
                    cve_id_dict[cve_id] += len(code_result) * weight[2]

            except Exception as e:
                pdb.set_trace()

        cve_id_dict = sorted(cve_id_dict.items(), key=lambda x: x[1], reverse=False)

        final_result = []
        for item in cve_id_dict:
            id_info = {}
            id_info["cve_id"] = item[0]
            id_info["count"] = item[1]
            final_result.append(id_info)

        return final_result

    def format_retreival_answer(self, purpose_answer, function_answer, code_answer):
        '''
        format the retrieval answer
        :param purpose_answer:
        :param function_answer:
        :param code_answer:
        :return:
        '''
        purpose_list = []
        purpose_dict = {}
        function_list = []
        function_dict = {}
        code_list = []
        code_dict = {}

        for item in purpose_answer:
            purpose_list.append(item["cve_id"])
            purpose_dict[item["cve_id"]] = item["content"]
        for item in function_answer:
            function_list.append(item["cve_id"])
            function_dict[item["cve_id"]] = item["content"]
        for item in code_answer:
            code_list.append(item["cve_id"])
            code_dict[item["cve_id"]] = item["content"]

        rerank_result = self.rerank_by_rank(purpose_list, function_list, code_list)

        # pdb.set_trace()
        knowledge_list = []

        for item in rerank_result:
            try:
                cve_knowledge = self.vul_knowledge[item["cve_id"]]
                for knowledege_item in cve_knowledge:
                    # pdb.set_trace()
                    if (item["cve_id"] in purpose_dict.keys() and purpose_dict[item["cve_id"]] == knowledege_item["GPT_purpose"]) or (item["cve_id"] in function_dict.keys() and function_dict[item["cve_id"]] == knowledege_item["GPT_function"]) or (item["cve_id"] in code_dict.keys() and code_dict[item["cve_id"]] == knowledege_item["code_before_change"]):
                        knowledge_list.append({"cve_id": knowledege_item["CVE_id"], "vulnerability_behavior": {"preconditions_for_vulnerability": knowledege_item["preconditions_for_vulnerability"], "trigger_condition": knowledege_item["trigger_condition"], "specific_code_behavior_causing_vulnerability": knowledege_item["specific_code_behavior_causing_vulnerability"]}, "solution_behavior": knowledege_item["solution"]})
                        break
            except Exception as e:
                print(e)

        return knowledge_list

    def retrieve_knowledge(self, cwe_name, code_snippet, purpose, function, top_N):
        purpose_query = purpose
        es_retrieval = LLM4DetectionRetrieval("gpt3_316" + cwe_name.lower() + "_" + "gpt_purpose", "gpt_purpose")
        purpose_answer = es_retrieval.search(query=purpose_query, retrieve_top_k = top_N)

        function_query = function
        es_retrieval = LLM4DetectionRetrieval("gpt3_316" + cwe_name.lower() + "_" + "gpt_function", "gpt_function")
        function_answer = es_retrieval.search(query=function_query, retrieve_top_k = top_N)

        function_query = code_snippet
        es_retrieval = LLM4DetectionRetrieval("gpt3_316" + cwe_name.lower() + "_" + "code_before_change", "code_before_change")
        code_answer = es_retrieval.search(query=function_query, retrieve_top_k = top_N)


        return self.format_retreival_answer(purpose_answer, function_answer, code_answer)


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

    def rerank_by_rank_code(self, code_result: []):

        cve_id_list = code_result
        cve_id_dict = {}
        for cve_id in cve_id_list:
            try:
                cve_id_dict[cve_id] = 0
                if cve_id in code_result:
                    cve_id_dict[cve_id] += code_result.index(cve_id)
                else:
                    cve_id_dict[cve_id] += len(code_result)

            except Exception as e:
                pdb.set_trace()

        cve_id_dict = sorted(cve_id_dict.items(), key=lambda x: x[1], reverse=False)

        final_result = []
        for item in cve_id_dict:
            id_info = {}
            id_info["cve_id"] = item[0]
            id_info["count"] = item[1]
            final_result.append(id_info)

        return final_result

    def format_retreival_answer_by_code(self, code_answer):
        '''
        format the retrieval answer
        :param code_answer:
        :return:
        '''

        code_list = []
        code_dict = {}


        for item in code_answer:
            code_list.append(item["cve_id"])
            code_dict[item["cve_id"]] = item["content"]

        rerank_result = self.rerank_by_rank_code(code_list)

        # pdb.set_trace()
        knowledge_list = []

        for item in rerank_result:
            try:
                cve_knowledge = self.vul_knowledge[item["cve_id"]]
                for knowledege_item in cve_knowledge:
                    # pdb.set_trace()
                    if (item["cve_id"] in code_dict.keys() and code_dict[item["cve_id"]] == knowledege_item["code_before_change"]):
                        knowledge_list.append({"cve_id": knowledege_item["CVE_id"], "vulnerability_behavior": knowledege_item["vulnerability_behavior"], "solution_behavior": knowledege_item["solution"]})
                        break
            except Exception as e:
                pdb.set_trace()

        return knowledge_list

    def retrieve_knowledge_by_code(self, cwe_name, code_snippet, top_N):
        function_query = code_snippet
        es_retrieval = LLM4DetectionRetrieval("gpt3_12" + "_" + "code_before_change", "code_before_change")
        code_answer = es_retrieval.search(query=function_query, retrieve_top_k = top_N)

        return self.format_retreival_answer_by_code(code_answer)

    def detect_pipeline_retrival_by_code(self, query_cve, code_snippet, cwe_name, top_N):

        # retrieve knowledge
        vul_knowledge_list = self.retrieve_knowledge_by_code(cwe_name, code_snippet, top_N)

        detect_result = []

        for vul_knowledge in vul_knowledge_list[:3]:
            if vul_knowledge['cve_id'] == query_cve:
                continue
            vul_detect_prompt = self.generate_detect_vul_prompt(code_snippet, vul_knowledge)
            sol_detect_prompt = self.generate_detect_sol_prompt(code_snippet, vul_knowledge)
            vul_messages = self.get_messages(vul_detect_prompt)
            sol_messages = self.get_messages(sol_detect_prompt)
            vul_output = self.get_response(vul_messages, self.model_name)
            sol_output = self.get_response(sol_messages, self.model_name)
            result = {"vul_knowledge": vul_knowledge, "vul_output": vul_output, "sol_output": sol_output}
            detect_result.append(result)
            if "YES" in vul_output and "NO" in sol_output:
                return {"cve_id": query_cve, "code_snippet": code_snippet, "detect_result": detect_result, "final_result": 1}
            elif "YES" in sol_output:
                return {"cve_id": query_cve, "code_snippet": code_snippet, "detect_result": detect_result, "final_result": 0}
            else:
                continue
        # todo: add postprocessing if no result is detected
        return {"cve_id": query_cve, "code_snippet": code_snippet, "detect_result": detect_result, "final_result": -1}

    def detect_pipeline(self, query_cve, code_snippet, state, cwe_name, top_N):
        # get purpose and function
        purpose_prompt, function_prompt = self.generate_extract_prompt(code_snippet)
        purpose_messages = self.get_messages(purpose_prompt)
        function_messages = self.get_messages(function_prompt)
        purpose = self.get_purpose_info(self.get_response(purpose_messages, "gpt-3.5-turbo"))
        function = self.get_function_info(self.get_response(function_messages, "gpt-3.5-turbo"))


        # retrieve knowledge
        vul_knowledge_list = self.retrieve_knowledge(cwe_name, code_snippet, purpose, function, top_N)

        # detect vulnerability with the ranking knowledge list, if Yes/No or No/Yes is detected, return the result, else, continue to detect the next knowledge
        detect_result = []
        flag = 0

        for vul_knowledge in vul_knowledge_list[:5]:
            vul_detect_prompt = self.generate_detect_vul_prompt(code_snippet, vul_knowledge)
            sol_detect_prompt = self.generate_detect_sol_prompt(code_snippet, vul_knowledge)
            vul_messages = self.get_messages(vul_detect_prompt)
            sol_messages = self.get_messages(sol_detect_prompt)
            vul_output = self.get_response(vul_messages, self.model_name)
            sol_output = self.get_response(sol_messages, self.model_name)
            result = {"vul_knowledge": vul_knowledge, "vul_output": vul_output, "sol_output": sol_output}
            detect_result.append(result)
            if "YES" in vul_output and "NO" in sol_output:
                return {"cve_id": query_cve, "purpose": purpose, "function": function, "code_snippet": code_snippet, "detect_result": detect_result, "final_result": 1}
            elif "YES" in sol_output:
                flag = 1
                continue
            else:
                continue

        if flag == 1:
            return {"cve_id": query_cve, "purpose": purpose, "function": function, "code_snippet": code_snippet, "detect_result": detect_result, "final_result": 0}
        else:
            return {"cve_id": query_cve, "purpose": purpose, "function": function, "code_snippet": code_snippet, "detect_result": detect_result, "final_result": -1}

    def generate_detect_vul_prompt(self, code_snippet, cve_knowledge):

        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a vulnerability in the code snippet.\n Code Snippet:\n'''\n {code_snippet}\n'''\nVulnerability Knowledge:\nIn a similar code scenario, the following vulnerabilities have been found:\n'''{cve_knowledge}\n'''\nPlease check if the above code snippet contains vulnerability behaviors mentioned in the vulnerability knowledge, answer YES or NO."""

    def generate_detect_sol_prompt(self, code_snippet, cve_knowledge):

        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there are necessary solution behaviors in the code snippet, which can prevent the occurrence of related vulnerabilities in the vulnerability knowledge.\n Code Snippet:\n'''\n {code_snippet}\n'''\nVulnerability Knowledge:\nIn a similar code scenario, the following vulnerabilities have been found:\n'''{cve_knowledge}\n'''\nPlease check if the above code snippet contains solution behaviors mentioned in the vulnerability knowledge, answer YES or NO."""

    def generate_detect_prompt(self, code_snippet, cve_knowledge):
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a vulnerability in the code snippet.\n Code Snippet:\n'''\n {code_snippet}\n'''\nVulnerability Knowledge:\nIn a similar code scenario, the following vulnerabilities have been found:\n'''{cve_knowledge}\n'''\nPlease use your own knowledge of vulnerabilities in combination with the above vulnerability knowledge to detect whether there is a vulnerability in the code snippet. """

if __name__ == '__main__':

    # detection
    VulD = VulDetector(model_name, KNOWLEDGE_PATH)

    # # detect pair data
    cve_code = {}
    for cve in cve_list:
        cve_code[cve] = []
        for item in clean_data:
            try:
                if item["cve_id"] == cve:
                    cve_code[cve].append((item["code_before_change"], item["code_after_change"]))
                    break
            except:
                print("Error1: ", cve)

    if PathUtil.check_file_exists(output_path):
        current_data = DataUtils.load_json(output_path)
        vul_list = current_data["vul_data"]
        non_vul_list = current_data["non_vul_data"]
    else:
        vul_list = []
        non_vul_list = []

    for cve in tqdm(cve_list):

        for (code_before_change, code_after_change) in cve_code[cve]:
            try:
                if RETRIEVE_BY_CODE:
                    vul_detect_result = VulD.detect_pipeline_retrival_by_code(cve, code_before_change, CWE_name, 20)
                    non_vul_detect_result = VulD.detect_pipeline_retrival_by_code(cve, code_after_change, CWE_name, 20)
                else:
                    vul_detect_result = VulD.detect_pipeline(cve, code_before_change, "code_before_change", CWE_name, 20)
                    non_vul_detect_result = VulD.detect_pipeline(cve, code_after_change, "code_after_change", CWE_name, 20)
                vul_list.append(vul_detect_result)
                non_vul_list.append(non_vul_detect_result)

            except:
                print("Error: ", cve)
        DataUtils.save_json(output_path, {"vul_data": vul_list, "non_vul_data": non_vul_list})

    # detect correct code only:

    # if PathUtil.check_file_exists(output_path):
    #     current_data = DataUtils.load_json(output_path)
    #     non_vul_list = current_data["non_vul_data"]
    # else:
    #     non_vul_list = []
    #
    # for cve in tqdm(cve_list[10:35]):
    #
    #     for (code_before_change, code_after_change) in cve_code[cve]:
    #         try:
    #             non_vul_detect_result = VulD.detect_pipeline(cve, code_after_change, "code_after_change", CWE_name, 20)
    #             non_vul_list.append(non_vul_detect_result)
    #
    #         except:
    #             print("Error: ", cve)
    #     DataUtils.save_json(output_path, {"non_vul_data": non_vul_list})

    # detect non-vul code
    # non_vul_path = PathUtil.clean_data("non_vul_functions_selected", "json")
    # non_vul_data = DataUtils.load_json(non_vul_path)
    # non_vul_list = []
    # for item in non_vul_data:
    #     non_vul_list.append(item["code"])
    #
    # result_list = []
    # if PathUtil.check_file_exists(non_vul_output_path):
    #     result_list = DataUtils.load_json(non_vul_output_path)
    #
    # fail_cnt = 0
    # for code in tqdm(non_vul_list[63:73]):
    #     try:
    #         non_vul_detect_result = VulD.detect_pipeline("0", code, CWE_name, 10)
    #         result_list.append(non_vul_detect_result)
    #         DataUtils.save_json(non_vul_output_path, result_list)
    #     except:
    #         fail_cnt += 1
    #
    # print("Error: ", fail_cnt)





