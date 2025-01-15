from constant import LLMResponseKeywords as rkw
from constant import LLMResponseSeparator as rsep
import constant
from typing import Literal

# ----------------------- Prompt for Baseline -----------------------
class BaselinePrompt:
    @staticmethod
    def generate_basic_prompt_without_explanation(**kwargs) -> str:
        code_snippet = kwargs.get("code_snippet")
        if code_snippet is None:
            raise ValueError("code_snippet is required.")
        prompt = f"""I want you to act as a vulnerability detection expert. Given the following code, please detect whether there is a vulnerability in the code snippet,
Code Snippet:
'''
{code_snippet}
'''
and ultimately answer {rkw.POS_ANS.value} or {rkw.NEG_ANS.value} without explanation.
"""
        return prompt

    @staticmethod
    def generate_basic_prompt_with_explanation(**kwargs) -> str:
        code_snippet = kwargs.get("code_snippet")
        if code_snippet is None:
            raise ValueError("code_snippet is required.")
        prompt = f"""I want you to act as a vulnerability detection expert. Given the following code, please detect whether there is a vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Answer {rkw.POS_ANS.value} or {rkw.NEG_ANS.value}, and explain why you think so.
"""
        return prompt
    
    @staticmethod
    def generate_cot_prompt(**kwargs) -> str:
        code_snippet = kwargs.get("code_snippet")
        if code_snippet is None:
            raise ValueError("code_snippet is required.")
        prompt = f"""I want you to act as a vulnerability detection expert.
Initially, you need to explain the behavior of the code. Subsequently, you need to determine whether the code is vulnerable. Answer in {rkw.POS_ANS.value} or {rkw.NEG_ANS.value}.
The code is:
{code_snippet}
"""
        return prompt
    
    @staticmethod
    def generate_advanced_cot_prompt(**kwargs) -> str:
        code_snippet = kwargs.get("code_snippet")
        if code_snippet is None:
            raise ValueError("code_snippet is required.")
        prompt = f"""I want you to act as a vulnerability detection system. Initially, you need to explain the behavior of the given code. Subsequently, analyze whether there are potential root causes that could result in vulnerabilities. Based on above analysis, determine whether the code is vulnerable, and conclude your answer with either {rkw.POS_ANS.value} or {rkw.NEG_ANS.value}.
### Code Snippet:
{code_snippet}
"""
        return prompt
    
    @staticmethod
    def generate_prompt_with_CWE_description(**kwargs) -> str:
        code_snippet = kwargs.get("code_snippet")
        if code_snippet is None:
            raise ValueError("code_snippet is required.")
        
        cwe_id = kwargs.get("cwe_id")
        if cwe_id is None:
            raise ValueError("cwe_id is required for prompt with CWE description.")
        
        prompt = f"""I want you to act as a vulnerability detection system. I will provide you with a code snippet and a CWE description. Please analyze the code to determine if it contains the vulnerability described in the CWE. Answer in {rkw.POS_ANS.value} or {rkw.NEG_ANS.value} only without explanation.
Code Snippet:
{code_snippet}
The CWE description:
{constant.CWE_DESCRIPTIONS[cwe_id]}
"""
        return prompt

    @staticmethod
    def generate_baseline_prompt(prompt_type_idx: Literal[0, 1, 2, 3, 4] = 0, **kwargs) -> str:
        """
        Generate a prompt for the baseline experiment based on the specified type.

        Parameters:
        prompt_type_idx (int, optional): The index of the prompt type to use. Defaults to 0.
            0: A basic prompt requesting a vulnerability detection without an explanation.
            1: A basic prompt requesting a vulnerability detection with an explanation.
            2: COT: A prompt requesting a vulnerability detection with an explanation and a code behavior explanation.
            3: COT2: An advanced prompt based on COT.
            4: A prompt requesting a vulnerability detection with a CWE description.

        **kwargs:
            code_snippet (str): The code snippet to be used in the prompt.
            cwe_id (str, optional): The CWE ID to be used in the prompt with CWE description. Required if prompt_type_idx is 4.

        Returns:
        str: The selected prompt based on the prompt_type_idx.

        Raises:
        ValueError: If an invalid prompt type index is provided.
        """
        prompt_generators = {
            0: BaselinePrompt.generate_basic_prompt_without_explanation,
            1: BaselinePrompt.generate_basic_prompt_with_explanation,
            2: BaselinePrompt.generate_cot_prompt,
            3: BaselinePrompt.generate_advanced_cot_prompt,
            4: BaselinePrompt.generate_prompt_with_CWE_description
        }
        
        if prompt_type_idx in prompt_generators:
            return prompt_generators[prompt_type_idx](**kwargs)
        else:
            raise ValueError("Invalid prompt type index.")

# ----------------------- Prompt for Baseline -----------------------


# ----------------------- Prompt for Extraction -----------------------
class ExtractionPrompt:
    @staticmethod
    def generate_extraction_prompt_for_vulrag(code_snippet):
        prefix_str = f"""This is a code snippet: \n{code_snippet}\n"""
        # extract purpose prompt
        purpose_prompt = prefix_str + (
            "What is the purpose of the function in the above code snippet? "
            "Please summarize the answer in one sentence with the following format: "
            "Function purpose: \"\""
        )

        # extract function prompt
        function_prompt = prefix_str + (
            "Please summarize the functions of the above code snippet "
            "in the list format without other explanation: "
            "\"The functions of the code snippet are: 1. 2. 3.\""
        )

        return purpose_prompt, function_prompt
    
    @staticmethod
    def generate_extract_prompt(CVE_id, CVE_description, modified_lines, code_before_change, code_after_change):
        prefix_str = f"""This is a code snippet with a vulnerability {CVE_id}:
'''
{code_before_change}
'''
The vulnerability is described as follows:
{CVE_description}
"""

        # extract purpose prompt
        purpose_prompt = f"""{prefix_str}
What is the purpose of the function in the above code snippet? \
Please summarize the answer in one sentence with following format: Function purpose: \"\"
"""

        # extract function prompt
        function_prompt = f"""{prefix_str}
Please summarize the functions of the above code snippet in the list format without other \
explanation: \"The functions of the code snippet are: 1. 2. 3.\"
"""

        # extract analysis prompt
        analysis_prompt = f"""{prefix_str}
The correct way to fix it is by adding/deleting\n'''\n{modified_lines}\n'''\n."""

        if modified_lines["added"] != []:
            analysis_prompt += f"""The code after modification is as follows:\n'''\n{code_after_change}\n'''\n"""

        analysis_prompt += """Why is the above modification necessary?"""

        knowledge_extraction_prompt = """
I want you to act as a vulnerability detection expert and organize vulnerability knowledge based on the above \
vulnerability repair information. Please summarize the generalizable specific behavior of the code that \
leads to the vulnerability and the specific solution to fix it. Format your findings in JSON.
Here are some examples to guide you on the level of detail expected in your extraction:
Example 1:
{
    "vulnerability_behavior": {
        'preconditions_for_vulnerability': 'Lack of proper handling for asynchronous events during device removal process.',
        'trigger_condition': 'A physically proximate attacker unplugs a device while the removal function is executing, \
leading to a race condition and use-after-free vulnerability.',
        'specific_code_behavior_causing_vulnerability': 'The code does not cancel pending work associated with a specific \
functionality before proceeding with further cleanup during device removal. This can result in a use-after-free scenario if \
the device is unplugged at a critical moment.'
    }, 
    'solution': 'To mitigate the vulnerability, it is necessary to cancel any pending work related to the specific \
functionality before proceeding with further cleanup during device removal. This ensures that the code handles asynchronous \
events properly and prevents the use-after-free vulnerability. In this case, the solution involves adding a line to cancel the \
pending work associated with the specific functionality before continuing with the cleanup process.'
}
Please be mindful to omit specific resource names in your descriptions to ensure the knowledge remains generalized. \
For example, instead of writing mutex_lock(&dmxdev->mutex), simply use mutex_lock.
"""


        return purpose_prompt, function_prompt, analysis_prompt, knowledge_extraction_prompt
# ----------------------- Prompt for Extraction -----------------------


# ----------------------- Prompt for VUL-RAG -----------------------
class VulRAGPrompt:
    @staticmethod
    def generate_detect_vul_prompt(code_snippet, cve_knowledge) -> str:
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please check if the above code snippet contains vulnerability behaviors mentioned in the vulnerability knowledge. Perform a step-by-step analysis and conclude your response with either {rsep.ANSWER_SEP.value} {rkw.POS_ANS.value} {rsep.ANSWER_SEP.value} or {rsep.ANSWER_SEP.value} {rkw.NEG_ANS.value} {rsep.ANSWER_SEP.value}.
"""

    @staticmethod
    def generate_detect_sol_prompt(code_snippet, cve_knowledge) -> str:
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there are necessary solution behaviors in the code snippet, which can prevent the occurrence of related vulnerabilities in the vulnerability knowledge.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please check if the above code snippet contains solution behaviors mentioned in the vulnerability knowledge. Perform a step-by-step analysis and conclude your response with either {rsep.ANSWER_SEP.value} {rkw.POS_ANS.value} {rsep.ANSWER_SEP.value} or {rsep.ANSWER_SEP.value} {rkw.NEG_ANS.value} {rsep.ANSWER_SEP.value}.
"""

    @staticmethod
    def generate_detect_prompt(code_snippet, cve_knowledge) -> str:
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please use your own knowledge of vulnerabilities in combination with the above vulnerability knowledge to detect whether there is a vulnerability in the code snippet. Perform a step-by-step analysis and conclude your response with either {rsep.ANSWER_SEP.value} {rkw.POS_ANS.value} {rsep.ANSWER_SEP.value} or {rsep.ANSWER_SEP.value} {rkw.NEG_ANS.value} {rsep.ANSWER_SEP.value}.
"""
    
    @staticmethod
    def generate_detect_vul_prompt_without_explanation(code_snippet, cve_knowledge) -> str:
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please check if the above code snippet contains vulnerability behaviors mentioned in the vulnerability knowledge, answer {rkw.POS_ANS.value} or {rkw.NEG_ANS.value} without explanation.
"""

    @staticmethod
    def generate_detect_sol_prompt_without_explanation(code_snippet, cve_knowledge) -> str:
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there are necessary solution behaviors in the code snippet, which can prevent the occurrence of related vulnerabilities in the vulnerability knowledge.
Code Snippet:
'''
{code_snippet}
'''
Vulnerability Knowledge:
In a similar code scenario, the following vulnerabilities have been found:
'''
{cve_knowledge}
'''
Please check if the above code snippet contains solution behaviors mentioned in the vulnerability knowledge, answer {rkw.POS_ANS.value} or {rkw.NEG_ANS.value} without explanation.
"""

    @staticmethod
    def generate_detect_prompt_for_code_retrieval(code_snippet, vul_code, non_vul_code):
        return f"""I want you to act as a vulnerability detection expert, given the following code snippet and related vulnerability knowledge, please detect whether there is a vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Related vulnerability code snippet:
'''
{vul_code}
'''
Related non-vulnerability code snippet:
'''
{non_vul_code}
'''
Please use your own knowledge of vulnerabilities in combination with the above related code snippets to detect whether there is a vulnerability in the code snippet. Please answer {rkw.POS_ANS.value} or {rkw.NEG_ANS.value} without explanation.
"""


# ----------------------- Prompt for VUL-RAG -----------------------

if __name__ == "__main__":
    pass