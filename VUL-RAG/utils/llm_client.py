import openai
import os
import re

class DeepseekClient:
    def __init__(self,model_name):
        self.model_name = model_name
        self.client = openai.OpenAI(
            base_url="https://api.deepseek.com/v1",
            api_key=os.environ.get("DEEPSEEK_API_KEY")
        )
        # self.client = openai.OpenAI(
        #     base_url="https://openkey.cloud/v1",
        #     api_key=os.environ.get("OPENAI_API_KEY")
        # )

    def generate_text(self, prompt,model_settings=None):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages = prompt,
            **model_settings
        )

        response_content=response.choices[0].message.content
        try:
            thinking_content = response.choices[0].message.reasoning_content
            response_content = "<think>\n"+thinking_content +"\n</think>" +"\n\n" + response_content
        except: 
            pass
        return response_content
    
class OpenaiClient:
    def __init__(self,model_name):
        self.model_name = model_name
        self.client = openai.OpenAI(
            base_url="https://openkey.cloud/v1",
            api_key=os.environ.get("OPENAI_API_KEY")
        )

    def generate_text(self, prompt,model_settings=None):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages = prompt,
            **model_settings
        )
        return response.choices[0].message.content
    
class QwenClient:
    def __init__(self,model_name):
        self.model_name = model_name
        self.client = openai.OpenAI(
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            api_key=os.environ.get("DASHSCOPE_API_KEY")
        )

    def generate_text(self, prompt,model_settings=None):
        response = self.client.chat.completions.create(
            model = self.model_name,
            messages = prompt,
            **model_settings
        )
        return response.choices[0].message.content
    
class ClaudeClient:
    def __init__(self,model_name):
        self.model_name = model_name
        self.client = openai.OpenAI(
            base_url="https://openkey.cloud/v1",
            api_key=os.environ.get("OPENAI_API_KEY")
        )

    def generate_text(self, prompt,model_settings=None):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages = prompt,
            **model_settings
        )
        return response.choices[0].message.content

def push_prompt(prompt:list, role:str, content:str):
    prompt.append({"role": role, "content": content})
    return prompt

def remove_thinking(text:str):
    return re.sub(r"<think>.*?</think>", "", text)

def generate_simple_prompt(prompt:str):
    return [{"role": "user", "content": prompt}]

def get_llm_client(llm_name):
    if 'deepseek' in llm_name:
        return DeepseekClient(llm_name)
    elif 'qwen' in llm_name:
        return QwenClient(llm_name)
    elif 'claude' in llm_name:
        return ClaudeClient(llm_name)
    elif 'openai' in llm_name or "gpt" in llm_name or "o1" in llm_name or "o3" in llm_name:
        if 'openai' in llm_name:
            llm_name = llm_name.replace("openai-","")
        return OpenaiClient(llm_name)
    raise ValueError(f"Unsupported LLM: {llm_name}")

def parse_kv_string_to_dict(
        key_value_string: str, 
        arg_sep: str = ";",
        kv_sep: str = "="
    ) -> dict:
    """
    This function parses a key-value string argument into a dictionary.
    The input string should have key-value pairs separated by 'arg_sep' (default is ';')
    and keys and values separated by 'kv_sep' (default is '=').
    For example, the string "key1=value1;key2=value2" will be parsed into the dictionary
    {"key1": "value1", "key2": "value2"}.
    The function also attempts to convert the values to int, float, or boolean types if possible.
    """
    key_value_list = key_value_string.split(arg_sep)
    key_value_dict = {}
    for key_value in key_value_list:
        try:
            key, value_str = key_value.split(kv_sep, 1)
        except ValueError:
            # logging.warning(f"Skipping invalid key-value pair: {key_value}")
            print(f"Skipping invalid key-value pair: {key_value}")
            continue
        key = key.strip()
        value_str = value_str.strip()
        try:
            value = int(value_str)
        except ValueError:
            try:
                value = float(value_str)
            except ValueError:
                if value_str.lower() == "true":
                    value = True
                elif value_str.lower() == "false":
                    value = False
                else:
                    value = value_str
        key_value_dict[key] = value
    return key_value_dict

def extract_LLM_response_by_prefix(response: str, prefix: str) -> str:
    """
    This function extracts the response from the LLM output that is prefixed by a given string.
    """
    if prefix in response:
        return response.split(prefix)[1].strip()
    else:
        return response.strip()

if __name__ == "__main__":
    # print(remove_thinking("<think>thinking</think>Action"))
    # client = get_llm_client("deepseek-chat")
    # prompt = [{"role": "user", "content": "你好"}]
    # print(client.generate_text(prompt,model_settings={"temperature":0.2,"max_tokens":5}))
    # model_settings = parse_kv_string_to_dict("temperature=0.2;max_tokens=10")
    # print(model_settings)
    pass
