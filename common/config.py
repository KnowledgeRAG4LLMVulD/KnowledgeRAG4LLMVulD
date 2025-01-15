import sys
import os
sys.path.append(os.path.dirname(__file__))
from util.data_utils import DataUtils
from util.path_util import PathUtil



# ----------------------- config for logging -----------------------
import logging
logging.basicConfig(
    level = logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)d - %(message)s'
)
# ----------------------- config for logging -----------------------



# ----------------------- config for Elastic Search -----------------------
ES_CONFIG_SERVER = None

ES_CONFIG_LOCAL = {
    "host": "localhost",
    "port": 9201,
}

ES_CONFIG = ES_CONFIG_LOCAL

ES_SETTINGS = {
    "index": {
        "blocks": {
            "read_only_allow_delete": False
        }
    }
}
DISABLE_ES_LOGGING = True
ES_USE_CUSTOM_SETTINGS = False
# ----------------------- config for Elastic Search -----------------------




# ----------------------- config for OpenAI API -----------------------
deepseek_api_base = "https://api.deepseek.com/v1"
deepseek_api_key = DataUtils.load_data_from_pickle_file(PathUtil.api_keys_data("deepseek_api_key", "pkl"))

openkey_openai_api_base = "https://openkey.cloud/v1"
openkey_openai_api_key = DataUtils.load_data_from_pickle_file(PathUtil.api_keys_data("openkey_openai_api_key", "pkl"))

qwen_api_base = "https://dashscope.aliyuncs.com/compatible-mode/v1"
qwen_api_key = DataUtils.load_data_from_pickle_file(PathUtil.api_keys_data("qwen_api_key", "pkl"))


# claude_api_base = "https://api.aiproxy.io"
claude_api_base = "https://api.openai-proxy.org/anthropic"
claude_api_key = DataUtils.load_data_from_pickle_file(PathUtil.api_keys_data("claude_api_key", "pkl"))

OPENAI_API_CONNECTION_PROXY = "http://localhost:7890"
CLAUDE_DEFAULT_MAX_TOKENS = 2048
# ----------------------- config for OpenAI API -----------------------



# ----------------------- config for others -----------------------
ES_SEARCH_MAX_TOKEN_LENGTH = 10240
DEFAULT_BEHAVIOR_SUMMARY_MODEL = "gpt-3.5-turbo"
DEFAULT_RETRIEVAL_RANK_WEIGHT = [1, 1, 1]
DEFAULT_RETRIEVAL_TOP_K = 20
RESULT_UNIFORM_MAP = {
    1: 1,
    0: 0,
    -1: 0,
    "yes": 1,
    "no": 0,
    "Yes": 1,
    "No": 0,
    "1": 1,
    "0": 0,
    "-1": 0
}
METRICS_DECIMAL_PLACES_RESERVED = 4
MAX_RETRIEVE_KNOWLEDGE_NUM = 5
MAX_RETRIEVE_CODE_NUM = 5
DEFAULT_KNOWLEDGE_EXTRACTION_MODEL_SETTINGS = {
    "max_tokens": 2048,
    "temperature": 0.2,
}
# ----------------------- config for others -----------------------