import argparse
from components.knowledge_extractor import KnowledgeExtractor
from common.util import common_util
import common.config as cfg

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

def parse_command_line_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--extract_knowledge', 
        action = 'store_true', 
        help = 'Determines whether to extract knowledge from the CWEs.'
    )

    parser.add_argument(
        '--store_knowledge', 
        action = 'store_true', 
        help = 'Determines whether to store knowledge to the Elasticsearch.'
    )

    parser.add_argument(
        '--extract_only_once', 
        action = 'store_true', 
        help = 'Determines whether to extract knowledge only once for each CVE.'
    )

    parser.add_argument(
        "--model_name",
        type = str,
        default = 'gpt-3.5-turbo',
        help = "The name of the model used for knowledge extraction.",
    )

    parser.add_argument(
        '--CWE_list', 
        nargs = '*', 
        type = str, 
        help = 'The list of CWEs to store knowledge.',
        default = []
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
        '--resume',
        action = 'store_true',
        help = 'Whether to resume from a checkpoint.'
    )

    args = parser.parse_args()

    if args.model_settings:
        args.model_settings_dict = common_util.parse_kv_string_to_dict(args.model_settings)
    else:
        args.model_settings_dict = cfg.DEFAULT_KNOWLEDGE_EXTRACTION_MODEL_SETTINGS
        args.model_settings = "default-settings"

    return args

if __name__ == '__main__':

    args = parse_command_line_arguments()

    KnowledgeE = KnowledgeExtractor(model_name = args.model_name)
    #knowledge extraction
    if args.extract_knowledge:
        for cwe_name in args.CWE_list:
            KnowledgeE.extract_knowledge_from_cwe(
                CWE_name = cwe_name,
                extract_only_once = args.extract_only_once,
                resume = args.resume,
                model_settings_dict = args.model_settings_dict
            )

    if args.store_knowledge:
        KnowledgeE.document_store(cwe_name_list = args.CWE_list)
