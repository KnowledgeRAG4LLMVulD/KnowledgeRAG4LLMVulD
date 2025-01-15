# !/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from pathlib import Path
from enum import Enum

class PreSufConstant(Enum):
    DB_NAME_PREFIX_FAISS = 'faiss_'
    DB_NAME_PREFIX_ES = 'es_'
    DB_NAME_PREFIX_MILVUS = 'milvus_'
    DB_NAME_SUFFIX = '_haystack'

    DB_INDEX_PREFIX_FAISS = 'faiss_'
    DB_INDEX_PREFIX_MILVUS = 'milvus_'
    DB_INDEX_SUFFIX = '_haystack'

class LLMResponseSeparator(Enum):
    DOC_SEP = "####"
    ANSWER_SEP = "###"
    FUN_PURPOSE_SEP = "Function purpose: "
    FUN_FUNCTION_SEP = "The functions of the code snippet are:"

class LLMResponseKeywords(Enum):
    POS_ANS = "YES"
    NEG_ANS = "NO"

class MetricsKeywords(Enum):
    FN = "False Negative"
    FP = "False Positive"
    TP = "True Positive"
    TN = "True Negative"
    AC = "Accuracy"
    PC = "Precision"
    RC = "Recall"
    F1 = "F1 Score"
    PAC = "Pair Accuracy"
    VPC = "Valid Pair Count"
    APC = "Accurate Pair Count"
    FNR = "False Negative Rate"
    FPR = "False Positive Rate"
    TNR = "True Negative Rate"
    TPR = "True Positive Rate"
    PD = "Prediction"
    GT = "Ground Truth"
    P1R = "Pair_1 Rate"
    P0R = "Pair_0 Rate"
    P1C = "Pair_1 Count"
    P0C = "Pair_0 Count"
    
    

class KnowledgeDocumentName(Enum):
    PRECONDITIONS = "preconditions_for_vulnerability"
    TRIGGER = "trigger_condition"
    CODE_BEHAVIOR = "specific_code_behavior_causing_vulnerability"
    SOLUTION = "solution"
    PURPOSE = "GPT_purpose"
    FUNCTION = "GPT_function"
    CODE_BEFORE = "code_before_change"
    CODE_AFTER = "code_after_change"
    VUL_BEHAVIOR = "vulnerability_behavior"
    CVE_ID = "CVE_id"

    @classmethod
    def get_es_document_values(cls) -> list:
        return [item.value for item in cls][:-2]

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = str(Path(ROOT_DIR) / "data")
OUTPUT_DIR = str(Path(ROOT_DIR) / "output")
LOGS_DIR = str(Path(ROOT_DIR) / "log")
MODEL_DIR = str(Path(ROOT_DIR) / "model")
COMMON_DIR = str(Path(ROOT_DIR) / "common")

VUL_KNOWLEDGE_PATTERN_FILE_NAME = "{model_name}_{cwe_id}_316_pattern_all"
ES_INDEX_NAME_TEMPLATE = "gpt3_316{lower_cwe_id}_{lower_document_name}"
TEST_DATA_FILE_NAME = "Linux_kernel_{cwe_id}_clean_data_testset_new"
CLEAN_DATA_FILE_NAME = "Linux_kernel_{cwe_id}_clean_data"
BASELINE_RESULT_FILE_NAME = "{cwe_id}_{model_name}_detection_baseline_{baseline_settings}"
VULRAG_DETECTION_RESULT_FILE_NAME = "{cwe_id}_{model_name}-{summary_model_name}_VulRAG-detection_{model_settings}"

DEFAULT_SYS_PROMPT = "You are a helpful assistant."

BASELINE_PROMPT_TYPE_DESCRIPTION_MAP = {
    0: "no_knowledge_basic_no_explanation",
    1: "no_knowledge_basic_with_explanation",
    2: "no_knowledge_cot",
    3: "no_knowledge_advanced_cot",
    4: "cwe_description"
}

CWE_DESCRIPTIONS = {
    "CWE-119": {
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "description": "The product performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
        "extended_description": "\n            Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced. This can cause read or write operations to be performed on memory locations that may be associated with other variables, data structures, or internal program data.\n            As a result, an attacker may be able to execute arbitrary code, alter the intended control flow, read sensitive information, or cause the system to crash.\n         \n         ",
        "url": "https://cwe.mitre.org/data/definitions/119.html",
        "is_category": False
    },
    "CWE-362": {
        "cwe_id": "CWE-362",
        "cwe_name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "description": "The product contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.",
        "extended_description": "\n            This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that should not be influenced by an outsider.\n            A race condition occurs within concurrent environments, and is effectively a property of a code sequence. Depending on the context, a code sequence may be in the form of a function call, a small number of instructions, a series of program invocations, etc.\n            A race condition violates these properties, which are closely related:\n               \n                  Exclusivity - the code sequence is given exclusive access to the shared resource, i.e., no other code sequence can modify properties of the shared resource before the original sequence has completed execution.\n                  Atomicity - the code sequence is behaviorally atomic, i.e., no other thread or process can concurrently execute the same sequence of instructions (or a subset) against the same resource.\n               \n            A race condition exists when an \"interfering code sequence\" can still access the shared resource, violating exclusivity. Programmers may assume that certain code sequences execute too quickly to be affected by an interfering code sequence; when they are not, this violates atomicity. For example, the single \"x++\" statement may appear atomic at the code layer, but it is actually non-atomic at the instruction layer, since it involves a read (the original value of x), followed by a computation (x+1), followed by a write (save the result to x).\n            The interfering code sequence could be \"trusted\" or \"untrusted.\" A trusted interfering code sequence occurs within the product; it cannot be modified by the attacker, and it can only be invoked indirectly. An untrusted interfering code sequence can be authored directly by the attacker, and typically it is external to the vulnerable product.\n         \n         ",
        "url": "https://cwe.mitre.org/data/definitions/362.html",
        "is_category": False
    },
    "CWE-416": {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        "extended_description": "\n            The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timing of the flaw. The simplest way data corruption may occur involves the system's reuse of the freed memory. Use-after-free errors have two common and sometimes overlapping causes:\n               \n                  Error conditions and other exceptional circumstances.\n                  Confusion over which part of the program is responsible for freeing the memory.\n               \n            In this scenario, the memory in question is allocated to another pointer validly at some point after it has been freed. The original pointer to the freed memory is used again and points to somewhere within the new allocation. As the data is changed, it corrupts the validly used memory; this induces undefined behavior in the process.\n            If the newly allocated data happens to hold a class, in C++ for example, various function pointers may be scattered within the heap data. If one of these function pointers is overwritten with an address to valid shellcode, execution of arbitrary code can be achieved.\n         \n         ",
        "url": "https://cwe.mitre.org/data/definitions/416.html",
        "is_category": False
    },
    "CWE-476": {
        "cwe_id": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
        "description": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.",
        "extended_description": "NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.\n         ",
        "url": "https://cwe.mitre.org/data/definitions/476.html",
        "is_category": False
    },
    "CWE-787": {
        "cwe_id": "CWE-787",
        "cwe_name": "Out-of-bounds Write",
        "description": "The product writes data past the end, or before the beginning, of the intended buffer.",
        "extended_description": "Typically, this can result in corruption of data, a crash, or code execution.  The product may modify an index or perform pointer arithmetic that references a memory location that is outside of the boundaries of the buffer.  A subsequent write operation then produces undefined or unexpected results.\n         ",
        "url": "https://cwe.mitre.org/data/definitions/787.html",
        "is_category": False
    }
}