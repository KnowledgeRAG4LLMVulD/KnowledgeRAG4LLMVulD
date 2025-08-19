import json
import sys
import os
import argparse
import time
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils.llm_client as llm_client

LLM_CLIENT = None

def extract_result_from_output(output):
    """
    Extracts content between <result> and </result> tags and determines the result
    
    Args:
        output (str): LLM output text
        
    Returns:
        int: Returns 1 if YES is found, 0 if NO is found
        
    Raises:
        ValueError: If <result> tags are not found or the result contains neither YES nor NO
    """
    
    pattern = r'<result>(.*?)</result>'
    matches = re.findall(pattern, output, re.IGNORECASE | re.DOTALL)
    
    if not matches:
        raise ValueError("No <result> and </result> tags found")
    
    result_content = matches[-1].strip()
    
    if "YES" in result_content.upper():
        return 1
    elif "NO" in result_content.upper():
        return 0
    else:
        raise ValueError(f"Result contains neither YES nor NO, actual content: '{result_content}'")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", type=str, required=True)
    parser.add_argument("--output_file", type=str, required=True)
    parser.add_argument("--model_name", type=str, required=True)
    parser.add_argument("--prompt_type", type=int, choices=[0, 1, 2, 3, 4], required=True,
                        help="Prompt type: 0=basic without explanation, 1=basic with explanation, 2=COT, 3=advanced COT, 4=CWE description")
    parser.add_argument("--cwe_id", type=str, help="CWE ID for prompt type 4 (CWE description)")
    parser.add_argument("--resume", action="store_true")

    parser.add_argument(
        '--thread_pool_size',
        type = int,
        default = 5,
        help = "Number of threads to use for parallel processing"
    )

    parser.add_argument(
        '--retry_time',
        type = int,
        default = 5,
        help = "Number of retry attempts for LLM requests"
    )

    parser.add_argument(
        '--model_settings',
        type = str,
        default = None,
        help = (
            'The settings of the model, format is a key-value pair separated by ";". '
            'e.g. "temperature=0.2;max_tokens=1024;stream=true"'
        )
    )

    args = parser.parse_args()
    args.model_settings = llm_client.parse_kv_string_to_dict(args.model_settings)
    return args

def generate_basic_prompt_without_explanation(code_snippet) -> str:
    if code_snippet is None:
        raise ValueError("code_snippet is required.")
    prompt = f"""Given the following code, please detect whether there is a vulnerability in the code snippet,
Code Snippet:
'''
{code_snippet}
'''
and ultimately answer <result> YES </result> or <result> NO </result> without explanation.
"""
    return prompt

def generate_basic_prompt_with_explanation(code_snippet) -> str:
    if code_snippet is None:
        raise ValueError("code_snippet is required.")
    prompt = f"""Given the following code, please detect whether there is a vulnerability in the code snippet.
Code Snippet:
'''
{code_snippet}
'''
Answer <result> YES </result> or <result> NO </result>, and explain why you think so.
"""
    return prompt

def generate_cot_prompt(code_snippet) -> str:
    if code_snippet is None:
        raise ValueError("code_snippet is required.")
    prompt = f"""I want you to act as a vulnerability detection expert.
Initially, you need to explain the behavior of the code. Subsequently, you need to determine whether the code is vulnerable. Answer in <result> YES </result> or <result> NO </result>.
The code is:
{code_snippet}
"""
    return prompt

def generate_advanced_cot_prompt(code_snippet) -> str:
    if code_snippet is None:
        raise ValueError("code_snippet is required.")
    prompt = f"""I want you to act as a vulnerability detection system. Initially, you need to explain the behavior of the given code. Subsequently, analyze whether there are potential root causes that could result in vulnerabilities. Based on above analysis, determine whether the code is vulnerable, and conclude your answer with either <result> YES </result> or <result> NO </result>.
### Code Snippet:
{code_snippet}
"""
    return prompt

def generate_prompt_with_CWE_description(code_snippet, cwe_id) -> str:
    if code_snippet is None:
        raise ValueError("code_snippet is required.")
    
    if cwe_id is None:
        raise ValueError("cwe_id is required for prompt with CWE description.")
    
    # CWE descriptions (simplified version - in a real implementation, you might want to load these from a file)
    cwe_descriptions = {
        "CWE-20": "Improper Input Validation: The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
        "CWE-125": "Out-of-bounds Read: The product reads data past the end, or before the beginning, of the intended buffer.",
        "CWE-264": "Permissions, Privileges, and Access Controls: Weaknesses in this category are related to the management of permissions, privileges, and other security features that are used to perform access control.",
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor: The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        "CWE-401": "Missing Release of Memory after Effective Lifetime: The product does not sufficiently track and release allocated memory after it has been used, making the memory unavailable for reallocation and reuse.",
        "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer: The product performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
        "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'): The product contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.",
        "CWE-416": "Use After Free: Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        "CWE-476": "NULL Pointer Dereference: A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.",
        "CWE-787": "Out-of-bounds Write: The product writes data past the end, or before the beginning, of the intended buffer."
    }
    
    cwe_description = cwe_descriptions.get(cwe_id, "Description not available")
    
    prompt = f"""I want you to act as a vulnerability detection system. I will provide you with a code snippet and a CWE description. Please analyze the code to determine if it contains the vulnerability described in the CWE. Answer in <result> YES </result> or <result> NO </result>.
Code Snippet:
{code_snippet}
The CWE description:
{cwe_description}
"""
    return prompt

def detect_code(code_snippet, args):
    if args.prompt_type == 0:
        prompt = generate_basic_prompt_without_explanation(code_snippet)
    elif args.prompt_type == 1:
        prompt = generate_basic_prompt_with_explanation(code_snippet)
    elif args.prompt_type == 2:
        prompt = generate_cot_prompt(code_snippet)
    elif args.prompt_type == 3:
        prompt = generate_advanced_cot_prompt(code_snippet)
    elif args.prompt_type == 4:
        if not args.cwe_id:
            raise ValueError("CWE ID is required for prompt type 4")
        prompt = generate_prompt_with_CWE_description(code_snippet, args.cwe_id)
    else:
        raise ValueError(f"Invalid prompt type: {args.prompt_type}")
    
    last_exception = None
    for attempt in range(args.retry_time):
        try:
            prompt_dict = llm_client.generate_simple_prompt(prompt)
            output = LLM_CLIENT.generate_text(prompt_dict, args.model_settings)
            assert output is not None, "Output is None"
            assert "<result>" in output, "Output does not contain <result>"

            detect_result = extract_result_from_output(llm_client.remove_thinking(output))
            
            return detect_result, prompt, output
            
        except Exception as e:
            last_exception = e
            print(f"Attempt {attempt + 1}/{args.retry_time} failed: {str(e)}")
            if attempt < args.retry_time - 1:
                time.sleep(1) 
            
    raise last_exception

def process_single_item(item, args):
    try:
        code_before_change = item["code_before_change"]
        result_of_before = detect_code(code_before_change, args)

        code_after_change = item["code_after_change"]
        result_of_after = detect_code(code_after_change, args)

        return {
            "id": item["id"],
            "cve_id": item["cve_id"],
            "model_name": args.model_name,
            "model_settings": args.model_settings,
            "detect_result_before": {
                "code_snippet": code_before_change,
                "prompt": result_of_before[1],
                "output": result_of_before[2],
                "final_result": result_of_before[0]
            },
            "detect_result_after": {
                "code_snippet": code_after_change,
                "prompt": result_of_after[1],
                "output": result_of_after[2],
                "final_result": result_of_after[0]
            }
        }
    except Exception as e:
        print(f"Error occurred while processing item {item.get('id', 'unknown')}: {str(e)}")
        raise

def load_existing_results(output_file_path):
    if os.path.exists(output_file_path):
        try:
            with open(output_file_path, "r") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, IOError) as e:
            print(f"Failed to read existing results file: {str(e)}")
            return []
    return []

def save_results_to_file(output_data, output_file_path, lock):
    with lock:
        try:
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
            with open(output_file_path, "w") as f:
                json.dump(output_data, f, indent=4)
        except Exception as e:
            print(f"Failed to save results file: {str(e)}")

def main():
    global LLM_CLIENT
    args = parse_args()
    
    LLM_CLIENT = llm_client.get_llm_client(args.model_name)
    print(f"LLM client initialization completed: {LLM_CLIENT.model_name}")
    
    with open(f"data/test/{args.input_file}", "r") as f:
        data = json.load(f)

    output_file_path = f"output/baseline/{args.output_file}"
    
    output_data = []
    processed_ids = set()
    
    if args.resume:
        existing_results = load_existing_results(output_file_path)
        output_data.extend(existing_results)
        processed_ids = {item["id"] for item in existing_results}
        print(f"Resume mode: Loaded {len(existing_results)} processed results")
    
    items_to_process = [item for item in data if item["id"] not in processed_ids]
    print(f"Total {len(data)} items, {len(items_to_process)} items to process")
    
    if not items_to_process:
        print("All items have been processed!")
        return
    
    lock = threading.Lock()
    
    with tqdm(total=len(items_to_process), desc="Processing progress", unit="item") as pbar:
        with ThreadPoolExecutor(max_workers=args.thread_pool_size) as executor:
            future_to_item = {executor.submit(process_single_item, item, args): item for item in items_to_process}
            
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                    
                    with lock:
                        output_data.append(result)
                        processed_count = len(output_data)
                        
                        pbar.set_postfix({
                            "Current ID": item.get('id', 'unknown'),
                            "Total Progress": f"{processed_count}/{len(data)}"
                        })
                        pbar.update(1)
                    
                    save_results_to_file(output_data, output_file_path, lock)
                    
                except Exception as e:
                    with lock:
                        pbar.set_postfix({
                            "Error ID": item.get('id', 'unknown'),
                            "Error": str(e)[:30] + "..."
                        })
                        pbar.update(1)
                    
                    tqdm.write(f"Item {item.get('id', 'unknown')} processing failed: {str(e)}")
                    continue
    
    print(f"\nAll tasks completed, results saved to {output_file_path}")
    print(f"Processed a total of {len(output_data)} items")

if __name__ == "__main__":
    main()

### python src_baseline/baseline_detect.py --input_file linux_kernel_CWE-401_testset.json --output_file linux_kernel_CWE-401_result_gpt-4o-mini.json --model_name gpt-4o-mini --model_settings temperature=0.01 --prompt_type 2 --resume --thread_pool_size 10