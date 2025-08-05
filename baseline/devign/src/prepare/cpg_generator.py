import json
import re
import subprocess
import os.path
import os
import time
from tqdm import tqdm  
# from .cpg_client_wrapper import CPGClientWrapper  # Not needed for our evaluation
#from ..data import datamanager as data


def funcs_to_graphs(funcs_path):
    # client = CPGClientWrapper()  # Not used in our evaluation pipeline
    # query the cpg for the dataset
    print(f"Creating CPG.")
    # graphs_string = client(funcs_path)
    # removes unnecessary namespace for object references
    # graphs_string = re.sub(r"io\.shiftleft\.codepropertygraph\.generated\.", '', graphs_string)
    # graphs_json = json.loads(graphs_string)
    # return graphs_json["functions"]
    raise NotImplementedError("This function is not used in our evaluation pipeline. Use joern_parse and joern_create instead.")


def graph_indexing(graph):
    idx = int(graph["file"].split(".c")[0].split("/")[-1])
    del graph["file"]
    return idx, {"functions": [graph]}


def joern_parse(joern_path, input_path, output_path, file_name):
    out_file = file_name + ".bin"
    joern_parse_bin = os.path.join(joern_path, "joern-parse")
    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)
    out_file_path = os.path.join(output_path, out_file)
    os.makedirs(output_path, exist_ok=True)
    env = os.environ.copy()
    env["JAVA_HOME"] = "/usr/lib/jvm/java-8-openjdk-amd64"
    
    try:
        print(f"🔄 Parsing CPG: {file_name}")
        start_time = time.time()
        
        joern_parse_call = subprocess.run([
            joern_parse_bin,
            input_path,
            "--out",
            out_file_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, env=env, timeout=30)
        
        end_time = time.time()
        duration = end_time - start_time
        print(f"✅ CPG parsed in {duration:.1f}s: {out_file}")
        
        if joern_parse_call.stdout.strip():
            print(f"   stdout: {joern_parse_call.stdout.strip()}")
        if joern_parse_call.stderr.strip():
            print(f"   stderr: {joern_parse_call.stderr.strip()}")
            
    except subprocess.TimeoutExpired:
        print(f"⏰ CPG parsing TIMEOUT (30s): {file_name}")
        raise RuntimeError(f"CPG parsing timed out after 30s for {file_name}")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ CPG parsing FAILED: {file_name}")
        print(f"   Error: {e.stderr}")
        raise RuntimeError(f"CPG parsing failed for {file_name}: {e.stderr}")
        
    except Exception as e:
        print(f"💥 UNEXPECTED ERROR during CPG parsing: {file_name}")
        print(f"   Exception: {str(e)}")
        raise RuntimeError(f"Unexpected error during CPG parsing for {file_name}: {str(e)}")

    return out_file


def joern_create(joern_path, in_path, out_path, cpg_files):
    joern_bin = os.path.join(joern_path, "joern")
    script_path = "/home/fdse/wentai/Vul-RAG.exp/devign/joern/run-graph-for-funcs.sc"
    json_files = []
    successful_files = []
    failed_files = []
    timeout_files = []
    
    env = os.environ.copy()
    env["JAVA_HOME"] = "/usr/lib/jvm/java-8-openjdk-amd64"
    
    for cpg_file in tqdm(cpg_files, desc="Converting CPG to JSON", unit="file"):
        json_file_name = f"{cpg_file.split('.')[0]}.json"
        cpg_full_path = os.path.abspath(os.path.join(in_path, cpg_file))
        json_out = os.path.abspath(os.path.join(out_path, json_file_name))
        params = f"cpgFile={cpg_full_path},outputFile={json_out}"
        
        try:
            print(f"\n🔄 Converting {cpg_file} to JSON...")
            start_time = time.time()
            
            result = subprocess.run([
                joern_bin,
                "--script", script_path,
                "--params", params
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, check=True, timeout=30)
            
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"✅ Success in {duration:.1f}s: {json_file_name}")
            json_files.append(json_file_name)
            successful_files.append(cpg_file)
            
            if result.stdout.strip():
                print(f"   stdout: {result.stdout.strip()}")
            if result.stderr.strip():
                print(f"   stderr: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            print(f"⏰ TIMEOUT (30s): {cpg_file} - skipping")
            timeout_files.append(cpg_file)
            continue
            
        except subprocess.CalledProcessError as e:
            print(f"❌ FAILED: {cpg_file}")
            print(f"   Error: {e.stderr}")
            failed_files.append(cpg_file)
            continue
            
        except Exception as e:
            print(f"💥 UNEXPECTED ERROR: {cpg_file}")
            print(f"   Exception: {str(e)}")
            failed_files.append(cpg_file)
            continue
    
    print(f"\n📊 CPG to JSON Conversion Summary:")
    print(f"   ✅ Successful: {len(successful_files)}/{len(cpg_files)}")
    print(f"   ⏰ Timeout (30s): {len(timeout_files)}")
    print(f"   ❌ Failed: {len(failed_files)}")
    
    if timeout_files:
        print(f"   Timeout files: {timeout_files}")
    if failed_files:
        print(f"   Failed files: {failed_files}")
    
    return json_files


def json_process(in_path, json_file):
    if os.path.exists(os.path.join(in_path, json_file)):
        try:
            # Try UTF-8 first (default)
            with open(os.path.join(in_path, json_file), 'r', encoding='utf-8') as jf:
                cpg_string = jf.read()
        except UnicodeDecodeError:
            try:
                # Try latin-1 if UTF-8 fails
                with open(os.path.join(in_path, json_file), 'r', encoding='latin-1') as jf:
                    cpg_string = jf.read()
            except UnicodeDecodeError:
                try:
                    # Try with error handling
                    with open(os.path.join(in_path, json_file), 'r', encoding='utf-8', errors='ignore') as jf:
                        cpg_string = jf.read()
                except Exception as e:
                    print(f"Failed to read JSON file {json_file}: {e}")
                    return None
        try:
            cpg_string = re.sub(r"io\.shiftleft\.codepropertygraph\.generated\.", '', cpg_string)
            cpg_json = json.loads(cpg_string)
            container = [graph_indexing(graph) for graph in cpg_json["functions"] if graph["file"] != "N/A"]
            return container
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON in file {json_file}: {e}")
            return None
        except Exception as e:
            print(f"Error processing CPG JSON {json_file}: {e}")
            return None
    return None

'''
def generate(dataset, funcs_path):
    dataset_size = len(dataset)
    print("Size: ", dataset_size)
    graphs = funcs_to_graphs(funcs_path[2:])
    print(f"Processing CPG.")
    container = [graph_indexing(graph) for graph in graphs["functions"] if graph["file"] != "N/A"]
    graph_dataset = data.create_with_index(container, ["Index", "cpg"])
    print(f"Dataset processed.")

    return data.inner_join_by_index(dataset, graph_dataset)
'''

# client = CPGClientWrapper()
# client.create_cpg("../../data/joern/")
# joern_parse("../../joern/joern-cli/", "../../data/joern/", "../../joern/joern-cli/", "gen_test")
# print(funcs_to_graphs("/data/joern/"))
"""
while True:
    raw = input("query: ")
    response = client.query(raw)
    print(response)
"""
