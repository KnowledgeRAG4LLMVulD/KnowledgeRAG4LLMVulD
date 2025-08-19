# Project Description

This project is a vulnerability detection tool based on Large Language Models (LLM) that incorporates Retrieval-Augmented Generation (RAG) technology to improve detection accuracy. It mainly consists of three core components: knowledge extraction, vulnerability detection, and result evaluation.

## Directory Structure

```
/
├── README.md                   # Project description document
├── requirements.txt            # Project dependencies
├── data/                       # Dataset directory
│   ├── test/                   # Test dataset
│   └── train/                  # Training dataset
├── output/                     # Output directory
│   ├── baseline/               # Baseline results
│   ├── detect/                 # Detection results
│   │   ├── metrics/            # Evaluation metrics
│   │   └── ...                 # Detection result files
│   └── knowledge/              # Extracted knowledge base
├── src/                        # Source code directory
│   ├── evaluate_result.py      # Result evaluation script
│   ├── extract_knowledge.py    # Knowledge extraction script
│   └── vulnerability_detect.py # Main vulnerability detection script
└── utils/                      # Utility scripts directory
    ├── bm25_retriever.py       # BM25 retrieval module
    └── llm_client.py           # LLM client interface
```

## Method Overview

### Knowledge Extraction
```bash
python src/extract_knowledge.py --input_file_name linux_kernel_CWE-401_data.json --output_file_name linux_kernel_CWE-401_knowledge.json --model_name gpt-4o-mini --thread_pool_size 10 --resume --model_settings temperature=0.01
```

This command extracts vulnerability-related knowledge from the training dataset and saves it to the specified output file. Parameter descriptions:
- `--input_file_name`: Input training dataset file name.
- `--output_file_name`: Output knowledge base file name.
- `--model_name`: Name of the LLM model used.
- `--thread_pool_size`: Thread pool size for parallel processing.
- `--resume`: If an existing knowledge base file exists, resume processing from it.
- `--model_settings`: LLM model setting parameters.

### Detection
```bash
python src/vulnerability_detect.py --input_file_name linux_kernel_CWE-401_testset.json --output_file_name linux_kernel_CWE-401_result_gpt-4o-mini.json --knowledge_file_name linux_kernel_CWE-401_knowledge.json --model_name gpt-4o-mini --summary_model_name gpt-4o-mini --retrieval_top_k 20 --thread_pool_size 10 --resume --model_settings temperature=0.01 --early_return --max_knowledge 3
```

This command uses the extracted knowledge base to detect vulnerabilities in the test dataset and saves the detection results to the specified output file. Parameter descriptions:
- `--input_file_name`: Input test dataset file name.
- `--output_file_name`: Output detection result file name.
- `--knowledge_file_name`: Knowledge base file name used.
- `--model_name`: LLM model name used for detection.
- `--summary_model_name`: LLM model name used for generating summary function information for retrieval.
- `--retrieval_top_k`: Number of Top-K retrieval results.
- `--thread_pool_size`: Thread pool size for parallel processing.
- `--resume`: If an existing detection result file exists, resume processing from it.
- `--model_settings`: LLM model setting parameters.
- `--early_return`: Return early if a clear solution behavior is found.
- `--max_knowledge`: Maximum number of knowledge entries to use.

### Calculate Evaluation Metrics
```bash
python src/evaluate_result.py --input_files $(ls -F output/detect | grep -v '/$')
```

This command calculates evaluation metrics for the detection results and saves the evaluation results to the specified output directory. Parameter descriptions:
- `--input_files`: List of input detection result files.
- `--baseline`: Whether to calculate baseline evaluation metrics.

## Dependencies

Python version 3.12

You can install the dependencies using the following command:
```bash
pip install -r requirements.txt
```
Also, download the spaCy model using the following command:
```bash
python -m spacy download en_core_web_sm
```

## Usage Steps
1. **Prepare Dataset**: Create the data directory and output directory with subdirectories according to the directory structure specified in this README, and place the training dataset and test dataset (in the `/benchmark` folder of project [KnowledgeRAG4LLMVulD](https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD)) in the `data/train/` and `data/test/` directories respectively.
2. **Configure API**: Replace the model's `api_key` and `base_url` in `utils/llm_client.py` with your own API key and base URL.
3. **Extract Knowledge**: Run the `extract_knowledge.py` script to extract knowledge from the training dataset.
4. **Perform Detection**: Run the `vulnerability_detect.py` script to detect vulnerabilities in the test dataset.
5. **Evaluate Results**: Run the `evaluate_result.py` script to calculate evaluation metrics for the detection results.

## Notes
- Ensure that the required spaCy model `en_core_web_sm` for tokenization has been downloaded on your system.
- If you need to interrupt processing and resume later, you can use the `--resume` parameter.
