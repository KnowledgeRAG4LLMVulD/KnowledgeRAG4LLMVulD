This project is a reproduction of the [LLMAO](https://github.com/squaresLab/LLMAO) project on our dataset.

In addition to the environment configuration required by LLMAO, since we fine-tune DeepseekR1-7b and Qwen2.5-32b, it is necessary to download these two models and modify the model paths in `qwen_processor.py` and `deepseek_distill_processor.py`.

Preprocessing:
```
python3 -u codegen_loading_deepseek7b.py newdata CWE362 1 deepseek7b
python3 -u codegen_loading_qwen.py newdata CWE362 1 qwen32b
```

Training:
```
python3 -u training_deepseek7b.py newdata CWE362 deepseek7b 1
python3 -u training_qwen.py newdata CWE362 qwen32b 1
```

Evaluation:
```
python3 -u inference_deepseek7b.py CWE362
python3 -u inference_qwen.py CWE362
```
