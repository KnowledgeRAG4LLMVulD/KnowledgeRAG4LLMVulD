import os
import numpy as np
import torch
from transformers import (
    AutoTokenizer,
    AutoConfig,
    AutoModelForCausalLM,
)

model_path = "/other/DeepSeek-R1-Distill-Qwen-7B"

class CodeProcessor:
    def __init__(self, cuda_device, model_path=model_path):
        self.device_0 = cuda_device
        print(f"Using device: {self.device_0}")
        
        try:
            print(f"Checking model path: {model_path}")
            print(f"Files in model directory: {os.listdir(model_path)}")
            
            print("Loading tokenizer...")

            self.tokenizer = AutoTokenizer.from_pretrained(
                model_path,
                trust_remote_code=True
            )

            self.tokenizer.pad_token = self.tokenizer.eos_token
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id  # 151645


            test_text = "Hello\nWorld"
            test_tokens = self.tokenizer.encode(test_text)
            print(f"Test text: {repr(test_text)}")
            print(f"Test tokens: {test_tokens}")
            print(f"Decoded test tokens: {repr(self.tokenizer.decode(test_tokens))}")
            

            for i in range(len(test_tokens) - 1):
                partial_decode = self.tokenizer.decode([test_tokens[i]])
                next_decode = self.tokenizer.decode([test_tokens[i+1]])
                print(f"Token {test_tokens[i]} -> '{repr(partial_decode)}', Token {test_tokens[i+1]} -> '{repr(next_decode)}'")
            
            print("Loading model...")
            config = AutoConfig.from_pretrained(model_path)

            os.environ["CUDA_VISIBLE_DEVICES"] = cuda_device.split(":")[-1]
            self.model = AutoModelForCausalLM.from_pretrained(
                model_path,
                config=config,
                trust_remote_code=True,
                torch_dtype=torch.float32,
                device_map=None
            ).to(self.device_0)
            self.model.eval()
            print("Model loaded successfully")
            
        except Exception as e:
            print(f"Error during initialization: {e}")
            raise

    def get_hidden_state(self, decoded_program):
        try:
            lines = decoded_program.split('\n')
            print(f"Total Line Count: {len(lines)}")
            

            hidden_states = []
            

            for k in range(1, len(lines)):

                partial_program = '\n'.join(lines[:k]) + '\n'


                inputs = self.tokenizer(
                    partial_program,
                    return_tensors="pt",
                    truncation=True,
                    max_length=131072
                )
                input_ids = inputs['input_ids'].to(self.device_0)
                

                with torch.no_grad():
                    outputs = self.model(
                        input_ids=input_ids,
                        output_hidden_states=True
                    )
                    
                    if isinstance(outputs, tuple):
                        all_hidden_states = outputs[2]
                    else:
                        all_hidden_states = outputs.hidden_states
                    
                    attention_hidden_states = all_hidden_states[1:]
                    hidden_state = attention_hidden_states[-1]
                    

                    last_token_state = hidden_state[:, -1, :]
                    hidden_states.append(last_token_state)
            
  
            if hidden_states:
                final_attention_states = torch.cat(hidden_states, dim=0)
                return final_attention_states
            else:
                return torch.tensor([])
            
        except Exception as e:
            print(f"Error in get_hidden_state: {e}")
            import traceback
            traceback.print_exc()
            raise


if __name__ == "__main__":
    code = """int add(int a,int b)
{
    int c = a + b;
    ind d = a - b;

    return c;
}"""
    
    qwen_processor = CodeProcessor("cuda:0")

    hidden_states = qwen_processor.get_hidden_state(code)
    print(hidden_states.shape)
    print("how many new lines in code: {}".format(len(code.split('\n'))-1))
