import os
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from torch.utils.data import Dataset
import torch.utils.checkpoint
os.environ["CUDA_VISIBLE_DEVICES"] = "0,1,2"

class VoltronDataset(Dataset):
    def __init__(self, data_root):
        self.samples = []
        for i, code_file_path in enumerate(os.listdir(data_root)):
            if i > 1:
                break
            with open(os.path.join(data_root, code_file_path), 'r') as code_file:
                for code_block in code_file.read().splitlines():
                    encoded = [int(x) for x in code_block.split('\t')]
                    self.samples.append(encoded)

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]


class CodeGenPass():
    def collate_batch(self, batch):
        # Padds batch of variable length
        tensor_batch = [torch.tensor(x) for x in batch]
        max_len = max([x.squeeze().numel() for x in tensor_batch])
        padded_batch = [torch.nn.functional.pad(x, pad=(
            0, max_len - x.numel()), mode='constant', value=0) for x in tensor_batch]
        padded_batch = torch.stack(padded_batch)
        return padded_batch

    def setup_model(self, type):
        print('Loading codegen model ...')
        starcoder = "bigcode/starcoder"
        codegen = f"Salesforce/codegen-{type}-multi"
        codegen_token = "Salesforce/codegen-350M-mono"

        model = AutoModelForCausalLM.from_pretrained(
            codegen, output_hidden_states=True, torch_dtype=torch.bfloat16, device_map="auto")
        model.eval()
        tokenizer = AutoTokenizer.from_pretrained(
            codegen_token, fp16=True)
        print('Finished loading')
        return model, tokenizer

    def get_hidden_state(self, decoded_program=None, model=None, tokenizer=None, device=None):
        nl_replacement = '\n'
        if not isinstance(decoded_program, str):
            decoded_program = " ".join(decoded_program)
            if len(decoded_program) > 2048:
                decoded_program = decoded_program[:2048]

        decoded_program = decoded_program.replace(
            '#TAB#', '\t').replace('#NL#', nl_replacement)
        input_ids = tokenizer(
            decoded_program, return_tensors='pt').input_ids.to(device)

        # nl_ids = tokenizer(
        #     '\n', return_tensors='pt').input_ids.to(device)
        # print('nl id: ', nl_ids)
        nl_indices = torch.where(input_ids == 198)

        try:
            outputs = model(input_ids=input_ids)
        except:
            return
        hidden_states = outputs[2]
        attention_hidden_states = hidden_states[1:]
        final_attention_states = attention_hidden_states[-1]
        nl_final_attention_states = final_attention_states[torch.arange(
            final_attention_states.size(0)), nl_indices[1]]
        # project fix number (dense to 1024)
        return nl_final_attention_states, len(nl_indices[1])


if __name__ == '__main__':
    codegen_trainer = CodeGenPass()
    nl_final_attention_states = codegen_trainer.get_hidden_state_local()
    print('\n\n\n'+'done\n\n\n')
