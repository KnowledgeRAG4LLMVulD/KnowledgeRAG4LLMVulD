import os
from codegen import CodeGenPass
import argparse
import numpy as np
import torch
import torchdata.datapipes as dp
from torch.utils.data import DataLoader
import json
from pynvml import *
import csv
import qwen_processor

torch.set_printoptions(profile="full")
csv.field_size_limit(sys.maxsize)
MAX_LEN = 128

DEEPSEEK_SWITCH = True

class CSVDataLoader:
    def __init__(self, root, dim_model=1024, pretrain_type='350M'):
        self.root = root
        if not DEEPSEEK_SWITCH:
            self.codegen_trainer = CodeGenPass()
        self.device_0 = "cuda:4"
        self.pretrain_type = pretrain_type
        if not DEEPSEEK_SWITCH:
            self.model, self.tokenizer = self.codegen_trainer.setup_model(
                type=self.pretrain_type)
            self.model.resize_token_embeddings(len(self.tokenizer))
        self.dim_model = dim_model
        if DEEPSEEK_SWITCH:
            self.deepseek_processor = qwen_processor.CodeProcessor(self.device_0)

    def get_hidden_state(self, decoded_program):
        input_ids = self.tokenizer(
            decoded_program, return_tensors="pt", truncation=True, max_length=20000).input_ids

        input_ids = input_ids.to(self.device_0)
        split_input_ids = torch.split(input_ids, 2048, 1)
        hidden_states = []
        for input_id in split_input_ids:
            outputs = self.model(input_ids=input_id)[2]
            outputs = [h.detach() for h in outputs]
            attention_hidden_states = outputs[1:]
            hidden_state = attention_hidden_states[-1]
            nl_indices = torch.where((input_id == 198) | (input_id == 628))
            if len(nl_indices) > 1:
                nl_index = nl_indices[1]
            else:
                nl_index = nl_indices[0]
            nl_final_attention_states = hidden_state[torch.arange(
                hidden_state.size(0)), nl_index]
            hidden_states.append(nl_final_attention_states)
        final_attention_states = torch.cat(hidden_states, axis=0)
        return final_attention_states

    def row_processer(self, row):
        try:
            decoded_program = row[0]
            label = json.loads(row[1])
            # print("Original label:", label)
        except:
            return None
        if not DEEPSEEK_SWITCH:
            hidden_states = self.get_hidden_state(
                decoded_program=decoded_program)
        if DEEPSEEK_SWITCH:
            hidden_states = self.deepseek_processor.get_hidden_state(decoded_program)
        sample_shape = list(hidden_states.size())[0]
        native_sample_size = len(decoded_program.split("\n"))
        print("Sample shape:", sample_shape)
        print("Native sample size:", native_sample_size)
        print("MAX_LEN:", MAX_LEN)
        if sample_shape+1 > MAX_LEN or native_sample_size != (sample_shape+1):
            print(sample_shape, MAX_LEN, native_sample_size)
            print("decoded_program:", decoded_program)
            import pdb
            pdb.set_trace()
            return None
        # Padding
        sample_padding = torch.zeros(
            MAX_LEN - sample_shape, self.dim_model).to(self.device_0)

        final_hidden_states = torch.cat(
            [hidden_states, sample_padding], axis=0)
        # Binary tensor for NL tokens
        NL_tokens = np.zeros(MAX_LEN)
        try:
            NL_tokens[label] = np.ones(len(label))
        except:
            print('Label shape wrong')
            return None
        NL_tokens = torch.tensor(NL_tokens)
        NL_tokens = NL_tokens.to(self.device_0)
        # Masking
        attention_mask = torch.cat(
            [torch.ones(sample_shape), torch.zeros(MAX_LEN - sample_shape)], axis=0
        ).to(self.device_0)
        output = (final_hidden_states, NL_tokens, attention_mask)
        return output

    def data_load(self):
        datapipe = dp.iter.FileLister([self.root]).filter(
            filter_fn=lambda filename: filename.endswith(".csv")
        )
        datapipe = dp.iter.FileOpener(datapipe, mode="rt")
        datapipe = datapipe.parse_csv(delimiter=",")
        datapipe = datapipe.map(self.row_processer)
        datapipe = datapipe.filter(lambda sample: sample is not None)
        return datapipe


def save_data():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_path", help="Path to data root")
    ap.add_argument("data_name", help="Name of dataset")
    ap.add_argument("biggest_model", help="")
    ap.add_argument("deepseek",help="if use deepseek")
    
    args = ap.parse_args()
    global DEEPSEEK_SWITCH
    if "deepseek" in args.deepseek.lower() or "qwen" in args.deepseek.lower():
        DEEPSEEK_SWITCH = True
    else:
        DEEPSEEK_SWITCH = False
    data_path = args.data_path
    data_name = args.data_name
    biggest_model = int(args.biggest_model)

    if biggest_model:
        pretrain_types = ['16B']
    else:
        pretrain_types = ['350M', '2B', '6B']
        pretrain_types = ['350M']
    if args.deepseek.lower() == "deepseek":
        pretrain_types = ['deepseek']
    if args.deepseek.lower() == "qwen32b":
        pretrain_types = ['qwen32b']


    for pretrain_type in pretrain_types:
        if pretrain_type == '350M':
            dim_model = 1024
        elif pretrain_type == '2B':
            dim_model = 2560
        elif pretrain_type == '6B':
            dim_model = 4096
        elif pretrain_type == '16B':
            dim_model = 6144
        elif pretrain_type == 'deepseek':
            dim_model = 4096
        elif pretrain_type == 'deepseek_distill':
            dim_model = 3584
        elif pretrain_type == 'qwen32b':
            dim_model = 5120
        print(f'Loading {pretrain_type} codegen states on {data_name}')

        # Data loading
        current_path = os.getcwd()
        root = f'{current_path}/{data_path}/{data_name}'
        data = CSVDataLoader(
            root=root,
            dim_model=dim_model,
            pretrain_type=pretrain_type,
        )
        datapipe = data.data_load()
        data_loaded = DataLoader(
            dataset=datapipe, batch_size=1, drop_last=True
        )
        save_path = f'{current_path}/{data_path}/codegen_states'
        try:
            os.mkdir(save_path)
        except OSError:
            pass 
        os.chdir(save_path)
        # pretrain_type = "starcoder"
        if not os.path.isdir(f"{data_name}_{pretrain_type}"):
            os.mkdir(f"{data_name}_{pretrain_type}")

        
        for batch_iter, batch in enumerate(data_loaded):
            input = batch[0][0].detach()
            label = batch[1][0].detach()
            mask = batch[2][0].detach()
            print_out = False
            if print_out:
                print(input.size())
                print(label.size())
                print(mask.size())
            hidden_layer_dict = {'input': input, 'label': label, 'mask': mask}
            save_path = '{}_{}/{}.pt'.format(
                data_name, pretrain_type, batch_iter)
            torch.save(hidden_layer_dict, save_path)
            for tensor in hidden_layer_dict.items():
                tensor[1].detach()
        print('Finished preloading {} samples'.format(batch_iter))


if __name__ == "__main__":
    save_data()

