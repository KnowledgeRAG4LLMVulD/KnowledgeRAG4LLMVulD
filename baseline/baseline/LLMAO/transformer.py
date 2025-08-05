import torch
import torch.utils.checkpoint
from torch import nn
from transformers import AutoConfig, CodeGenTokenizerFast
try:
    from codegen import CodeGenPass
except:
    from llmao.codegen import CodeGenPass
    
try:
    from modeling_codegen import CodeGenBlock
except:
    from llmao.modeling_codegen import CodeGenBlock
import os
import numpy as np
import math
import pandas as pd
import json


MAX_LEN = 256

# 在此处添加全局变量
CUDA_DEVICE = "cuda:5"


class Utilities:
    def recall_prec_function(self, predictions, label, mask):
        """Computes masked prediction accuracies

        Args:
            predictions (2D float): _description_
            targets (2D binary float): _description_
            mask (2D binary float): _description_

        Returns:
            1D float: accuracy and precision per batch
        """

        num_bugs = torch.sum(label * mask) + 1e-6
        sigmoid_prediction = torch.round(torch.sigmoid(predictions))
        corrects = torch.eq(label, sigmoid_prediction)
        true_positive = torch.logical_and(mask, corrects)
        true_positive = true_positive * label

        accuracies = torch.logical_and(mask, corrects)
        final_acc = torch.mean(torch.sum(accuracies) / torch.sum(mask))

        recall = torch.sum(true_positive) / num_bugs
        precision = torch.sum(true_positive) / torch.sum(
            sigmoid_prediction * mask + 1e-6
        )
        return (
            recall.cpu().detach().numpy(),
            precision.cpu().detach().numpy(),
            final_acc.cpu().detach().numpy(),
        )  # 1D float

    def get_lr(
        self, iter, lr_decay_iters=10000, max_lr=1e-4, min_lr=1e-6, warmup_iters=500
    ):
        # 1) linear warmup for warmup_iters steps
        if iter < warmup_iters:
            return max_lr * iter / warmup_iters
        # 2) if iter > lr_decay_iters, return min learning rate
        if iter > lr_decay_iters:
            return min_lr
        # 3) in between, use cosine decay down to min learning rate
        decay_ratio = (iter - warmup_iters) / (lr_decay_iters - warmup_iters)
        assert 0 <= decay_ratio <= 1
        # coeff ranges 0..1
        coeff = 0.5 * (1.0 + math.cos(math.pi * decay_ratio))
        return min_lr + coeff * (max_lr - min_lr)


class TokenizeMask:
    def __init__(self, pretrain_type):
        self.max_token_len = 2048
        self.codegen_trainer = CodeGenPass()
        if pretrain_type == "350M":
            self.dim_model = 1024
        elif pretrain_type == "2B":
            self.dim_model = 2560
        elif pretrain_type == "6B":
            self.dim_model = 4096
        elif pretrain_type == "16B":
            self.dim_model = 6144
        self.model, self.tokenizer = self.codegen_trainer.setup_model(
            type=pretrain_type
        )

    def drop_double_newlines(self, code_line):
        code_line_split = code_line.split("\n")
        dropped_code = []
        is_even_newline = False
        for _, line in enumerate(code_line_split):
            if not line and not is_even_newline:
                is_even_newline = True
                continue
            is_even_newline = False
            dropped_code.append(line)
        dropped_code = "\n".join(dropped_code)
        return dropped_code

    def get_hidden_state(self, input_ids):
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
            nl_final_attention_states = hidden_state[
                torch.arange(hidden_state.size(0)), nl_index
            ]
            hidden_states.append(nl_final_attention_states)
        final_attention_states = torch.cat(hidden_states, axis=0)
        return final_attention_states

    def padding_pretrain(self, input):
        hidden_states = self.get_hidden_state(input_ids=input)
        sample_shape = list(hidden_states.size())[0]
        # Padding
        sample_padding = torch.zeros(self.max_token_len - sample_shape, self.dim_model)
        final_hidden_states = torch.cat([hidden_states, sample_padding], axis=0)
        # Masking
        attention_mask = torch.cat(
            [torch.ones(sample_shape), torch.zeros(self.max_token_len - sample_shape)],
            axis=0,
        )
        return (
            final_hidden_states,
            attention_mask,
            sample_shape,
        )

    def padding_naive(self, input):
        sample_shape = list(input.size())[0]
        sample_padding = torch.zeros(self.max_token_len - sample_shape)
        padded_input = torch.cat([input, sample_padding], axis=0)
        attention_mask = ((padded_input == 198) | (padded_input == 628)).to(int)
        return padded_input, attention_mask

    def generate_token_mask(self, input):
        input = self.drop_double_newlines(input)
        input_ids = self.tokenizer(
            input, return_tensors="pt", truncation=True, max_length=self.max_token_len
        )["input_ids"]
        decoded_input = self.tokenizer.decode(input_ids[0])
        padded_input, attention_mask, input_size = self.padding_pretrain(input_ids)
        return padded_input, attention_mask, input_size, decoded_input


class PreloadedDataset(torch.utils.data.Dataset):
    def __init__(self, root_path):
        self.tensor_paths = []
        self.path_batch_iter = -1
        for root, dirs, filenames in os.walk(root_path):
            for fileName in filenames:
                self.tensor_paths.append(int(fileName.replace(".pt", "")))
            break
        self.tensor_paths.sort()
        # self.max_file = int(self.tensor_paths[-1])
        self.max_file = len(self.tensor_paths)
        for i, file in enumerate(self.tensor_paths):
            self.tensor_paths[i] = root_path + str(file) + ".pt"
        print(f"Loading {self.max_file} samples of pretrained hidden states")

    def __getitem__(self, idx):
        sample = torch.load(self.tensor_paths[idx])
        input = sample["input"].to(CUDA_DEVICE)
        label = sample["label"].to(CUDA_DEVICE)
        mask = sample["mask"].to(CUDA_DEVICE)
        return input, label, mask

    def __len__(self):
        return self.max_file


class NaiveDataset(torch.utils.data.Dataset):
    def __init__(self, root_path):
        self.code_bugline = pd.read_csv(
            root_path + "/code_bugline.csv", names=["input", "label"]
        )
        self.max_token_len = 2048
        self.tokenizer = CodeGenTokenizerFast.from_pretrained(
            "Salesforce/codegen-350M-mono", fp16=True
        )

    def padding(self, input, label):
        sample_shape = list(input.shape)[0]
        nl_indices = torch.where((input == 198) | (input == 628))
        if len(nl_indices) > 1:
            nl_index = nl_indices[1]
        else:
            nl_index = nl_indices[0]

        # Padding input
        sample_padding = torch.zeros(self.max_token_len - sample_shape)
        padded_input = torch.cat([input, sample_padding], axis=0)

        # Binary tensor for NL tokens
        label = [x for x in label if x < list(nl_index.shape)[0]]
        token_label = nl_index[label]
        token_label = [x for x in token_label if x < self.max_token_len]
        NL_tokens = np.zeros(self.max_token_len)
        NL_tokens[token_label] = np.ones(len(token_label))
        NL_tokens = torch.tensor(NL_tokens)

        # Mask
        attention_mask_nopad = ((input == 198) | (input == 628)).to(int)
        attention_mask = torch.cat(
            [
                attention_mask_nopad,
                torch.zeros(self.max_token_len - list(attention_mask_nopad.shape)[0]),
            ],
            axis=0,
        )

        return padded_input.detach(), NL_tokens.detach(), attention_mask.detach()

    def __getitem__(self, idx):
        input = self.code_bugline["input"][idx]
        label = json.loads(self.code_bugline["label"][idx])
        input_ids = self.tokenizer(
            input, return_tensors="pt", truncation=True, max_length=self.max_token_len
        ).input_ids[0]
        input_ids.detach()
        padded_input, NL_tokens, attention_mask = self.padding(input_ids, label)
        return (
            padded_input.to(CUDA_DEVICE),
            NL_tokens.to(CUDA_DEVICE),
            attention_mask.to(CUDA_DEVICE),
        )

    def __len__(self):
        return len(self.code_bugline)


class Encoder(nn.Module):
    def __init__(self, num_layer=2, dim_model=1024, num_head=16):
        super(Encoder, self).__init__()
        self.num_layer = num_layer
        codegen_model = "Salesforce/codegen-350M-multi"
        config = AutoConfig.from_pretrained(codegen_model)
        config.n_layer = num_layer
        config.n_head = num_head
        config.n_embd = dim_model

        self.enc_layers = torch.nn.ModuleList(
            [CodeGenBlock(config) for _ in range(num_layer)]
        )

    def forward(self, x, padding_mask):
        """Transformer encoding layer

        Args:
            x (torch.tensor): shape [batch_size=batch_size, seq_len=256, num_dimensions=1024]
            padding_mask (torch.tensor): shape [batch_size=batch_size, seq_len=256]

        Returns:
            torch.tensor: [batch_size=batch_size, input_seq_len=256, d_model=1024]
        """
        for i in range(self.num_layer):
            x = self.enc_layers[i](x, attention_mask=padding_mask)
            x = x[0]
        return x  # (batch_size, input_seq_len, d_model)
import pdb

class VoltronTransformerPretrained(nn.Module):
    def __init__(self, num_layer=2, dim_model=1024, num_head=16, target_dim=256):
        super().__init__()
        self.target_dim = target_dim
        self.dim_projection = nn.Linear(dim_model, self.target_dim)
        self.encoder = Encoder(
            num_layer=num_layer, dim_model=self.target_dim, num_head=num_head
        )
        self.binary_prediction = nn.Linear(self.target_dim, 1)
        self.apply(self._init_weights)

    def _init_weights(self, module):
        """Initialize the weights."""
        if isinstance(module, (nn.Linear,)):
            torch.nn.init.xavier_normal_(module.weight)
            if module.bias is not None:
                module.bias.data.zero_()
        elif isinstance(module, nn.Embedding):
            torch.nn.init.xavier_normal_(module.weight)
            if module.padding_idx is not None:
                module.weight.data[module.padding_idx].zero_()
        elif isinstance(module, nn.LayerNorm):
            module.bias.data.zero_()
            module.weight.data.fill_(1.0)

    def forward(self, embedding, attention_mask):
        """_summary_

        Args:
            embedding (torch.tensor): shape [batch_size=batch_size, seq_len=256, num_dimensions=1024]
            attention_mask (torch.tensor): shape [batch_size=batch_size, seq_len=256]
        Returns:
            _type_: _description_
        """
        # print("embedding.shape", embedding.shape)
        # print("embedding", embedding)
        # print("self.dim_projection.weight.shape", self.dim_projection.weight.shape)
        # print("self.dim_projection.weight", self.dim_projection.weight)
        # print("self.dim_projection.bias.shape", self.dim_projection.bias.shape)
        # print("self.dim_projection.bias", self.dim_projection.bias)
        attention_mask = torch.where(
            attention_mask[:, None, None, :] == 1, 0, -torch.inf
        )
        # print("attention_mask.shape", attention_mask.shape)
        # print("attention_mask", attention_mask)
        projected = self.dim_projection(embedding)
        # print("projected.shape", projected.shape)
        # print("projected", projected)
        enc_output = self.encoder(projected, padding_mask=attention_mask)
        # print("enc_output.shape", enc_output.shape)
        # print("enc_output", enc_output)
        """
        enc_output: [batch_size, input_seq_len, d_model]
        => torch.Size([batch_size, 256, 1024]
        """
        single_logit = self.binary_prediction(enc_output)
        # print("single_logit.shape", single_logit.shape)
        # print("single_logit", single_logit)
        """
        print('logit: ', single_logit.size()) 
        => torch.Size([batch_size, 256, 1])
        """
        squeezed = torch.squeeze(single_logit, axis=-1)
        # print("squeezed.shape", squeezed.shape)
        # print("squeezed", squeezed)
        """
        Output dimension
        print('squeezed: ', squeezed.size()) 
        => torch.Size([batch_size, 256])
        """
        return squeezed


def get_angles(pos, i, d_model):
    angle_rates = 1 / np.power(10000, (2 * (i // 2)) / np.float32(d_model))
    return pos * angle_rates


class PositionalEncoding(torch.nn.Module):  # custom code
    def __init__(self, d_model, dropout=0.1, max_len=2048):
        super(PositionalEncoding, self).__init__()
        self.dropout = torch.nn.Dropout(p=dropout)
        pe = torch.zeros((max_len, 1, d_model), dtype=torch.float32)
        factor = -math.log(10000.0) / d_model  # outs loop
        for pos in range(0, max_len):  # position of word in seq
            for i in range(0, d_model, 2):  # pos of embed of word
                div_term = math.exp(i * factor)
                pe[pos, 0, i] = math.sin(pos * div_term)
                pe[pos, 0, i + 1] = math.cos(pos * div_term)
        self.register_buffer("pe", pe)  # allows state-save

    def forward(self, x):
        x = x + self.pe[: x.size(0), :]
        return self.dropout(x)


class VoltronTransformer(nn.Module):
    def __init__(self, num_layer=2, dim_model=256, num_head=16):
        super().__init__()
        self.dim_model = dim_model
        self.dropout_rate = 0.1
        self.input_vocab_size = 50304

        # Embedding layers
        self.pos_encoding = PositionalEncoding(self.dim_model)
        self.embedding = nn.Embedding(self.input_vocab_size, self.dim_model)
        self.embedding_dropout = nn.Dropout(p=self.dropout_rate)
        self.encoder = Encoder(
            num_layer=num_layer, dim_model=self.dim_model, num_head=num_head
        )
        self.binary_prediction = nn.Linear(self.dim_model, 1)
        self.apply(self._init_weights)

    def _init_weights(self, module):
        """Initialize the weights."""
        if isinstance(module, (nn.Linear,)):
            torch.nn.init.xavier_normal_(module.weight)
            if module.bias is not None:
                module.bias.data.zero_()
        elif isinstance(module, nn.Embedding):
            torch.nn.init.xavier_normal_(module.weight)
            if module.padding_idx is not None:
                module.weight.data[module.padding_idx].zero_()
        elif isinstance(module, nn.LayerNorm):
            module.bias.data.zero_()
            module.weight.data.fill_(1.0)

    def forward(self, inp, attention_mask):
        """_summary_

        Args:
            embedding (torch.tensor): shape [batch_size=batch_size, seq_len=2560, num_dimensions=num_dimensions]
            attention_mask (torch.tensor): shape [batch_size=batch_size, seq_len=2560]
        Returns:
            _type_: _description_
        """
        embeddings = self.embedding(inp.type(torch.long))
        embeddings *= math.sqrt(torch.tensor(self.dim_model))
        embeddings = self.pos_encoding(embeddings)
        embeddings = self.embedding_dropout(embeddings)

        # Transformer layers
        attention_mask = torch.where(
            attention_mask[:, None, None, :] == 1, 0, -torch.inf
        )
        enc_output = self.encoder(embeddings, padding_mask=attention_mask)
        """
        enc_output: [batch_size, input_seq_len, d_model]
        => torch.Size([batch_size, 256, 1024]
        """
        single_logit = self.binary_prediction(enc_output)
        """
        print('logit: ', single_logit.size()) 
        => torch.Size([2, 256, 1])
        """
        squeezed = torch.squeeze(single_logit, axis=-1)
        """
        Output dimension
        print('squeezed: ', squeezed.size()) 
        => torch.Size([2, 256])
        """

        return squeezed
