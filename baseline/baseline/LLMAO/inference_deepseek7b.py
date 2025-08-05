import torch.utils.checkpoint
import torch
import argparse
import pdb
from transformer import VoltronTransformerPretrained, TokenizeMask
from tqdm import tqdm
import json
# import qwen_processor
import deepseek_distill_processor
import numpy as np
import re
import os


class SampleEvalution:
    def __init__(self,cwe) -> None:

        self.cuda_device = "cuda:7"
        os.environ["CUDA_VISIBLE_DEVICES"] = self.cuda_device.split(":")[-1]
        
        self.max_len = 128
        self.qwen_processor = deepseek_distill_processor.CodeProcessor(self.cuda_device)
        self.dim_model = 3584

        self.cwe_name = cwe

        self.target_dim = 512
        self.num_head = 8
        self.num_layer = 4
        print(f'start loading model_checkpoints/{cwe}_deepseek7b')
        self.model = VoltronTransformerPretrained(
            num_layer=self.num_layer, dim_model=self.dim_model, num_head=self.num_head, target_dim=self.target_dim
        )
        self.model.load_state_dict(torch.load(
            f'model_checkpoints/{cwe}_deepseek7b'), strict=False)
        self.model.eval()

    def sample_processer(self, code, label_code):
        try:
            decoded_program = code
            label = label_code
            # print("Original label:", label)
        except:
            return None

        hidden_states = self.qwen_processor.get_hidden_state(decoded_program)
        sample_shape = list(hidden_states.size())[0]
        native_sample_size = len(decoded_program.split("\n"))

        if sample_shape+1 > self.max_len or native_sample_size != (sample_shape+1):
            print(sample_shape, self.max_len, native_sample_size)
            print("decoded_program:", decoded_program)
            return None
        # Padding
        sample_padding = torch.zeros(
            self.max_len - sample_shape, self.dim_model).to(self.cuda_device)

        final_hidden_states = torch.cat(
            [hidden_states, sample_padding], axis=0)
        # Binary tensor for NL tokens
        NL_tokens = np.zeros(self.max_len)
        try:
            NL_tokens[label] = np.ones(len(label))
        except:
            print('Label shape wrong')
            return None
        NL_tokens = torch.tensor(NL_tokens)
        NL_tokens = NL_tokens.to(self.cuda_device)
        # Masking
        attention_mask = torch.cat(
            [torch.ones(sample_shape), torch.zeros(self.max_len - sample_shape)], axis=0
        ).to(self.cuda_device)
        output = (final_hidden_states, NL_tokens, attention_mask)
        return output

    def sample_evalution(self,code,label):
        final_hidden_states, NL_tokens, attention_mask = self.sample_processer(code,label)
        self.model.to(self.cuda_device)
        self.model.eval()

        result = False
        with torch.no_grad():
            final_hidden_states = final_hidden_states.to(self.cuda_device)
            NL_tokens = NL_tokens.to(self.cuda_device)
            attention_mask = attention_mask.to(self.cuda_device)

            final_hidden_states = final_hidden_states.unsqueeze(0).to(self.cuda_device)
            NL_tokens = NL_tokens.unsqueeze(0).to(self.cuda_device)  
            attention_mask = attention_mask.unsqueeze(0).to(self.cuda_device)  

            predictions = self.model(final_hidden_states, attention_mask)


            flattened_input = torch.flatten(final_hidden_states)
            flattened_labels = torch.flatten(NL_tokens)
            flattened_probabilities = torch.flatten(torch.sigmoid(predictions))
            real_indices = torch.flatten(attention_mask == 1)
            flattened_probabilities = flattened_probabilities[real_indices]
            flattened_labels = flattened_labels[real_indices]

        flattened_result = flattened_probabilities.cpu().detach().numpy()

        return round(np.max(flattened_result))

    def cwe_pipeline(self):
        with open(f"deepseek7b_test_data/test/{self.cwe_name}/{self.cwe_name}_test_set_for_LLMAO.json",'r') as f:
            data = json.load(f)
        id_dict = {}
        for sample in data:
            id_ = sample["id"]
            if not sample["vul"] == 1:
                id_ -= 1
            if id_ not in id_dict:
                id_dict.update({id_ :{}})
            if sample["vul"] == 1:
                if "vul" not in id_dict[id_ ]:
                    id_dict[id_ ].update({"vul":[]})
                id_dict[id_ ]["vul"].append({"code":sample["code"],"label":sample["bug_line_number"]})
            else:
                if "non_vul" not in id_dict[id_ ]:
                    id_dict[id_ ].update({"non_vul":[]})
                id_dict[id_ ]["non_vul"].append({"code":sample["code"],"label":sample["bug_line_number"]})

        with open(f"deepseek7b_test_data/test/{self.cwe_name}/{self.cwe_name}_format_for_detect.json",'w')as f:
            json.dump(id_dict,f,indent=4,ensure_ascii=False)
        accurate_pair_num = 0
        false_pair_num = 0
        pair_1_num = 0
        pair_0_num = 0

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        all_pair = 0

        crash_num = 0

        print(f"Start Detecting for {self.cwe_name}")
        print(f"{len(id_dict)} sample to detect")
        

        for k,v in id_dict.items():
            try:
            # print(v)
                vul_code = v["vul"]
                non_vul_code = v["non_vul"]
                result_of_vul = 0
                for code_sni in vul_code:
                    result = self.sample_evalution(code_sni["code"],code_sni["label"])
                    if result == 1:
                        result_of_vul = 1
                        break
                result_of_non_vul = 0
                for code_sni in non_vul_code:
                    result = self.sample_evalution(code_sni["code"],code_sni["label"])
                    if result == 1:
                        result_of_non_vul = 1
                        break
                
                if result_of_vul == 1:
                    tp+=1
                else:
                    fn+=1
                
                if result_of_non_vul == 0:
                    tn+=1
                else:
                    fp+=1
                
                if result_of_vul == 1 and result_of_non_vul == 1:
                    pair_1_num+=1
                if result_of_vul == 1 and result_of_non_vul == 0:
                    accurate_pair_num+=1
                if result_of_vul == 0 and result_of_non_vul == 0:
                    pair_0_num+=1
                if result_of_vul == 0 and result_of_non_vul == 1:
                    false_pair_num+=1

                all_pair +=1
                print(f"already done: {all_pair}")
            except:
                all_pair += 1
                crash_num += 1
                print(f"Crashed: {crash_num}")
                continue
            
        metrics = self.calculate_metrics(tp=tp,fp=fp,tn=tn,fn=fn)
        accurate_pair_rate = accurate_pair_num/(accurate_pair_num+pair_1_num+pair_0_num+false_pair_num)

        print(f"Result of {self.cwe_name}:")
        print(metrics)
        metrics.update({
            "accurate_pair_rate":accurate_pair_rate,
            "pair_1_rate":pair_1_num/(accurate_pair_num+pair_1_num+pair_0_num+false_pair_num),
            "pair_0_rate":pair_0_num/(accurate_pair_num+pair_1_num+pair_0_num+false_pair_num),
            "False Pair Rate":false_pair_num/(accurate_pair_num+pair_1_num+pair_0_num+false_pair_num),
        })
        print(f"result of {self.cwe_name}")
        
        metrics.update({
            "False Positive Rate":fp/(fp+tn+fn+tp),
            "False Negative Rate":fn/(fp+tn+fn+tp),
            "True Positive Rate":tp/(fp+tn+fn+tp),
            "True Negative Rate":tn/(fp+tn+fn+tp),
            "Pair Count":all_pair,
            "Valid Pair Count":all_pair-crash_num,
            "Accurate Pair Count":accurate_pair_num,
            "Pair 1 Count":pair_1_num,
            "Pair 0 Count":pair_0_num,
            "False Pair Count":false_pair_num,
            "True Positive":tp,
            "False Positive":fp,
            "True Negative":tn,
            "False Negative":fn
        })
        print(json.dumps(metrics,indent=4))
        with open(f"deepseek7b_test_data/test/{self.cwe_name}/{self.cwe_name}_result.json",'w')as f:
            json.dump(metrics,f,indent=4)
        
        
    def calculate_metrics(self, tp, fp, tn, fn):

        TP = tp
        FP = fp
        TN = tn
        FN = fn
        pos_precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        pos_recall = TP / (TP + FN) if (TP + FN) > 0 else 0

        neg_precision = TN / (TN + FN) if (TN + FN) > 0 else 0
        neg_recall = TN / (TN + FP) if (TN + FP) > 0 else 0


        precision = (pos_precision + neg_precision) / 2
        recall = (pos_recall + neg_recall) / 2
        
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
        
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        

        
        return {
            "precision": precision,
            "recall": recall,
            "accuracy": accuracy,
            "f1_score": f1_score,
        }
        

    def remove_comments(self,code):

        code = re.sub(r'(?s)/\*.*?\*/', '', code)
        

        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        
 
        code = re.sub(r'\n\s*\n', '\n', code)
        
        return code

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cwe")
    args = ap.parse_args()

    eva = SampleEvalution(args.cwe)
    eva.cwe_pipeline()

    pass


