import json
import argparse
import os
import sys 

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_files", nargs='+', required=True, help="One or more input file names")
    parser.add_argument("--baseline", action="store_true", help="Whether to calculate metrics for baseline")
    
    return parser.parse_args()

def calculate_metrics(fp, tp, fn, tn):
    TP = tp
    FP = fp
    FN = fn
    TN = tn

    pos_precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    pos_recall = TP / (TP + FN) if (TP + FN) > 0 else 0

    neg_precision = TN / (TN + FN) if (TN + FN) > 0 else 0
    neg_recall = TN / (TN + FP) if (TN + FP) > 0 else 0

    precision = (pos_precision + neg_precision) / 2
    recall = (pos_recall + neg_recall) / 2

    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0
    FN_rate = FN / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1
    FP_rate = FP / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1
    TN_rate = TN / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1
    TP_rate = TP / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else -1

    return {
        "true_positive": TP,
        "false_positive": FP,
        "false_negative": FN,
        "true_negative": TN,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "FN_rate": FN_rate,
        "FP_rate": FP_rate,
        "TN_rate": TN_rate,
        "TP_rate": TP_rate
    }

def evaluate_result(args):
    # Ensure output directory exists
    if args.baseline:
        os.makedirs("output/baseline/metrics", exist_ok=True)
    else:
        os.makedirs("output/detect/metrics", exist_ok=True)
    
    fp_total = 0
    tp_total = 0
    fn_total = 0
    tn_total = 0
    pair_right_total = 0
    pair_1_total = 0
    pair_0_total = 0
    pair_wrong_total = 0

    for input_file in args.input_files:
        if args.baseline:
            with open(f"output/baseline/{input_file}", "r") as f:
                data = json.load(f)
        else:
            with open(f"output/detect/{input_file}", "r") as f:
                data = json.load(f)

        fp = 0
        tp = 0
        fn = 0
        tn = 0

        pair_right = 0
        pair_1 = 0
        pair_0 = 0
        pair_wrong = 0
        
        for item in data:
            if item["detect_result_before"]["final_result"] == 1:
                tp += 1
            else:
                fn +=1
            if item["detect_result_after"]["final_result"] != 1:
                tn += 1
            else:
                fp += 1
        
            if item["detect_result_before"]["final_result"] == 1 and item["detect_result_after"]["final_result"] != 1:
                pair_right += 1
            elif item["detect_result_before"]["final_result"] == 1 and item["detect_result_after"]["final_result"] == 1:
                pair_1 += 1
            elif item["detect_result_before"]["final_result"] != 1 and item["detect_result_after"]["final_result"] != 1:
                pair_0 += 1
            else:
                pair_wrong += 1

        metrics = calculate_metrics(fp, tp, fn, tn)
        metrics.update({
            "pair_total": pair_right + pair_1 + pair_0 + pair_wrong,
            "pair_right": pair_right,
            "pair_1": pair_1,
            "pair_0": pair_0,
            "pair_wrong": pair_wrong,
            "pair_accuracy": (pair_right) / (pair_right + pair_1 + pair_0 + pair_wrong),
            "pair_1_rate": pair_1 / (pair_right + pair_1 + pair_0 + pair_wrong),
            "pair_0_rate": pair_0 / (pair_right + pair_1 + pair_0 + pair_wrong),
            "false_pair_rate": pair_wrong / (pair_right + pair_1 + pair_0 + pair_wrong),
        })

        fp_total += fp
        tp_total += tp
        fn_total += fn
        tn_total += tn
        pair_right_total += pair_right
        pair_1_total += pair_1
        pair_0_total += pair_0
        pair_wrong_total += pair_wrong

        for k,v in metrics.items():
            metrics[k] = round(v, 4)

        if args.baseline:
            with open(f"output/baseline/metrics/{input_file.split('.')[0]}_metrics.json", "w") as f:
                json.dump(metrics, f, indent=4)
        else:
            with open(f"output/detect/metrics/{input_file.split('.')[0]}_metrics.json", "w") as f:
                json.dump(metrics, f, indent=4)

    metrics_total = calculate_metrics(fp_total, tp_total, fn_total, tn_total)
    metrics_total.update({
        "pair_total": pair_right_total + pair_1_total + pair_0_total + pair_wrong_total,
        "pair_right": pair_right_total,
        "pair_1": pair_1_total,
        "pair_0": pair_0_total,
        "pair_wrong": pair_wrong_total,
        "pair_accuracy": (pair_right_total) / (pair_right_total + pair_1_total + pair_0_total + pair_wrong_total),
        "pair_1_rate": pair_1_total / (pair_right_total + pair_1_total + pair_0_total + pair_wrong_total),
        "pair_0_rate": pair_0_total / (pair_right_total + pair_1_total + pair_0_total + pair_wrong_total),
        "false_pair_rate": pair_wrong_total / (pair_right_total + pair_1_total + pair_0_total + pair_wrong_total),
    })

    for k,v in metrics_total.items():
        metrics_total[k] = round(v, 4)

    if args.baseline:
        with open(f"output/baseline/metrics/total_metrics.json", "w") as f:
            json.dump(metrics_total, f, indent=4)
    else:
        with open(f"output/detect/metrics/total_metrics.json", "w") as f:
            json.dump(metrics_total, f, indent=4)
    
    
if __name__ == "__main__":
    args = parse_args()
    if args.baseline:
        os.makedirs("output/baseline/metrics", exist_ok=True)
    else:
        os.makedirs("output/detect/metrics", exist_ok=True)
    evaluate_result(args)