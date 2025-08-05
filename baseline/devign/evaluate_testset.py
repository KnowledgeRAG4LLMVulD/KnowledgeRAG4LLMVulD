#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Set Evaluation Script for Devign

This script processes the test_set data through the complete Devign pipeline:
0. Data Alignment - Convert test_set format to devign format
1. CPG Generation - Generate Code Property Graphs
2. Embedding - Create node embeddings and graph representations  
3. Model Testing - Run predictions and calculate metrics

Usage:
    python evaluate_testset.py --all                    # Run all stages
    python evaluate_testset.py --align --cpg            # Run specific stages
    python evaluate_testset.py --embed --test           # Run embedding and testing
    python evaluate_testset.py --test-only             # Only run model testing
"""

import argparse
import json
import os
import pandas as pd
import gc
import shutil
from pathlib import Path
from typing import Dict, List, Tuple
import torch
from tqdm import tqdm

# Import devign modules
import configs
import src.data as data
import src.prepare as prepare
import src.process as process
import src.utils.functions.cpg as cpg
from gensim.models.word2vec import Word2Vec

# Configuration
PATHS = configs.Paths()
FILES = configs.Files()
DEVICE = FILES.get_device()

class TestSetEvaluator:
    def __init__(self, test_set_dir="../test_set", output_dir="eval_output"):
        self.test_set_dir = Path(test_set_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for evaluation
        self.aligned_dir = self.output_dir / "aligned_data"
        self.aligned_dir.mkdir(exist_ok=True)
        
        # Create evaluation-specific data directories (separate from mydata)
        self.eval_cpg_dir = self.output_dir / "cpg"
        self.eval_joern_dir = self.output_dir / "joern" 
        self.eval_tokens_dir = self.output_dir / "tokens"
        self.eval_w2v_dir = self.output_dir / "w2v"
        self.eval_input_dir = self.output_dir / "input"
        
        for dir_path in [self.eval_cpg_dir, self.eval_joern_dir, self.eval_tokens_dir, 
                        self.eval_w2v_dir, self.eval_input_dir]:
            dir_path.mkdir(exist_ok=True)
        
        print(f"🚀 TestSet Evaluator initialized")
        print(f"   📁 Test set: {self.test_set_dir}")
        print(f"   📁 Output: {self.output_dir}")
        print(f"   📁 Eval data: {self.output_dir} (separate from mydata)")

    def stage0_data_alignment(self):
        """
        Stage 0: Convert test_set data to devign format
        """
        print("\n" + "="*60)
        print("🔄 Stage 0: Data Alignment")
        print("="*60)
        
        all_samples = []
        cwe_stats = {}
        
        # Process test_set files (nested JSON format)
        test_files = list(self.test_set_dir.glob("kernel_CWE-*_testset.json"))
        print(f"📊 Found {len(test_files)} CWE test files")
        
        for file_path in tqdm(test_files, desc="Processing CWE files"):
            cwe_type = file_path.stem.split('_')[1]  # Extract CWE-XXX
            
            with open(file_path, 'r', encoding='utf-8') as f:
                cwe_data = json.load(f)
            
            file_samples = []
            for cve_id, cve_data in cwe_data.items():
                for item in cve_data.get('item', []):
                    # Create before sample (vulnerable)
                    before_sample = {
                        'project': 'kernel',
                        'func': item['code_before_change'],
                        'target': 1,  # Vulnerable
                        'cve_id': item['cve_id'],
                        'cwe_type': cwe_type,
                        'code_type': 'before',
                        'original_id': item.get('id', 0)
                    }
                    
                    # Create after sample (fixed)
                    after_sample = {
                        'project': 'kernel', 
                        'func': item['code_after_change'],
                        'target': 0,  # Fixed
                        'cve_id': item['cve_id'],
                        'cwe_type': cwe_type,
                        'code_type': 'after',
                        'original_id': item.get('id', 0)
                    }
                    
                    file_samples.extend([before_sample, after_sample])
            
            all_samples.extend(file_samples)
            cwe_stats[cwe_type] = len(file_samples)
            print(f"   ✅ {cwe_type}: {len(file_samples)} samples (before+after)")
        
        # Create DataFrame and add indices
        df = pd.DataFrame(all_samples)
        df['Index'] = range(len(df))
        
        # Apply data cleaning
        print(f"\n📊 Total samples: {len(df)}")
        
        # Save aligned data
        output_file = self.aligned_dir / "aligned_testset.json"
        df.to_json(output_file, orient='records', indent=2)
        
        # Save statistics
        stats = {
            'total_samples': len(df),
            'cwe_distribution': cwe_stats,
            'vulnerable_samples': len(df[df.target == 1]),
            'fixed_samples': len(df[df.target == 0])
        }
        
        stats_file = self.output_dir / "alignment_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"\n✅ Stage 0 Complete!")
        print(f"   📄 Aligned data: {output_file}")
        print(f"   📊 Statistics: {stats_file}")
        print(f"   🎯 Total samples: {len(df)}")
        print(f"   🔴 Vulnerable: {len(df[df.target == 1])}")
        print(f"   🟢 Fixed: {len(df[df.target == 0])}")
        
        return df

    def stage1_cpg_generation(self):
        """
        Stage 1: Generate CPGs using devign's create_task flow
        """
        print("\n" + "="*60)
        print("🔄 Stage 1: CPG Generation")
        print("="*60)
        
        # Load aligned data
        aligned_file = self.aligned_dir / "aligned_testset.json"
        if not aligned_file.exists():
            raise FileNotFoundError(f"Aligned data not found: {aligned_file}")
        
        # Read aligned data as devign expects
        df = pd.read_json(aligned_file)
        print(f"📊 Loaded {len(df)} aligned samples")
        
        # Apply devign's data processing  
        df = data.clean(df)
        
        # Store pairing information before processing (including target for metrics)
        pairing_info = df[['Index', 'cve_id', 'cwe_type', 'code_type', 'original_id', 'target']].copy()
        pairing_file = self.output_dir / "pairing_info.json"
        pairing_info.to_json(pairing_file, orient='records', indent=2)
        print(f"📋 Saved pairing information: {pairing_file}")
        
        # Keep only devign fields for CPG processing
        data.drop(df, ["cve_id", "cwe_type", "code_type", "original_id"])
        
        # Create slices like devign does
        context = configs.Create()
        slices = data.slice_frame(df, context.slice_size)
        slices = [(s, slice.apply(lambda x: x)) for s, slice in slices]
        
        print(f"📊 Created {len(slices)} data slices (1 sample per slice)")
        
        cpg_files = []
        successful_slices = []
        failed_slices = []
        
        # Generate CPG files for each slice (now 1 sample per slice)
        for s, slice_df in tqdm(slices, desc="Generating CPGs"):
            sample_info = f"slice {s} (Index: {slice_df.index[0] if len(slice_df) > 0 else 'unknown'})"
            print(f"\n🔄 Processing {sample_info}")
            
            try:
                # Write slice to files for joern (use eval-specific directory)
                data.to_files(slice_df, str(self.eval_joern_dir) + "/")
                
                # Generate CPG binary (use eval-specific directories)
                cpg_file = prepare.joern_parse(
                    context.joern_cli_dir, 
                    str(self.eval_joern_dir) + "/", 
                    str(self.eval_cpg_dir) + "/", 
                    f"{s}_{FILES.cpg}"
                )
                cpg_files.append(cpg_file)
                successful_slices.append(s)
                print(f"   ✅ CPG binary: {cpg_file}")
                
            except Exception as e:
                print(f"   ❌ Failed to generate CPG for {sample_info}: {str(e)}")
                failed_slices.append(s)
                continue
            
            finally:
                # Clean up temporary joern files
                if self.eval_joern_dir.exists():
                    shutil.rmtree(self.eval_joern_dir)
                    self.eval_joern_dir.mkdir(exist_ok=True)
        
        print(f"\n📊 CPG Generation Summary:")
        print(f"   ✅ Successful: {len(successful_slices)}/{len(slices)}")
        print(f"   ❌ Failed: {len(failed_slices)}")
        if failed_slices:
            print(f"   Failed slices: {failed_slices[:10]}{'...' if len(failed_slices) > 10 else ''}")
        
        if not cpg_files:
            raise RuntimeError("No CPG files were successfully generated!")
        
        # Create JSON files from CPG binaries
        print(f"\n🔄 Converting CPGs to JSON format...")
        json_files = prepare.joern_create(
            context.joern_cli_dir, 
            str(self.eval_cpg_dir) + "/", 
            str(self.eval_cpg_dir) + "/", 
            cpg_files
        )
        
        # Process each JSON file and create final datasets
        valid_pairs = list(zip([s for s in successful_slices if f"{s}_{FILES.cpg}.json" in json_files], 
                              [slice_df for s, slice_df in slices if s in successful_slices and f"{s}_{FILES.cpg}.json" in json_files],
                              [jf for jf in json_files if jf in [f"{s}_{FILES.cpg}.json" for s in successful_slices]]))
        
        processed_samples = 0
        for s, slice_df, json_file in tqdm(valid_pairs, desc="Processing JSON"):
            sample_info = f"slice {s} (Index: {slice_df.index[0] if len(slice_df) > 0 else 'unknown'})"
            print(f"\n🔄 Processing JSON for {sample_info}")
            
            graphs = prepare.json_process(str(self.eval_cpg_dir) + "/", json_file)
            if graphs is None:
                print(f"   ❌ {sample_info} failed to process JSON")
                continue
            
            # Create dataset with CPG data
            dataset = data.create_with_index(graphs, ["Index", "cpg"])
            dataset = data.inner_join_by_index(slice_df, dataset)
            
            # Save processed dataset
            output_file = f"{s}_{FILES.cpg}.pkl"
            data.write(dataset, str(self.eval_cpg_dir) + "/", output_file)
            print(f"   ✅ Saved: {output_file}")
            processed_samples += 1
            
            del dataset
            gc.collect()
        
        print(f"\n✅ Stage 1 Complete - Atomic Processing Summary:")
        print(f"   📊 Total samples: {len(df)}")
        print(f"   🔄 CPG generation: {len(successful_slices)}/{len(slices)} successful")
        print(f"   🔄 JSON processing: {processed_samples}/{len(valid_pairs)} successful")
        print(f"   📁 Final CPG files: {processed_samples}")
        print(f"   📂 Output directory: {self.eval_cpg_dir}")
        
        if processed_samples == 0:
            raise RuntimeError("No samples were successfully processed through the full pipeline!")
        
        print(f"\n🎯 Ready for Stage 2 with {processed_samples} processed samples")

    def stage2_embedding(self):
        """
        Stage 2: Create embeddings using devign's embed_task flow
        """
        print("\n" + "="*60)
        print("🔄 Stage 2: Embedding Generation")
        print("="*60)
        
        context = configs.Embed()
        
        # Get CPG dataset files from eval directory
        dataset_files = data.get_directory_files(str(self.eval_cpg_dir) + "/")
        print(f"📊 Found {len(dataset_files)} CPG dataset files")
        
        # Initialize Word2Vec model
        w2vmodel = Word2Vec(**context.w2v_args)
        w2v_init = True
        
        for pkl_file in tqdm(dataset_files, desc="Processing embeddings"):
            file_name = pkl_file.split(".")[0]
            print(f"\n🔄 Processing {file_name}")
            
            # Load CPG dataset from eval directory
            cpg_dataset = data.load(str(self.eval_cpg_dir) + "/", pkl_file)
            print(f"   📊 Loaded {len(cpg_dataset)} samples")
            
            # Tokenize source code
            tokens_dataset = data.tokenize(cpg_dataset)
            data.write(tokens_dataset, str(self.eval_tokens_dir) + "/", f"{file_name}_{FILES.tokens}")
            
            # Train Word2Vec model
            print(f"   🔄 Training Word2Vec...")
            w2vmodel.build_vocab(corpus_iterable=tokens_dataset.tokens, update=not w2v_init)
            w2vmodel.train(tokens_dataset.tokens, total_examples=len(tokens_dataset.tokens), epochs=1)
            
            if w2v_init:
                w2v_init = False
            
            # Generate node embeddings
            print(f"   🔄 Generating node embeddings...")
            # Fix: Use result_type='reduce' to ensure single column output
            cpg_dataset["nodes"] = cpg_dataset.apply(
                lambda row: cpg.parse_to_nodes(row.cpg, context.nodes_dim), 
                axis=1, 
                result_type='reduce'
            )
            
            # Remove rows with no nodes
            before_filter = len(cpg_dataset)
            cpg_dataset = cpg_dataset.loc[cpg_dataset.nodes.map(len) > 0]
            after_filter = len(cpg_dataset)
            print(f"   📊 Filtered empty nodes: {before_filter} → {after_filter}")
            
            # Create graph input data
            print(f"   🔄 Creating graph inputs...")
            # Fix: Use result_type='reduce' to ensure single column output
            cpg_dataset["input"] = cpg_dataset.apply(
                lambda row: prepare.nodes_to_input(
                    row.nodes, row.target, context.nodes_dim, 
                    w2vmodel.wv, context.edge_type
                ), axis=1, result_type='reduce'
            )
            
            # Clean up and save to eval directory
            data.drop(cpg_dataset, ["nodes"])
            data.write(cpg_dataset[["input", "target"]], str(self.eval_input_dir) + "/", f"{file_name}_{FILES.input}")
            print(f"   ✅ Saved input dataset: {file_name}_{FILES.input}")
            
            del cpg_dataset
            gc.collect()
        
        # Save Word2Vec model to eval directory
        w2v_path = str(self.eval_w2v_dir) + "/" + FILES.w2v
        w2vmodel.save(w2v_path)
        print(f"\n✅ Stage 2 Complete!")
        print(f"   📁 Input datasets saved to: {self.eval_input_dir}")
        print(f"   🔤 Word2Vec model saved: {w2v_path}")

    def stage3_model_testing(self):
        """
        Stage 3: Run model testing and generate predictions
        """
        print("\n" + "="*60)
        print("🔄 Stage 3: Model Testing")
        print("="*60)
        
        # Load model
        context_process = configs.Process()
        devign_config = configs.Devign()
        model_path = PATHS.model + FILES.model
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        print(f"📋 Loading model from: {model_path}")
        model = process.Devign(
            path=model_path, 
            device=DEVICE, 
            model=devign_config.model,
            learning_rate=devign_config.learning_rate,
            weight_decay=devign_config.weight_decay,
            loss_lambda=devign_config.loss_lambda
        )
        model.load()
        print(f"✅ Model loaded successfully")
        
        # Load test dataset from eval directory
        input_dataframe = data.loads(str(self.eval_input_dir) + "/")
        print(f"📊 Loaded {len(input_dataframe)} test samples")
        
        # Convert DataFrame to InputDataset for DataLoader
        from src.utils.objects.input_dataset import InputDataset
        input_dataset = InputDataset(input_dataframe)
        
        # Create test data loader
        test_loader = input_dataset.get_loader(context_process.batch_size, shuffle=False)
        test_loader_step = process.LoaderStep("Test", test_loader, DEVICE)
        
        # Run predictions with detailed results
        print(f"🔄 Running model predictions...")
        detailed_results = self._run_detailed_predictions(model, test_loader, input_dataset)
        
        # Save results
        results_file = self.output_dir / "test_results.json"
        with open(results_file, 'w') as f:
            json.dump(detailed_results, f, indent=2)
        
        print(f"\n✅ Stage 3 Complete!")
        print(f"   📄 Results saved: {results_file}")
        
        # Calculate detailed metrics
        metrics = self._calculate_metrics(detailed_results)
        
        return detailed_results
    
    def _run_detailed_predictions(self, model, test_loader, input_dataset):
        """
        Run model predictions and return detailed results with probabilities and labels
        """
        model.model.eval()
        results = []
        
        with torch.no_grad():
            for batch_idx, batch in enumerate(tqdm(test_loader, desc="Running predictions")):
                batch = batch.to(DEVICE)
                output = model.model(batch)
                
                # Convert output to probabilities
                probabilities = output.cpu().numpy()
                
                # Get predictions (adjusted threshold based on observed probability distribution)
                threshold = 0.5
                predictions = (probabilities >= threshold).astype(int)
                
                # Store results for each sample in the batch
                for i in range(len(probabilities)):
                    sample_idx = batch_idx * test_loader.batch_size + i
                    if sample_idx < len(input_dataset):
                        # Get original data for this sample
                        original_sample = input_dataset.dataset.iloc[sample_idx]
                        
                        result = {
                            'sample_index': sample_idx,
                            'probability': float(probabilities[i]),
                            'predicted_label': int(predictions[i]),
                            'true_label': int(original_sample['target']),
                            'Index': int(original_sample.get('Index', sample_idx))
                        }
                        results.append(result)
        
        print(f"📊 Generated predictions for {len(results)} samples")
        return results

    def _calculate_metrics(self, results):
        """Calculate and display evaluation metrics"""
        print(f"\n📊 Evaluation Metrics:")
        print("-" * 40)
        
        # Load pairing information for detailed metrics calculation
        pairing_file = self.output_dir / "pairing_info.json"
        if pairing_file.exists():
            pairing_df = pd.read_json(pairing_file)
            
            # Check if target column exists, if not, try to recover from predictions
            if 'target' not in pairing_df.columns:
                print("⚠️  Warning: pairing_info.json missing 'target' column")
                print("   Trying to recover target values from predictions...")
                
                # Create target mapping from predictions
                pred_df = pd.DataFrame(results) if isinstance(results, list) else results
                if 'true_label' in pred_df.columns:
                    # Map true_label back to Index
                    target_mapping = pred_df.set_index('Index')['true_label'].to_dict()
                    pairing_df['target'] = pairing_df['Index'].map(target_mapping)
                    
                    # Save updated pairing info
                    pairing_df.to_json(pairing_file, orient='records', indent=2)
                    print("   ✅ Successfully recovered target values")
                else:
                    print("   ❌ Cannot recover target values - missing true_label in predictions")
                    return None
            
            test_results = self._calculate_detailed_metrics(results, pairing_df)
            return test_results
        else:
            print("❌ Cannot find pairing information for detailed metrics calculation")
            print("   Make sure to run Stage 1 (CPG generation) before Stage 3")
            return None
    
    def _calculate_detailed_metrics(self, predictions, aligned_data):
        """
        Calculate detailed metrics including pairwise accuracy, balanced recall, and balanced precision
        
        Args:
            predictions: List of prediction results
            aligned_data: DataFrame with original data alignment information
        """
        print("🔄 Calculating detailed metrics...")
        
        # Convert predictions to DataFrame for easier manipulation
        pred_df = pd.DataFrame(predictions) if isinstance(predictions, list) else predictions
        
        # Merge with aligned data to get pairing information
        if 'Index' in pred_df.columns:
            merged_df = pd.merge(pred_df, aligned_data, on='Index', how='inner')
        else:
            # If no Index column, assume sequential order
            merged_df = pd.concat([pred_df.reset_index(drop=True), 
                                 aligned_data.reset_index(drop=True)], axis=1)
        
        # Ensure we have target column (prefer from predictions as true_label)
        if 'target' not in merged_df.columns and 'true_label' in merged_df.columns:
            merged_df['target'] = merged_df['true_label']
        elif 'target' not in merged_df.columns:
            print("❌ Error: No target or true_label column found")
            return None
        
        print(f"📊 Merged {len(merged_df)} samples for evaluation")
        
        # Group by original_id and cve_id to find pairs
        pairs = []
        grouped = merged_df.groupby(['original_id', 'cve_id'])
        
        for (orig_id, cve_id), group in grouped:
            if len(group) == 2:  # Must have both before and after
                before_row = group[group['code_type'] == 'before']
                after_row = group[group['code_type'] == 'after']
                
                if len(before_row) == 1 and len(after_row) == 1:
                    pairs.append({
                        'original_id': orig_id,
                        'cve_id': cve_id,
                        'cwe_type': group.iloc[0]['cwe_type'],
                        'before_true': before_row.iloc[0]['target'],
                        'before_pred': before_row.iloc[0].get('predicted_label', 
                                                           1 if before_row.iloc[0].get('probability', 0.5) >= 0.6208 else 0),
                        'after_true': after_row.iloc[0]['target'],
                        'after_pred': after_row.iloc[0].get('predicted_label',
                                                          1 if after_row.iloc[0].get('probability', 0.5) >= 0.6208 else 0),
                        'before_prob': before_row.iloc[0].get('probability', 0.5),
                        'after_prob': after_row.iloc[0].get('probability', 0.5)
                    })
        
        pairs_df = pd.DataFrame(pairs)
        print(f"📊 Found {len(pairs_df)} valid pairs for evaluation")
        
        if len(pairs_df) == 0:
            print("❌ No valid pairs found for evaluation")
            return None
        
        # Calculate metrics
        metrics = {}
        
        # 1. Pairwise Accuracy
        # A pair is correctly classified if both before=1 and after=0 are predicted correctly
        correct_pairs = ((pairs_df['before_true'] == pairs_df['before_pred']) & 
                        (pairs_df['after_true'] == pairs_df['after_pred']))
        pairwise_accuracy = correct_pairs.sum() / len(pairs_df)
        metrics['pairwise_accuracy'] = pairwise_accuracy
        
        # 2. Individual predictions for Balanced Recall and Precision
        all_true = list(pairs_df['before_true']) + list(pairs_df['after_true'])
        all_pred = list(pairs_df['before_pred']) + list(pairs_df['after_pred'])
        
        # Calculate confusion matrix components
        tp_vul = sum((t == 1 and p == 1) for t, p in zip(all_true, all_pred))  # True positive for vulnerable
        tn_vul = sum((t == 0 and p == 0) for t, p in zip(all_true, all_pred))  # True negative for vulnerable  
        fp_vul = sum((t == 0 and p == 1) for t, p in zip(all_true, all_pred))  # False positive for vulnerable
        fn_vul = sum((t == 1 and p == 0) for t, p in zip(all_true, all_pred))  # False negative for vulnerable
        
        total_vul = tp_vul + fn_vul  # Total actual vulnerable
        total_nvul = tn_vul + fp_vul  # Total actual non-vulnerable
        
        # 3. Balanced Recall = (#True_vul/#Total_vul + #True_nvul/#Total_nvul) / 2
        recall_vul = tp_vul / total_vul if total_vul > 0 else 0
        recall_nvul = tn_vul / total_nvul if total_nvul > 0 else 0
        balanced_recall = (recall_vul + recall_nvul) / 2
        metrics['balanced_recall'] = balanced_recall
        metrics['recall_vulnerable'] = recall_vul
        metrics['recall_non_vulnerable'] = recall_nvul
        
        # 4. Balanced Precision = (#True_vul/#Predict_vul + #True_nvul/#Predict_nvul) / 2
        predict_vul = tp_vul + fp_vul  # Total predicted vulnerable
        predict_nvul = tn_vul + fn_vul  # Total predicted non-vulnerable
        
        precision_vul = tp_vul / predict_vul if predict_vul > 0 else 0
        precision_nvul = tn_vul / predict_nvul if predict_nvul > 0 else 0
        balanced_precision = (precision_vul + precision_nvul) / 2
        metrics['balanced_precision'] = balanced_precision
        metrics['precision_vulnerable'] = precision_vul
        metrics['precision_non_vulnerable'] = precision_nvul
        
        # 5. Standard metrics
        accuracy = (tp_vul + tn_vul) / len(all_true)
        
        # Standard Precision and Recall (overall)
        total_tp = tp_vul
        total_fp = fp_vul  
        total_fn = fn_vul
        
        standard_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        standard_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        standard_f1 = 2 * standard_precision * standard_recall / (standard_precision + standard_recall) if (standard_precision + standard_recall) > 0 else 0
        
        # Store all required metrics
        metrics['acc'] = accuracy
        metrics['p'] = standard_precision
        metrics['r'] = standard_recall
        metrics['f1'] = standard_f1
        metrics['pair_acc'] = pairwise_accuracy
        metrics['balanced_p'] = balanced_precision
        metrics['balanced_r'] = balanced_recall
        
        # Calculate balanced F1
        balanced_f1 = 2 * balanced_precision * balanced_recall / (balanced_precision + balanced_recall) if (balanced_precision + balanced_recall) > 0 else 0
        metrics['balanced_f1'] = balanced_f1
        
        # Keep detailed metrics for analysis
        metrics['accuracy_detailed'] = accuracy
        metrics['f1_vulnerable'] = 2 * precision_vul * recall_vul / (precision_vul + recall_vul) if (precision_vul + recall_vul) > 0 else 0
        metrics['f1_non_vulnerable'] = 2 * precision_nvul * recall_nvul / (precision_nvul + recall_nvul) if (precision_nvul + recall_nvul) > 0 else 0
        
        # 6. Per-CWE analysis
        cwe_metrics = {}
        for cwe_type in pairs_df['cwe_type'].unique():
            cwe_pairs = pairs_df[pairs_df['cwe_type'] == cwe_type]
            if len(cwe_pairs) > 0:
                cwe_correct = ((cwe_pairs['before_true'] == cwe_pairs['before_pred']) & 
                              (cwe_pairs['after_true'] == cwe_pairs['after_pred']))
                cwe_pairwise_acc = cwe_correct.sum() / len(cwe_pairs)
                cwe_metrics[cwe_type] = {
                    'pairs': len(cwe_pairs),
                    'pairwise_accuracy': cwe_pairwise_acc,
                    'correct_pairs': cwe_correct.sum()
                }
        
        metrics['per_cwe'] = cwe_metrics
        
        # Display results
        print(f"\n📊 Evaluation Results (Test Set - Full Dataset):")
        print(f"{'='*60}")
        print(f"🎯 Required Metrics:")
        print(f"   acc        : {metrics['acc']:.4f}")
        print(f"   p          : {metrics['p']:.4f}")
        print(f"   r          : {metrics['r']:.4f}")
        print(f"   f1         : {metrics['f1']:.4f}")
        print(f"   pair-acc   : {metrics['pair_acc']:.4f} ({correct_pairs.sum()}/{len(pairs_df)} pairs)")
        print(f"   balanced-p : {metrics['balanced_p']:.4f}")
        print(f"   balanced-r : {metrics['balanced_r']:.4f}")
        print(f"   balanced-f1: {metrics['balanced_f1']:.4f}")
        
        print(f"\n🔍 Detailed Breakdown:")
        print(f"   Vulnerable     - Precision: {precision_vul:.4f}, Recall: {recall_vul:.4f}")
        print(f"   Non-Vulnerable - Precision: {precision_nvul:.4f}, Recall: {recall_nvul:.4f}")
        
        print(f"\n📊 Confusion Matrix:")
        print(f"   True Positive (Vulnerable): {tp_vul}")
        print(f"   True Negative (Non-Vulnerable): {tn_vul}")
        print(f"   False Positive (Vulnerable): {fp_vul}")
        print(f"   False Negative (Non-Vulnerable): {fn_vul}")
        print(f"   Total Samples: {len(all_true)}")
        print(f"   Total Valid Pairs: {len(pairs_df)}")
        
        print(f"\n🎯 Per-CWE Results:")
        for cwe, cwe_stats in sorted(cwe_metrics.items()):
            print(f"   {cwe}: {cwe_stats['pairwise_accuracy']:.4f} ({cwe_stats['correct_pairs']}/{cwe_stats['pairs']} pairs)")
        
        # Save detailed results (convert numpy/pandas types to native Python types)
        def convert_to_serializable(obj):
            """Convert numpy/pandas types to native Python types for JSON serialization"""
            if hasattr(obj, 'item'):  # numpy scalars
                return obj.item()
            elif hasattr(obj, 'tolist'):  # numpy arrays
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_to_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_serializable(v) for v in obj]
            else:
                return obj
        
        serializable_metrics = convert_to_serializable(metrics)
        results_file = self.output_dir / "detailed_metrics.json"
        with open(results_file, 'w') as f:
            json.dump(serializable_metrics, f, indent=2)
        
        print(f"\n✅ Detailed metrics saved to: {results_file}")
        
        return metrics

    def run_all_stages(self):
        """Run all evaluation stages in sequence"""
        print("🚀 Starting complete evaluation pipeline...")
        
        # Stage 0: Data Alignment
        aligned_data = self.stage0_data_alignment()
        
        # Stage 1: CPG Generation  
        self.stage1_cpg_generation()
        
        # Stage 2: Embedding
        self.stage2_embedding()
        
        # Stage 3: Model Testing
        results = self.stage3_model_testing()
        
        print(f"\n🎉 All stages completed successfully!")
        return results


def main():
    parser = argparse.ArgumentParser(description="TestSet Evaluation for Devign")
    
    # Stage selection
    parser.add_argument('--all', action='store_true', help='Run all stages')
    parser.add_argument('--align', action='store_true', help='Run data alignment (Stage 0)')
    parser.add_argument('--cpg', action='store_true', help='Run CPG generation (Stage 1)')
    parser.add_argument('--embed', action='store_true', help='Run embedding (Stage 2)')
    parser.add_argument('--test', action='store_true', help='Run model testing (Stage 3)')
    parser.add_argument('--test-only', action='store_true', help='Only run model testing')
    
    # Configuration
    parser.add_argument('--test-set', default='../test_set', help='Test set directory')
    parser.add_argument('--output', default='eval_output', help='Output directory')
    
    args = parser.parse_args()
    
    if not any([args.all, args.align, args.cpg, args.embed, args.test, args.test_only]):
        parser.print_help()
        return
    
    # Initialize evaluator
    evaluator = TestSetEvaluator(args.test_set, args.output)
    
    # Run selected stages
    if args.all:
        evaluator.run_all_stages()
    else:
        if args.align:
            evaluator.stage0_data_alignment()
        if args.cpg:
            evaluator.stage1_cpg_generation()
        if args.embed:
            evaluator.stage2_embedding()
        if args.test or args.test_only:
            evaluator.stage3_model_testing()


if __name__ == "__main__":
    main() 