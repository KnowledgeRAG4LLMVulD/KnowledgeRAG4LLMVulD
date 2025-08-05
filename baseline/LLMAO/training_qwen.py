from torch.utils.tensorboard import SummaryWriter
import random
import os
import argparse
import glob
import json
import torch
import torch.utils.checkpoint
from torch import nn
from torch import optim
from torch.utils.data import DataLoader
from transformer import (
    PreloadedDataset,
    NaiveDataset,
    VoltronTransformerPretrained,
    VoltronTransformer,
    Utilities,
)
import pdb

CUDA_DEVICE = "cuda:5"
os.environ["CUDA_VISIBLE_DEVICES"] = CUDA_DEVICE.split(":")[-1]

QWEN_SWITCH = True

def train_one_epoch(
    model_utils,
    tb_writer,
    tb_checkpoint,
    train_dl,
    optimizer,
    model,
    max_lr,
    min_lr,
    warmup_iters,
    e_batch_iter,
    lr_decay_iters,
):
    """Training loop for an entire epoch

    Args:
        epoch_index (int): epoch index number
        tb_writer (torch.utils.tensorboard): tensorboard logger

        train_dl (torch.dataloader): train data
            Per batch variable dimensions:
                1. input: [batch_size=batch_size, seq_len=256, num_dimensions=1024)
                2. label: [batch_size=batch_size, seq_len=256]
                3. attention_mask: [batch_size=batch_size, seq_len=256]
                4. predictions: [batch_size=batch_size, seq_len=256]

        optimizer (torch.optim): optimizer
        model (transformer model): model
        loss_fn (torch.loss): loss function

    Returns:
        float: average training loss, accuracy, and precision per epoch
    """

    running_loss = 0.0
    last_loss = 0.0
    last_batch_iter = 0
    for batch_iter, (input, label, mask) in enumerate(train_dl):
        input = input.to(CUDA_DEVICE)
        label = label.to(CUDA_DEVICE)
        mask = mask.to(CUDA_DEVICE)
 

        # pdb.set_trace()
        # Set up loss function
        loss_fn = nn.BCEWithLogitsLoss(reduction="none")
        # Determine the learning rate for this iteration
        current_batch_iter = e_batch_iter + batch_iter
        lr = model_utils.get_lr(
            current_batch_iter, lr_decay_iters, max_lr, min_lr, warmup_iters
        )
        for param_group in optimizer.param_groups:
            param_group["lr"] = lr
        # Forward pass
        predictions = model(input, mask)
        # Loss calculation
        loss = loss_fn(predictions, label)
        loss *= mask
        loss = torch.mean(torch.sum(loss, -1) / (1e-6 + torch.sum(mask, -1)))
        # Calculate gradients
        loss.backward()
        if batch_iter % 4 == 0:
            # Update weights
            optimizer.step()
            # Clear gradient
            optimizer.zero_grad(set_to_none=True)
        # Add to running results
        running_loss += loss.item()
        if batch_iter % tb_checkpoint == (tb_checkpoint - 1):
            last_loss = running_loss / tb_checkpoint
            tb_x = e_batch_iter + batch_iter + 1
            tb_writer.add_scalar("Train loss", last_loss, tb_x)
            tb_writer.add_scalar("Learning rate", optimizer.param_groups[0]["lr"], tb_x)
            running_loss = 0.0
        if batch_iter > 800:
            break
        # print(loss)
        # if last_loss is nan
        if loss != loss:
            pdb.set_trace()
    last_batch_iter = batch_iter
    return last_loss, last_batch_iter


def validation_one_epoch(model_utils, validation_loader, model, pretraining):
    """Validation loop

    Args:
        validation_loader (torch.datapipe): validation data
        model (transformer model): model
        loss_fn (torch.loss): loss function

    Returns:
        float: average validation loss
    """
    loss_fn = nn.BCEWithLogitsLoss(reduction="none")
    running_vloss = 0.0
    running_vrec = 0.0
    running_vprec = 0.0
    running_vacc = 0.0

    all_probabilities = []
    all_labels = []


    total_samples = 0
    zero_label_samples = 0

    total_batches = len(validation_loader)
    debug_batch_idx = random.randint(0, min(total_batches-1, 350))
    with torch.no_grad():
        for batch_iter, (input, label, mask) in enumerate(validation_loader):
            input = input.to(CUDA_DEVICE)
            label = label.to(CUDA_DEVICE)
            mask = mask.to(CUDA_DEVICE)
       
            predictions = model(input, mask)
            vloss = loss_fn(predictions, label)

            # Logging tensors
            flattened_input = torch.flatten(input)

           
            flattened_labels = torch.flatten(label)
            flattened_probabilities = torch.flatten(torch.sigmoid(predictions))
            real_indices = torch.flatten(mask == 1)
            flattened_probabilities = flattened_probabilities[real_indices]
            flattened_labels = flattened_labels[real_indices]
            if not QWEN_SWITCH:
                # print("Here")
                nl_indices = torch.where(
                    (flattened_input == 198) | (flattened_input == 628)
                )
            else:
                nl_indices = torch.where(
                    (flattened_input == 198)
                )        
            # print(len(nl_indices))
            if len(nl_indices) > 1:
                nl_index = nl_indices[1]
            else:
                nl_index = nl_indices[0]
            if not pretraining:
                # Remove non nl tokens
                flattened_probabilities = flattened_probabilities[nl_index]
                flattened_labels = flattened_labels[nl_index]

            # Appending batch logging tensors to return list
            all_probabilities.append(flattened_probabilities)
            all_labels.append(flattened_labels)
            vloss *= mask
            vloss = torch.mean(torch.sum(vloss, -1) / (1e-6 + torch.sum(mask, -1)))
            running_vloss += vloss.item()

            vrecall, vprec, vaccuracy = model_utils.recall_prec_function(
                predictions, label, mask
            )
            running_vrec += vrecall
            running_vprec += vprec
            running_vacc += vaccuracy

            # break for testing
            if batch_iter > 200:
                break
    avg_vloss = running_vloss / (batch_iter + 1)
    avg_vrec = running_vrec / (batch_iter + 1)
    avg_vprec = running_vprec / (batch_iter + 1)
    avg_vacc = running_vacc / (batch_iter + 1)

    cat_probabilities = torch.cat(all_probabilities, dim=-1)
    cat_labels = torch.cat(all_labels, dim=-1)


    return avg_vloss, avg_vrec, avg_vprec, avg_vacc, cat_probabilities, cat_labels


def model_pipe(
    data_name,
    pretraining,
    pretrain_type,
    datapipe,
    dim_model=1024,
    num_head=16,
    num_layer=2,
    target_dim=256,
    batch_size=8,
    num_epochs=1,
    max_lr=1e-4,
    min_lr=1e-6,
    warmup_iters=500,
    tb_checkpoint=10,
    load_checkpoint=False,
    first_tb=True,
    lr_decay_iters=10000,
    tenfold_iteration=9,
):
    """Entire model pipeline

    Args:
        datapipe (torch.datapipe): Input data
        dim_model (int, optional): dimension of model. Defaults to 1024.
        batch_size (int, optional): batch size. Defaults to 8.
        num_epochs (int, optional): total number of epochs to run. Defaults to 1.
    """
    # Load data into batches

    # Shuffle indices before splitting into training and validation set.
    all_indices = list(range(len(datapipe)))
    random.seed(42)  # Seed to ensure shuffling deterministically.
    # random.shuffle(all_indices)
    
    training_set_end_idx = {
        "CWE119": 333,
        "CWE362": 580,
        "CWE416": 1230,
        "CWE476": 541,
        "CWE787": 343
    }
    if QWEN_SWITCH:
        ### vulrag_linux
        training_set_end_idx = {
            "CWE119": 356,
            "CWE362": 663,
            "CWE416": 1378,
            "CWE476": 583,
            "CWE787": 375,
            "CWE20": 373,
            "CWE200": 308,
            "CWE125": 285,
            "CWE401": 207,
            "CWE264": 254
        }


    if pretraining:
        """
        tenfold_float = tenfold_iteration / 10
        valid_index_start = int(tenfold_float * len(datapipe))
        valid_index_end = valid_index_start + int(0.1 * len(datapipe))
        valid_indices = all_indices[valid_index_start:valid_index_end]
        train_indices = [i for i in range(len(datapipe)) if i not in valid_indices]
        
        print(
            f"Training size={len(train_indices)},\n\
        Validation size={len(valid_indices)},\n\
        Validation indices={valid_index_start}, {valid_index_end}\n\
        Total size={len(datapipe)}"
        )
        """


        valid_samples = all_indices[:training_set_end_idx[data_name] + 1]
        
   
        random.seed(42)  
        random.shuffle(valid_samples)
        
    
        split_point = int(0.9 * len(valid_samples))
        train_indices = valid_samples[:split_point]
        valid_indices = valid_samples[split_point:]

        print(
            f"Training size={len(train_indices)},\n\
        Validation size={len(valid_indices)},\n\
        Total size={len(datapipe)}"
        )
    else:
        train_size = int(0.9 * len(datapipe))
        train_indices = all_indices[:train_size]
        valid_indices = all_indices[train_size:]
    
    print("len of train indices", len(train_indices))
    print(train_indices)
    print("len of valid indices", len(valid_indices))
    print(valid_indices)

    train_dp = torch.utils.data.Subset(datapipe, train_indices)
    valid_dp = torch.utils.data.Subset(datapipe, valid_indices)
    train_dl = DataLoader(dataset=train_dp, batch_size=batch_size, shuffle=False)
    validation_loader = DataLoader(
        dataset=valid_dp, batch_size=batch_size, shuffle=False
    )

    if pretraining:
        model = VoltronTransformerPretrained(
            num_layer=num_layer,
            dim_model=dim_model,
            num_head=num_head,
            target_dim=target_dim,
        )
    else:
        num_layer = 8
        model = VoltronTransformer(
            num_layer=num_layer, dim_model=target_dim, num_head=num_head
        )

    model = model.to(CUDA_DEVICE)
    model_utils = Utilities()

    # Loading checkpoint and setting up tensorboard logging
    model_path = f"{data_name}_{pretrain_type}"
    # model_checkpoint_path = f"model_checkpoints/{model_path}"
    model_checkpoint_path = f"model_checkpoints/devign_16B"
    new_checkpoint_path = f"model_checkpoints/{model_path}"
    if load_checkpoint and os.path.exists(model_checkpoint_path) and not QWEN_SWITCH:
        print("Loading checkpoint", model_checkpoint_path)
        model.load_state_dict(torch.load(model_checkpoint_path))
    else:
        print("Training new model")
        if QWEN_SWITCH:
            print("For Qwen")

    if pretraining:
        tb_folder = f"tb_logs/{model_path}_{str(target_dim)}"
        for f in tb_folder:
            try:
                os.remove(f)
            except:
                pass
        tb_writer = SummaryWriter(tb_folder)
        log_folder = (
            f"model_logs/{data_name}/{model_path}_{target_dim}_{tenfold_iteration}"
        )
    else:
        tb_folder = f"tb_logs/{data_name}_{str(target_dim)}_{target_dim}_scratch{str(num_layer)}"
        for f in tb_folder:
            try:
                os.remove(f)
            except:
                pass
        log_folder = f"model_logs/{data_name}/{data_name}_{target_dim}_scratch_{tenfold_iteration}"
    tb_writer = SummaryWriter(tb_folder)

    # Optimizing
    optimizer = optim.Adam(model.parameters(), max_lr)

    best_vloss = 1_000_000.0
    best_vrec = 0
    best_vprec = 0
    best_vacc = 0
    best_prec_rec = 0
    best_epoch = 0
    e_batch_iter = 0
    current_path = os.getcwd()
    try:
        os.mkdir(f"{current_path}/model_checkpoints")
    except OSError:
        pass
    try:
        os.mkdir(f"{current_path}/model_logs/")
    except OSError:
        pass
    try:
        os.mkdir(f"{current_path}/model_logs/{data_name}")
    except OSError:
        pass
    try:
        os.mkdir(log_folder)
    except OSError:
        pass

    for epoch_number in range(num_epochs):
        # Train loop
        model.train()
        avg_loss, last_batch_iter = train_one_epoch(
            model_utils,
            tb_writer,
            tb_checkpoint,
            train_dl,
            optimizer,
            model,
            max_lr,
            min_lr,
            warmup_iters,
            e_batch_iter,
            lr_decay_iters,
        )
        e_batch_iter += last_batch_iter
        # Validation loop
        model.eval()
        (
            avg_vloss,
            avg_vrec,
            avg_vprec,
            avg_vacc,
            cat_probabilities,
            cat_labels,
        ) = validation_one_epoch(model_utils, validation_loader, model, pretraining)
        lr = model_utils.get_lr(
            e_batch_iter, lr_decay_iters, max_lr, min_lr, warmup_iters
        )
        print(
            f"Epoch {epoch_number}: LR: {lr:.5f}, LOSS train {avg_loss:.4f} valid {avg_vloss:.4}, prec: {avg_vprec:.2%}, rec: {avg_vrec:.2%}"
        )

        tb_writer.add_scalar("Validation Loss", avg_vloss, e_batch_iter + 1)
        tb_writer.add_scalar("Validation Recall", avg_vrec, e_batch_iter + 1)
        tb_writer.add_scalar("Validation Precision", avg_vprec, e_batch_iter + 1)
        tb_writer.add_scalar("Validation Accuracy", avg_vacc, e_batch_iter + 1)
        tb_writer.flush()

        # Track best performance, and save the model's state
        prec_rec = 0.5 * avg_vprec + 0.5 * avg_vrec
        if pretraining:
            logging_epoch = 50
        else:
            logging_epoch = 0

        pretraining_logging = (
            (prec_rec >= best_prec_rec)
            and e_batch_iter > logging_epoch
            and avg_vloss < 1
        )
        scratch_logging = avg_vloss < best_vloss
        if (pretraining and pretraining_logging) or (
            (not pretraining) and scratch_logging
        ):
            if pretraining:
                print(f"Found new best performance of avg_vprec: {avg_vprec:.3%}, avg_vrec: {avg_vrec:.3%}")
            else:
                print(f"Found new best performance at validation loss {avg_vloss}")

            log_dict = {
                "prob": cat_probabilities.tolist(),
                "label": cat_labels.tolist(),
            }
            log_files = glob.glob(f"{log_folder}/*")
            for f in log_files:
                os.remove(f)
            logging_file = f"{log_folder}/step_{str(e_batch_iter+1)}.json"
            with open(logging_file, "w+", encoding="utf-8") as file:
                to_write = json.dumps(log_dict, indent=3)
                file.write(to_write + "\n")
            best_epoch = epoch_number
            best_vloss = avg_vloss
            best_vrec = avg_vrec
            best_vprec = avg_vprec
            best_vacc = avg_vacc
            best_prec_rec = prec_rec
            # save model at checkpoint
            # if os.path.exists(model_checkpoint_path):
            #     os.remove(model_checkpoint_path)
            # torch.save(model.state_dict(), model_checkpoint_path)
            
            if os.path.exists(new_checkpoint_path):
                os.remove(new_checkpoint_path)
            torch.save(model.state_dict(), new_checkpoint_path)

    model_str = (
        "Finished training {} epochs for {} dimensions & {} heads on {} {}".format(
            str(num_epochs), str(target_dim), str(num_head), data_name, pretrain_type
        )
    )
    epoch_str = "best epoch: " + str(best_epoch)
    vloss_str = "best vloss: " + str(round(best_vloss, 4))
    recall_str = "best rec: " + str(round(best_vrec, 7))
    precision_str = "best prec: " + str(round(best_vprec, 7))
    acc_str = "best acc: " + str(round(best_vacc, 7))

    logging = True
    if logging:
        f = open("log.txt", "a")
        f.write(
            model_str
            + "\n"
            + epoch_str
            + "\n"
            + vloss_str
            + "\n"
            + recall_str
            + "\n"
            + precision_str
            + "\n"
            + acc_str
            + "\n\n"
        )
        f.close()


def driver():
    # Uses a standard argument parsing library.
    ap = argparse.ArgumentParser()
    ap.add_argument("data_path", help="Path to data root")
    ap.add_argument("data_name", help="Dataset to train on")
    ap.add_argument("pretrain_type", help="codegen checkpoint type")
    ap.add_argument("pretraining", help="Using pretrained model e.g., codegen")
    args = ap.parse_args()

    global QWEN_SWITCH
    if args.pretrain_type == "qwen32b":
        QWEN_SWITCH = True
    else:
        QWEN_SWITCH = False

    # Initialize passed in variables
    data_path = args.data_path
    data_name = args.data_name
    pretrain_type = args.pretrain_type
    pretraining = int(args.pretraining)

    # Data loading
    current_path = os.getcwd()
    data_name_path = f"{current_path}/{data_path}/{data_name}"
    tensors_path = (
        f"{current_path}/{data_path}/codegen_states/{data_name}_{pretrain_type}/"
    )

    if pretraining:
        print(f"Using preloaded codegen hidden states for {data_name}_{pretrain_type}")
        print(tensors_path)
        datapipe = PreloadedDataset(tensors_path)
    else:
        print(f"Naive training for {data_name}")
        datapipe = NaiveDataset(data_name_path)

    # Hyperparameters pretraining
    max_lr = 1e-3
    min_lr = 1e-6
    target_dim = 512 # 1024
    num_epochs = 300
    warmup_iters = 1000
    lr_decay_iters = 20000
    tb_checkpoint = 10
    num_layer = 2

    if not pretraining:
        # Hyperparameters from scratch
        max_lr /= 20
        min_lr /= 20
        warmup_iters = 100
        lr_decay_iters = 5000
        num_epochs = 150
        num_layer = 4
        target_dim = 256

    if target_dim == 1024:
        num_head = 16
        max_lr = max_lr * 0.75
    elif target_dim == 512:
        num_head = 8
        max_lr = max_lr * 0.85
    elif target_dim == 256:
        num_head = 4

    if pretrain_type == "350M":
        dim_model = 1024
    elif pretrain_type == "2B":
        dim_model = 2560
        max_lr = max_lr / 10
        min_lr = min_lr / 10
    elif pretrain_type == "6B" or pretrain_type == "deepseek":
        dim_model = 4096
        max_lr = max_lr / 15
        min_lr = min_lr / 15
    elif pretrain_type == "16B":
        dim_model = 6144
        max_lr = max_lr / 25
        min_lr = min_lr / 25
    elif pretrain_type == "qwen32b":
        dim_model = 5120
        max_lr = max_lr / 20
        min_lr = min_lr / 20

    if data_name == "bugsinpy" or "defects4j" in data_name:
        batch_size = 8
    if data_name == "devign":
        batch_size = 16
    
    if pretrain_type == "qwen32b":
        max_lr = 1e-3/20
        min_lr = 1e-6/20
        warmup_iters = 100
        lr_decay_iters = 5000
        num_epochs = 500
        num_layer = 4
        target_dim = 512
        num_head = 8

    batch_size = 16

    useloop = False
    ten_fold = False
    load_checkpoint = True
    first_tb = False

    print("Starting training")
    if not useloop:
        model_pipe(
            data_name=data_name,
            pretraining=pretraining,
            pretrain_type=pretrain_type,
            datapipe=datapipe,
            dim_model=dim_model,
            num_head=num_head,
            num_layer=num_layer,
            target_dim=target_dim,
            batch_size=batch_size,
            num_epochs=num_epochs,
            max_lr=max_lr,
            min_lr=min_lr,
            warmup_iters=warmup_iters,
            tb_checkpoint=tb_checkpoint,
            load_checkpoint=load_checkpoint,
            first_tb=first_tb,
            lr_decay_iters=lr_decay_iters,
        )

    else:
        if ten_fold:
            for i in range(0, 2):
                model_pipe(
                    data_name=data_name,
                    pretraining=pretraining,
                    pretrain_type=pretrain_type,
                    datapipe=datapipe,
                    dim_model=dim_model,
                    num_head=num_head,
                    num_layer=num_layer,
                    target_dim=target_dim,
                    batch_size=batch_size,
                    num_epochs=num_epochs,
                    max_lr=max_lr,
                    min_lr=min_lr,
                    tb_checkpoint=tb_checkpoint,
                    load_checkpoint=load_checkpoint,
                    first_tb=first_tb,
                    lr_decay_iters=lr_decay_iters,
                    tenfold_iteration=i,
                )

        else:
            target_dims = [1024, 512, 256]
            num_heads = [16, 8, 4]
            for i, target_dim in enumerate(target_dims):
                num_head = num_heads[i]
                model_pipe(
                    data_name=data_name,
                    pretraining=pretraining,
                    pretrain_type=pretrain_type,
                    datapipe=datapipe,
                    dim_model=dim_model,
                    num_head=num_head,
                    num_layer=num_layer,
                    target_dim=target_dim,
                    batch_size=batch_size,
                    num_epochs=num_epochs,
                    max_lr=max_lr,
                    min_lr=min_lr,
                    tb_checkpoint=tb_checkpoint,
                    load_checkpoint=load_checkpoint,
                    first_tb=first_tb,
                    lr_decay_iters=lr_decay_iters,
                )


if __name__ == "__main__":
    driver()



