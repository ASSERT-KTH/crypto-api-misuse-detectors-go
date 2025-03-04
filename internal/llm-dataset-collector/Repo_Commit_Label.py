import subprocess
import os
import pandas as pd
import numpy as np

from huggingface_hub import login
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import tensorflow as tf


def get_commit_message(repo_name, commitID):
    cmd = f"cd {repo_name} && git log -n 1 --pretty=format:%B {commitID}"
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout


def get_all_commit_ids(repo_name):
    cmd = f'cd {repo_name} && git log --pretty=format:"%H"'
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    commit_ids = result.stdout.split('\n')
    return commit_ids


def AI_text_generator(repo, commitID):
    commit_mgs = get_commit_message(repo, commitID)
    messages = [
        {"role": "system", "content": "role"},
        {"role": "user", "content": f"""
        You are looking through GitHub commits message to determine if a commit is to fix a vulnerability in the code.
        Vulnerability also include: integer overflow, authentication and access control, buffer handling, code quality,
        control-flow management, encryption and randomness, error handling, file handling, information leaks,initialization 
        and shutdown, injection, and pointer, reference handling, deadlocks, and others. 
        Please read the commit message below and determine if it is to fix vulnerability, answer with yes or no.

        {commit_mgs}
        """},
    ]
    return messages


def Vuln_Label(repo, commitID, model):
    try:
        model_id = "meta-llama/Meta-Llama-3-70B-Instruct"
        tokenizer = AutoTokenizer.from_pretrained(model_id)

        input_msg = AI_text_generator(repo, commitID)

        input_ids = tokenizer.apply_chat_template(
            input_msg,
            add_generation_prompt=True,
            return_tensors="pt"
        ).to(model.device)

        terminators = [
            tokenizer.eos_token_id,
            tokenizer.convert_tokens_to_ids("<|eot_id|>")
        ]
        outputs = model.generate(
            input_ids,
            max_new_tokens=10,
            eos_token_id=terminators,
            do_sample=True,
            temperature=0.6,
            top_p=0.9,
        )
        response = outputs[0][input_ids.shape[-1]:]

        label = tokenizer.decode(response, skip_special_tokens=True)

        if label.lower()[:3] == "yes":
            return "yes"
        else:
            return "no"
    except:
        print("Error in lableing:", commitID)
        return "error"


def split_df(df, chunk_size):
    chunks = [df[i:i + chunk_size] for i in range(0, df.shape[0], chunk_size)]
    return chunks


def main():

    model_id = "meta-llama/Meta-Llama-3-70B-Instruct"
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )

    repo_list = ['linux', 'FFmpeg', 'chromium', 'bind9', 'httpd', 'libpng', 'nginx', 'openssl', 'qemu', 'openssh-portable', 'ImageMagick']

    for repo in repo_list:
        commit_ids = get_all_commit_ids(repo)
        df = pd.DataFrame(commit_ids, columns=['Commit ID'])
        print("Start Process", repo)
        for index, row in df.iterrows():
            print("Process:", index, "commit:", row['Commit ID'])
            df.at[index, 'Vuln Label'] = Vuln_Label(repo, row['Commit ID'], model)
        df.to_csv(f'{repo}_Vuln.csv')

if __name__ == '__main__':
    main()
