import subprocess
import os
import pandas as pd
import numpy as np
import re

from huggingface_hub import login
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import tensorflow as tf


def get_commit_message(repo_name, commitID):
    cmd = f"cd {repo_name} && git log -n 1 --pretty=format:%B {commitID}"
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    raw_msg = result.stdout

    out_msg = []
    msg_list = raw_msg.split("\n")
    for i in msg_list:
        if i.strip():
            ignore_patterns = [
                re.compile(r"signed[-\s]off[-\s]by", re.IGNORECASE),
                re.compile(r"reviewed[-\s]by", re.IGNORECASE),
                re.compile(r"cc", re.IGNORECASE),
                re.compile(r"merge[-\s]tag", re.IGNORECASE)
            ]

            if any(pattern.search(i) for pattern in ignore_patterns):
                continue

            out_msg.append(i)

    out_msg = "\n".join(out_msg)

    if len(out_msg) > 3000:
        print("Message too long, truncating")
        return out_msg[:3000]

    return out_msg


def AI_text_generator(commitID, repo):
    commit_mgs = get_commit_message(repo, commitID)
    messages = [
        {"role": "system", "content": "role"},
        {"role": "user", "content": f"""
        You are looking through {repo} GitHub commits message to determine if a commit is to fix a security vulnerability in the code.
        Given these security vulnerability: out-of-bounds write, out-of-bounds read, buffer overflow, format string vulnerability, race conditions, double free,
        use-after-free, improper input validation, null pointer derefernce, integer overflow or wraparound, improper restriction of operations within the bounds of a memory buffer,
        improper privilege management, incorrect default permissions, information leak, and denial of service.
        Read the following commit message and label any applicable vulnerabilities. If the commit does not address any of these vulnerabilities, please respond with "none."

        Commit message: {commit_mgs}

        Response format: List applicable vulnerabilities or respond with 'none.'
        """},
    ]
    return messages


def Vuln_Label(repo, commitID, tokenizer, model):
    try:
        input_msg = AI_text_generator(commitID, repo)

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

        return label
    except Exception as e:
        print("Error:", e)
        return "error"


def main():
    df = pd.read_csv('vuln_commit.csv')

    model_id = "meta-llama/Meta-Llama-3.1-70B-Instruct"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )

    df['Vuln_type'] = None
    for index, row in df.iterrows():
        df.at[index, 'Vuln_type'] = Vuln_Label(row['repo_name'], row['Commit ID'], tokenizer, model)
        print(row['repo_name'],"index: ", index, "commit ID: ", row['Commit ID'])
        print("Label: ", df.at[index, 'Vuln_type'])

    df.to_csv('commit_vuln_type.csv')


if __name__ == '__main__':
    main()

