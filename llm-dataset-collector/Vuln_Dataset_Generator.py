import subprocess
import os
import pandas as pd
import numpy as np
import re
import clang.cindex
from clang.cindex import Index, CursorKind, TranslationUnitLoadError

from huggingface_hub import login
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import tensorflow as tf


class Parser:
    def __init__(self, repo_name):
        self.repo_name = repo_name

        self.commit_id = None

        self.pre_commit_id = None

        self.model_id = None
        self.model = None
        self.vuln_patch_summary = None
        self.vuln_type = None

        self.code_file_lines = None

    def set_commit_id(self, commit_id):
        self.commit_id = commit_id

    def process_commit_id(self):
        # Filter the files
        try:
            data = self.create_diff_hunks_list_dict()
            if len(data) == 0:
                print("1st diff_hunk filter return nothing:", self.commit_id)
                return None
            if len(data.keys()) > 20:
                print("too many files:", self.commit_id)
                return None

            # Filter the sections
            diff_hunk_dict_section_list = self.create_diff_hunk_dict_section_list(data)

            if len(diff_hunk_dict_section_list) == 0:
                print("2nd diff_hunk_section_filter return nothing:", self.commit_id)
                return None
        except Exception as e:
            print('error in process_commit_id, step creat diff hunk list')
            print('error:', e)

        try:
            file_dict_funct_dict = {}
            diff_hunk_dict_func_list = {}
            vuln_file_dict_funct_dict = {}
            multi_change_bool = False

            self.commit_checkout(self.commit_id)

            for file_name in diff_hunk_dict_section_list.keys():
                func_lst = self.create_func_line_list(f"{self.repo_name}/{file_name}")
                if len(func_lst) == 0:
                    continue
                file_dict_funct_dict[file_name] = func_lst

            self.commit_checkout(self.pre_commit_id)
            for file_name in file_dict_funct_dict.keys():
                func_lst = self.create_func_line_list(f"{self.repo_name}/{file_name}")
                vuln_file_dict_funct_dict[file_name] = func_lst
        except Exception as e:
            print('error in parser in parsing all funcs')
            print('error:', e)

        try:
            self.commit_checkout(self.commit_id)
            file_dict_funct_dict, vuln_file_dict_funct_dict = self.filter_dict_function_exit_both_file(
                file_dict_funct_dict, vuln_file_dict_funct_dict
            )

            valid_file_names = set(file_dict_funct_dict.keys()) & set(vuln_file_dict_funct_dict.keys())

            diff_hunk_dict_section_list = {
                file_name: sections
                for file_name, sections in diff_hunk_dict_section_list.items()
                if file_name in valid_file_names
            }
        except Exception as e:
            print("error union set func dict of both files")
            print("error:", e)

        try:
            diff_hunk_dict_section_func_list = {}
            for file_name in file_dict_funct_dict.keys():
                try:
                    func_lst = file_dict_funct_dict[file_name]
                    section_lst = diff_hunk_dict_section_list[file_name]
                    diff_hunk_dict_section_func_list[file_name] = []
                    for section in section_lst:
                        start_line_extract_before, num_line_extract_before, start_line_extract_after, num_line_extract_after = self.get_diff_hunk_info(
                            section)
                        temp_section_func_list = []
                        for i in func_lst:
                            func_name = i[0]
                            func_start = i[1]
                            func_end = i[2]

                            modified_line = start_line_extract_after + 3

                            if func_start <= modified_line <= func_end:
                                temp_section_func_list.append((section, func_name, func_start, func_end))
                        temp_fix_func = max(temp_section_func_list, key=lambda x: abs(x[3] - x[2]))
                        diff_hunk_dict_section_func_list[file_name].append(temp_fix_func)
                except Exception as e:
                    print('error in first loop,', e)

                try:
                    if len(diff_hunk_dict_section_func_list[file_name]) == 0:
                        print("diff_hunk_dict_section_func_list[file_name] len 0 part 1")
                        print("filename:", file_name)
                        continue
                    if len(diff_hunk_dict_section_func_list[file_name]) > 1:
                        # clean
                        temp_name = ""
                        new_list = []
                        for i in diff_hunk_dict_section_func_list[file_name]:
                            temp_func_name = i[1]
                            if temp_func_name != temp_name:
                                temp_name = temp_func_name
                                new_list.append(i)
                            else:
                                temp_tup = (new_list[len(new_list) - 1][0] + '\n' + i[0], i[1], i[2], i[3])
                                new_list[len(new_list) - 1] = temp_tup
                        diff_hunk_dict_section_func_list[file_name] = new_list
                except Exception as e:
                    print("error part 2:", e)
                    #  Find Valid diff hunk section
                try:
                    if (len(diff_hunk_dict_section_func_list[file_name]) > 1) or (len(file_dict_funct_dict.keys()) > 1):
                        multi_change_bool = True
                        if not self.vuln_patch_summary:
                            self.llm_vuln_summary()
                        new_list = []
                        if len(diff_hunk_dict_section_func_list[file_name]) == 0:
                            print("diff_hunk_dict_section_func_list[file_name] len 0 part 2")
                            print("file_name:", file_name)
                        if not diff_hunk_dict_section_func_list[file_name]:
                            print("diff_hunk_dict_section_func_list[file_name] part 2 is none type")
                        for i in diff_hunk_dict_section_func_list[file_name]:
                            diff_section = i[0]
                            func_name = i[1]
                            func_start = i[2]
                            func_end = i[3]
                            res = self.llm_vuln_diff_hunk(file_name, func_name, diff_section)
                            print('res:', res, file_name)
                            if res == 'yes':
                                new_list.append((diff_section, func_name, func_start, func_end))
                        diff_hunk_dict_func_list[file_name] = new_list
                    else:
                        diff_hunk_dict_func_list[file_name] = diff_hunk_dict_section_func_list[file_name]
                except Exception as e:
                    print("error part 3:", e)
        except Exception as e:
            print('error in Parser finding functions')
            print('error:', e)
        # Extract Vuln pair
        try:
            file_vul_function_pair_list = []
            for file_name in diff_hunk_dict_func_list.keys():
                for i in diff_hunk_dict_func_list[file_name]:
                    func_name = i[1]
                    func_start = i[2]
                    func_end = i[3]

                    self.commit_checkout(self.commit_id)

                    function_code_patch = self.extract_function_code(f"{self.repo_name}/{file_name}", func_start,
                                                                     func_end)
                    temp_vuln_func_list = []
                    for item in vuln_file_dict_funct_dict[file_name]:
                        if item[0] == func_name:
                            temp_vuln_func_list.append(item)

                    temp_fix_vuln_func = max(temp_vuln_func_list, key=lambda x: abs(x[2] - x[1]))
                    func_start = temp_fix_vuln_func[1]
                    func_end = temp_fix_vuln_func[2]
                    self.commit_checkout(self.pre_commit_id)
                    function_code_vuln = self.extract_function_code(f"{self.repo_name}/{file_name}", func_start,
                                                                    func_end)

                    file_vul_function_pair_list.append((file_name, func_name, function_code_vuln, function_code_patch))
        except Exception as e:
            print('error in Parser extract funcs pair')
            print('error:', e)

        self.vuln_patch_summary = None

        return file_vul_function_pair_list, multi_change_bool

    def set_pre_commit_id(self, pre_commit_id):
        self.pre_commit_id = pre_commit_id

    def set_vuln_type(self, vuln_type):
        self.vuln_type = vuln_type

    def set_llm_model(self, model_id, model):
        self.model_id = model_id
        self.model = model

    def commit_checkout(self, commit_id):
        subprocess.run(
            ["git", "-C", self.repo_name, "reset", "--hard"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True
        )
        # Remove untracked files
        subprocess.run(
            ["git", "-C", self.repo_name, "clean", "-fd"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True
        )
        cmd_file_change = f"cd {self.repo_name} && git checkout {commit_id}"

        check = subprocess.run(cmd_file_change, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # print('check', check)

    def create_diff_hunks_list_dict(self):
        # Get the list of the modified files of the commit
        cmd_file_change = f"cd {self.repo_name} && git show {self.commit_id} --diff-merges=first-parent --name-only | grep -vE '^(Merge:|commit |Author:|Date:| )'"
        result_file_changes = subprocess.run(cmd_file_change, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             shell=True, text=True)
        file_change_list = [line for line in result_file_changes.stdout.split('\n') if line.strip()]

        # Take C and C++ file only
        file_extensions = [".c", ".cpp", ".cc"]
        target_files = [file for file in file_change_list if any(file.endswith(ext) for ext in file_extensions)]

        filter_diff_hunk_dict = {item: [] for item in target_files}

        # Get git diff output
        cmd_git_diff = f"cd {self.repo_name} && git show {self.commit_id} --diff-merges=first-parent | grep -vE '^(Merge:|commit |Author:|Date:| )'"
        git_diff_result = subprocess.run(cmd_git_diff, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                         text=True)
        git_diff_output = git_diff_result.stdout

        # Extract each hunk
        lines = git_diff_output.split('\n')
        for file_name in filter_diff_hunk_dict:
            i = 0
            while (i < len(lines)):
                code_change = ""
                diff_hunks_list = []
                line = lines[i]
                if "diff" in line and file_name in line:
                    while True and i < len(lines) - 1:
                        code_change += line + "\n"
                        i += 1
                        line = lines[i]
                        if ("diff --git" in line) or (i == len(lines) - 1):
                            diff_hunks_list.append(code_change)
                            i = len(lines)  # to cancel the outter loop
                            break
                else:
                    i += 1
            filter_diff_hunk_dict[file_name] = diff_hunks_list

        return filter_diff_hunk_dict

    def create_diff_hunk_dict_section_list(self, diff_hunk_dict):
        diff_hunk_dict_section_list = {}
        for file_name in diff_hunk_dict.keys():
            filtered_diff_hunk_section_list = []
            diff_hunk = diff_hunk_dict[file_name][0]
            diff_hunk_section_list = self.create_diff_hunk_sections_list(diff_hunk)
            self.set_file_code(file_name)
            for section in diff_hunk_section_list:
                if self.filter_check_diff_hunk_section(section):
                    filtered_diff_hunk_section_list.append(section)

            if len(filtered_diff_hunk_section_list) != 0:
                diff_hunk_dict_section_list[file_name] = filtered_diff_hunk_section_list

        return diff_hunk_dict_section_list

    def set_file_code(self, file_name):
        cmd = f'cd {self.repo_name} && git show --no-patch {self.commit_id}:{file_name}'
        cmd_result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        cmd_result = cmd_result.stdout

        code_file = cmd_result
        self.code_file_lines = code_file.split('\n')

    def create_diff_hunk_sections_list(self, diff_hunk=""):
        if not diff_hunk:
            diff_hunk = self.diff_hunk

        lines = diff_hunk.split('\n')

        # Extract into different sections
        i = 0
        diff_hunk_sections_list = []
        while i < len(lines):
            code_change = ""
            line = lines[i]
            if "@@" in line:
                while True and i < len(lines) - 1:
                    code_change += line + "\n"
                    i += 1
                    line = lines[i]
                    if "@@" in line or (i == len(lines) - 1):
                        diff_hunk_sections_list.append(code_change)
                        break
            else:
                i += 1

        self.diff_hunk_sections_list = diff_hunk_sections_list

        return diff_hunk_sections_list

    def get_diff_hunk_info(self, diff_hunk_section=""):
        if not diff_hunk_section:
            diff_hunk_section = self.diff_hunk_section
        # Get modified lines
        before_change_lines = 0
        after_change_lines = 0
        line_change_pattern = re.compile(r'^@@ -(\d+),(\d+) \+(\d+),(\d+) @@')
        for line in diff_hunk_section.split('\n'):
            match = line_change_pattern.match(line)
            if match:
                before_change_lines = int(match.group(1)), int(match.group(2))
                after_change_lines = int(match.group(3)), int(match.group(4))
                break
        if not before_change_lines or not after_change_lines:
            print("Error: no modify line change in git diff output detect")
            return None, None

        start_line_extract_before = before_change_lines[0]
        num_line_extract_before = before_change_lines[1]
        start_line_extract_after = after_change_lines[0]
        num_line_extract_after = after_change_lines[1]

        return start_line_extract_before, num_line_extract_before, start_line_extract_after, num_line_extract_after

    def create_func_line_list(self, file_path, language=None):
        """
        Parses a source or header file to extract functions and their line numbers.

        Args:
            file_path (str): Path to the source file.
            language (str, optional): Programming language ('c' or 'c++').
                                      If None, it's auto-detected from the file extension.

        Returns:
            list: A list of tuples where each tuple contains
                  (function_name, start_line, end_line).
        """
        if language is None:
            if file_path.endswith('.c'):
                language = 'c'
            elif file_path.endswith(('.cpp', '.cc', '.hpp', '.h')):
                language = 'c++'
            else:
                raise ValueError("Unsupported file extension. Use .c for C files or .cpp/.hpp/.h for C++ files.")

        # Define parsing arguments
        args = []
        if language == 'c++':
            args = ['-std=c++17', '-I/usr/include', '-I/usr/local/include']
        elif language == 'c':
            args = ['-std=c99', '-I/usr/include', '-I/usr/local/include']

        func_list = []

        try:
            # Create Clang index
            index = Index.create()

            # Parse the translation unit
            translation_unit = index.parse(file_path, args=args)

            # Log diagnostics for debugging
            # for diag in translation_unit.diagnostics:
            #     print(f"Diagnostic: {diag}")

            # Traverse the AST
            for node in translation_unit.cursor.get_children():
                if node.kind in [
                    CursorKind.FUNCTION_DECL,  # Regular functions
                    CursorKind.CXX_METHOD,  # Class methods (C++)
                    CursorKind.FUNCTION_TEMPLATE,  # Templates (C++)
                ]:
                    func_list.append(
                        (node.spelling, node.extent.start.line, node.extent.end.line)
                    )

        except TranslationUnitLoadError as e:
            print(f"Error parsing translation unit: {e}")
            print("file_path:", file_path)
            return []

        return func_list

    def filter_dict_function_exit_both_file(self, dict1, dict2):
        # Identify filenames to keep based on function overlap
        common_files = set(dict1.keys()) & set(dict2.keys())

        # Iterate over the common files and check function overlap
        for file_name in list(common_files):  # Use list to avoid modifying the set during iteration
            functions_1 = set(func[0] for func in dict1[file_name])
            functions_2 = set(func[0] for func in dict2[file_name])

            # If no functions overlap, remove the file from both dictionaries
            if not functions_1 & functions_2:
                dict1.pop(file_name, None)
                dict2.pop(file_name, None)

        # Remove files that were not in both dictionaries initially
        for file_name in list(dict1.keys()):
            if file_name not in common_files:
                dict1.pop(file_name)

        for file_name in list(dict2.keys()):
            if file_name not in common_files:
                dict2.pop(file_name)

        return dict1, dict2

    def extract_function_code(self, file_path, start_line, end_line):
        """
        Extracts the full code of a function from a source file based on start and end line numbers.

        Args:
            file_path (str): Path to the source file.
            start_line (int): Starting line number of the function.
            end_line (int): Ending line number of the function.

        Returns:
            str: The full code of the function as a string.
        """
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

                # Extract the specific lines corresponding to the function
                function_code = lines[start_line - 1:end_line]

                # Join and return the extracted lines as a single string
                return ''.join(function_code)
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def filter_check_diff_hunk_section(self, diff_hunk_section):
        start_line_extract_before, num_line_extract_before, start_line_extract_after, num_line_extract_after = self.get_diff_hunk_info(
            diff_hunk_section)

        delete_chunk = []
        add_chunk = []
        lines = diff_hunk_section.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            modify_line_check = ((line[0] == '+' or line[0] == '-') and (
                    line.split()[0] != "+++" and line.split()[0] != "---")) if line else False
            if not (line) or not (modify_line_check):
                i += 1
                continue
            if modify_line_check and i < len(lines) - 1 and len(line) != 1:
                j = i
                while j < len(lines):
                    line = lines[j]
                    if not (line) or not (line.replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "")):
                        j += 1
                        continue
                    if line[0] == '+':
                        add_chunk.append(line[1:])
                    else:
                        delete_chunk.append(line[1:])
                    j += 1
                break
            else:
                i += 1

        def check_all_deletes_change():
            lines = diff_hunk_section.split('\n')
            for line in lines:
                if not (line) or line.split()[0] == "+++" or line.split()[0] == "---":
                    continue
                if line[0] == '+':
                    return False
            return True

        def check_all_comments_change():
            start_line_extract = start_line_extract_after
            num_line_extract = num_line_extract_after

            # Check for full-line comments or inline comments
            for add_line, del_line in zip(add_chunk, delete_chunk):
                stripped_add = add_line.replace(" ", "")
                stripped_del = del_line.replace(" ", "")

                if not stripped_add or not stripped_del:
                    continue

                # Determine the index where the comment starts
                add_comment_index = stripped_add.find('/*') if '/*' in stripped_add else len(stripped_add)
                del_comment_index = stripped_del.find('/*') if '/*' in stripped_del else len(stripped_del)

                # Match beginning or end up to the start of the comment
                if ('/*' in stripped_add and '*/' in stripped_add) or ('/*' in stripped_del and '*/' in stripped_del):
                    if stripped_add[:add_comment_index] == stripped_del[:del_comment_index]:
                        return True

                add_comment_index = stripped_add.find('//') if '//' in stripped_add else len(stripped_add)
                del_comment_index = stripped_del.find('//') if '//' in stripped_del else len(stripped_del)
                if ('/.' in stripped_add and '*/' in stripped_add) or ('/*' in stripped_del and '*/' in stripped_del):
                    if stripped_add[:add_comment_index] == stripped_del[:del_comment_index]:
                        return True

                # Check for block or full-line comments
                if stripped_add.startswith("//") or '/*' in stripped_add or '*/' in stripped_add:
                    return True

            # check if in comment block
            index = start_line_extract + 3
            while index > 0:
                file_line = self.code_file_lines[index]
                if '/*' in file_line and not ('*/' in file_line):
                    return True
                elif '*/' in file_line:
                    return False
                index -= 1
            return False

        def check_empty_space_change():
            lines = diff_hunk_section.split('\n')
            i = 0
            while i < len(lines):
                line = lines[i]
                modify_line_check = ((line[0] == '+' or line[0] == '-') and (
                        line.split()[0] != "+++" and line.split()[0] != "---")) if line else False
                if not line or not modify_line_check:
                    i += 1
                    continue
                if modify_line_check and i < len(lines) - 1 and len(line) != 1:
                    j = i
                    # Get the delete and addition chunk of the changes
                    delete_chunk = []
                    add_chunk = []
                    while j < len(lines):
                        line = lines[j]
                        if not (line) or not (
                                line.replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "")):
                            j += 1
                            continue
                        if line[0] == '+':
                            add_chunk.append(line)
                        else:
                            delete_chunk.append(line)
                        j += 1
                    # Check if it is extra lines and spaces change
                    if len(add_chunk) != len(delete_chunk):
                        return False
                    else:
                        for k in range(0, len(delete_chunk)):
                            delete_line = delete_chunk[k][1:].replace(" ", "").replace("\t", "").replace("\n",
                                                                                                         "").replace(
                                "\r", "")
                            add_line = add_chunk[k][1:].replace(" ", "").replace("\t", "").replace("\n", "").replace(
                                "\r", "")
                            if delete_line != add_line:
                                return False
                    break
                else:
                    i += 1
            return True

        try:
            return not (check_all_deletes_change() or check_empty_space_change() or check_all_comments_change())
        except Exception as e:
            print("error in filter_check_diff_hunk_section: ", e)
            return False

    def get_commit_message(self):
        cmd = f"cd {self.repo_name} && git log -n 1 --pretty=format:%B {self.commit_id}"
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

    def llm_vuln_summary(self):
        try:
            tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            commit_mgs = self.get_commit_message()

            # Ensure commit_mgs and other fields are properly populated
            if not commit_mgs or not self.repo_name or not self.vuln_type:
                raise ValueError("Missing required inputs for prompt construction.")

            # Prepare the input message as a single string
            input_msg = f"""
            You are looking at a {self.repo_name} GitHub commit message that is a security vulnerability patch. 
            The security vulnerability labeled is {self.vuln_type}.
            Please read the commit message and summarize the security patch. 
            Include any information about the vulnerability fix in the function or file.
            Do not include the title or contributors in your response.

            Commit message: {commit_mgs}  # Limit message length for better processing
            """

            # Tokenize input directly (ensure input_msg is a single string)
            input_ids = tokenizer(
                input_msg,  # Pass the input as a single string
                return_tensors="pt"
            ).to(self.model.device)

            # Handle pad_token_id if it's not set by the tokenizer
            pad_token_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id

            # Create attention mask (non-padding tokens get attention)
            attention_mask = (input_ids.input_ids != pad_token_id).to(torch.long)

            eos_token_id = tokenizer.eos_token_id
            eot_id = tokenizer.convert_tokens_to_ids("<|eot_id|>")
            terminators = [eos_token_id, eot_id] if eot_id else [eos_token_id]

            # Model generation
            outputs = self.model.generate(
                input_ids.input_ids,
                attention_mask=attention_mask,  # Pass the attention mask
                max_new_tokens=70,
                eos_token_id=terminators,
                pad_token_id=pad_token_id,  # Ensure pad_token_id is set
                do_sample=True,
                temperature=0.6,
                top_p=0.9,
            )

            # Extract response and decode
            response = outputs[0][input_ids.input_ids.shape[-1]:]
            self.vuln_patch_summary = tokenizer.decode(response, skip_special_tokens=True)

            return self.vuln_patch_summary

        except Exception as e:
            import traceback
            print(f"Error during LLM processing for {self.repo_name}, commit {self.commit_id}:")
            traceback.print_exc()  # Log full stack trace for debugging
            return ""

    def llm_vuln_diff_hunk(self, file_name, function_name, diff_hunk_section):
        try:
            tokenizer = AutoTokenizer.from_pretrained(self.model_id)

            # Prepare input message
            input_msg2 = (
                f"You are analyzing a GitHub commit in the {self.repo_name} repository. "
                f"This commit fixes a security vulnerability related to {self.vuln_type}. "
                f"The patch summary: {self.vuln_patch_summary}.\n"
                f"Please review the modification details below and answer only with 'yes' or 'no'"
                f"if this section matches the described patch.\n\n"
                f"File: {file_name}\n"
                f"Function: {function_name}\n"
                f"Modification:{diff_hunk_section}\n"

                f"Please answer only with 'yes' or 'no' if this section matches the described patch."
            )
            # Tokenize input directly (ensure input_msg2 is a single string)
            input_ids = tokenizer(
                input_msg2,  # Pass the input as a single string
                return_tensors="pt"
            ).to(self.model.device)

            # Handle pad_token_id if it's not set by the tokenizer
            pad_token_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id

            # Create attention mask (non-padding tokens get attention)
            attention_mask = (input_ids.input_ids != pad_token_id).to(torch.long)

            eos_token_id = tokenizer.eos_token_id
            eot_id = tokenizer.convert_tokens_to_ids("<|eot_id|>")
            terminators = [eos_token_id, eot_id] if eot_id else [eos_token_id]

            # Model generation
            outputs = self.model.generate(
                input_ids.input_ids,
                attention_mask=attention_mask,  # Pass the attention mask
                max_new_tokens=8,
                eos_token_id=terminators,
                pad_token_id=pad_token_id,  # Ensure pad_token_id is set
                do_sample=True,
                temperature=0.6,
                top_p=0.9,
            )

            # Extract response and decode
            response_2 = outputs[0][input_ids.input_ids.shape[-1]:]
            vuln_patch = tokenizer.decode(response_2, skip_special_tokens=True)

            # Check if response starts with 'yes'
            if 'yes' in vuln_patch.lower():
                return "yes"
            else:
                return "no"

        except Exception as e:
            import traceback
            print("Error in llm_vuln_diff_hunk:", e)
            traceback.print_exc()  # Log full stack trace for debugging
            return "error"


class RepoVuln:
    def __init__(self, repo_name):
        self.repo_name = repo_name

        self.data_file_name = None
        self.commit_vuln_label_df = None
        self.vuln_func_df = None

        self.model_id = None
        self.model = None

        self.parser = Parser(repo_name)

    def set_repo_name(self, repo_name):
        self.repo_name = repo_name
        self.parser = Parser(repo_name)
        self.parser.set_llm_model(self.model_id, self.model)

    def read_vuln_label_file(self, file_name):
        self.commit_vuln_label_df = pd.read_csv(file_name)

    def set_vuln_df(self, df):
        self.commit_vuln_label_df = df

    def set_llm_model(self, model_id):
        self.model_id = model_id
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=torch.bfloat16,
            device_map="auto",
        )

        self.parser.set_llm_model(self.model_id, self.model)

    def make_vuln_func_dataset(self):
        print("Start making dataset")
        columns = ['repo_name', 'github_link', 'commit_id', 'previous_commit_id', 'vuln_label', 'vuln_type',
                   'file_name', 'function_name', 'vuln_func', 'fix_vuln_func']

        dataset = pd.DataFrame(columns=columns)
        df = self.commit_vuln_label_df

        for index, row in df.iterrows():
            commit_id = row['commit_id']
            try:
                # Determine previous commit ID
                if index < len(df) - 1:
                    prev_commit_id = df.iloc[index + 1]['commit_id']
                else:
                    print('No more previous commit to check')
                    break
                if (row['vuln_label'] == 'yes') and (row['vuln_type'] != 'none'):
                    print("Processing commit:", self.repo_name, commit_id)

                    result = self.parser.set_commit_id(commit_id)

                    self.parser.set_pre_commit_id(prev_commit_id)
                    self.parser.set_vuln_type(row['vuln_type'])

                    out, multi_change_bool = self.parser.process_commit_id()

                    if not out:
                        print(f"out is null in {self.repo_name} {commit_id}")
                        continue

                    # Process output if available
                    for item in out:
                        file_name, function_name, vuln_func, non_vuln_func = item

                        new_row = pd.DataFrame({
                            'repo_name': row['repo_name'],
                            'github_link': row['github_link'],
                            'commit_id': [commit_id],
                            'previous_commit_id': [prev_commit_id],
                            'vuln_label': row['vuln_label'],
                            'vuln_type': row['vuln_type'],
                            'file_name': [file_name],
                            'function_name': [function_name],
                            'vuln_func': [vuln_func],
                            'fix_vuln_func': [non_vuln_func],
                            'multi_change': [1 if multi_change_bool else 0]
                        })

                        dataset = pd.concat([dataset, new_row], ignore_index=True)
            except Exception as e:
                print("Error processing in make_vuln_func_dataset", self.repo_name, commit_id)
                print("Error:", e)
                continue

        return dataset


if __name__ == "__main__":
    clang.cindex.Config.set_library_file('/usr/local/lib/python3.10/dist-packages/clang/native/libclang.so')
    index = clang.cindex.Index.create()

    df = pd.read_csv('all_commits_label.csv')

    repo_list = ['linux', 'FFmpeg', 'chromium', 'bind9', 'httpd', 'libpng', 'nginx', 'openssl', 'qemu', 'openssh-portable', 'ImageMagick']

    generator = RepoVuln(repo_list[0])
    model_id = "meta-llama/Meta-Llama-3.1-70B-Instruct"
    generator.set_llm_model(model_id)

    for repo_name in repo_list:
        df_new = df[df["repo_name"] == repo_name]
        df_new = df_new.reset_index()

        generator.set_repo_name(repo_name)
        generator.set_vuln_df(df_new)
        dataset = generator.make_vuln_func_dataset()

        dataset.to_excel(f"{repo_name}_vuln_dataset.xlsx")