#!/usr/bin/env python

import sys
import subprocess
import re

"""This pre-receive hook attempts to perform some basic secrets detection before code is committed to a repository
    Currently there are a number of todo's such as adding validation checks, decoding base64, checking shannon
    entropy """


"""This pattern list represents several basic detections, but should be reimplemented as a dictionary so we know
   which detectors failed"""

pattern_list = [r'(?<=password\=)[^\s]*', r'(?<=PASSWORD\=)[^\s]*',
                r'(?=AKCp)[^\s]*', r'.*\=$', r'(?<=secret\=)[^\s]*',
                r'(?<=SECRET\=)[^\s]*', r'(?<=token\=)[^\s]*',
                r'(?<=TOKEN\=)[^\s]*', r'(?<=apikey\=)[^\s]*',
                r'(?<=api_key\=)[^\s]*', r'(?<=APIKEY\=)[^\s]*',
                r'(?<=API_KEY\=)[^\s]*', r'[a-zA-Z0-9+/]{28,1000}={0-2}',
                r'(?=dapi)[^\s]*', r'(?=dckr_pat_)[^\s]*']

# Arguments arrive over stdin and are sent to main, main send the args here to be parsed and turned into a a tuple

def get_arguments(line):
    args_list = line.split()
    old_ref = args_list[0]
    new_ref = args_list[1]
    ref_name = args_list[2]
    args_tuple = (old_ref, new_ref, ref_name)
    return args_tuple

# This function captures just the names of the files that have been changed, easier way to do it then parsing diffs

def get_changed_files(tupled_args):
    file_list = []
    captured_ref = tupled_args[1]
    git_diff = subprocess.run(["git", "diff-tree", "--no-commit-id", "--name-only", captured_ref, "-r"], capture_output=True, text=True)
    files = git_diff.stdout.split("\n")
    for f in files:
        if f != "":
            file_list += [f]
    return file_list

# The show string is useful for sending to git the exact <version>:<filename> we want git show to show

def create_show_string(changed_files, tupled_args):
    files_to_get_contents = []
    captured_ref = tupled_args[1]
    for f in changed_files:
        show_string = captured_ref + ":" + f
        files_to_get_contents.append(show_string.strip())
    return files_to_get_contents

# Utilizing the previous show string we can use git show to just get the contents of a file

def check_contents_of_changed_files(files_to_check_contents):
    total_matches = []
    for f in files_to_check_contents:
        output = subprocess.run(["git","show", f], capture_output=True, text=True)
        for regex in pattern_list:
            pattern = re.compile(regex)
            matches = re.findall(pattern, output.stdout)
            if matches:
                match_tuple = (f, regex, matches)
                total_matches.append(match_tuple)
    return total_matches

# This simply checks matches and sends the appropriate exit code

def pass_or_fail(matches):
    secrets_found = True
    if len(matches) != 0:
        return secrets_found
    else:
        secrets_found = None
        return secrets_found

# The driver code

def main():
    line = sys.stdin.read()
    current_args = get_arguments(line)
    current_changes = get_changed_files(current_args)
    current_show_string = create_show_string(current_changes, current_args)
    current_contents_matches = check_contents_of_changed_files(current_show_string)
    if len(current_contents_matches) != 0:
        print("Secrets!!! Detected!")
        for creds in current_contents_matches:
            offending_file = creds[0]
            detected_cred = creds[2]
            print(str(offending_file) + ":" + str(detected_cred))
        sys.exit(1)
    else:
        print("No Secrets Detected")
        sys.exit(0)


main()
