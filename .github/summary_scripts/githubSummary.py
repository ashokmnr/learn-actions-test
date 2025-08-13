#!/usr/bin/env python3

import json
import argparse
import sys

parser = argparse.ArgumentParser(description="A script that generate gitleaks summary.")
parser.add_argument("-exit_code", type=int, help="Exit code of gitleaks run.", required=True)
parser.add_argument("-repo_url", type=str, help="GitHub Project URL.", required=True)

args = parser.parse_args()

def results_to_markdown(output_md_path, content):
    try:
        with open(output_md_path, 'w', encoding='utf-8') as md_file:
            md_file.write("\n".join(content))
    except IOError:
        print(f"Error: Could not write to the file '{output_md_path}'.")

def extract_sarif_results_to_markdown(sarif_file_path,url):
    try:
        with open(sarif_file_path, 'r') as f:
            sarif_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: The file '{sarif_file_path}' was not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from the file '{sarif_file_path}'.")
        return

    # The results are located within the first 'run' object.
    results = sarif_data.get('runs', [{}])[0].get('results', [])

    if not results:
        print("No results found in the SARIF file.")
        return

    # Prepare data for Markdown writing
    md_content = []
    md_content.append("🛑 Gitleaks detected secrets 🛑\n")
    
    # Create Markdown table headers
    md_headers = "| Rule ID | Commit | Secret URL | Start Line | Author | Date | Email | File |"
    md_separator = "|---|---|---|---|---|---|---|---|"
    md_content.append(md_headers)
    md_content.append(md_separator)

    print("--- Extracting SARIF Results for Markdown ---")
    print(url)
    for result in results:
        rule_id = result.get('ruleId', 'N/A')
        fingerprints = result.get('partialFingerprints', {})
        commitSha = fingerprints.get('commitSha', 'N/A')
        author = fingerprints.get('author', 'N/A')
        email = fingerprints.get('email', 'N/A')
        date = fingerprints.get('date', 'N/A')

        # Location information is nested
        location = result.get('locations', [{}])[0].get('physicalLocation', {})
        file_path = location.get('artifactLocation', {}).get('uri', 'N/A')
        start_line = location.get('region', {}).get('startLine', 'N/A')
        commitURL = "[{0}]({1}/commit/{2})".format(commitSha[0:7], url, commitSha)
        #commitSha[0:7])
        secretURL = "[{0}]({1}/blob/{2}/{3}#L{4})".format("View Secret", url, commitSha, file_path, start_line)
        fileURL = "[{0}]({1}/blob/{2}/{3})".format(file_path,url,commitSha,file_path)
      
        # Add a row to the Markdown table
        md_row = f"| {rule_id} | {commitURL} | {secretURL} | {start_line} | {author} | {date} | {email} | {fileURL} |"
        md_content.append(md_row)

    # Write the extracted data to a Markdown file
    results_to_markdown('extracted_results.md', md_content)

if __name__ == '__main__':
    if args.exit_code == 2:
        print("🛑 Gitleaks detected secrets 🛑")
        extract_sarif_results_to_markdown('results.sarif',args.repo_url)
        sys.exit(args.exit_code)
    elif args.exit_code == 0:
        print("No leaks detected ✅")
        md_content = ["### No leaks detected ✅"]
        results_to_markdown('extracted_results.md', md_content)
        sys.exit(args.exit_code)
    elif args.exit_code == 1:
        print("❌ Gitleaks exited with error. Exit code {0}".format(args.exit_code))
        md_content = ["### ❌ Gitleaks exited with error. Exit code {0}".format(args.exit_code)]
        results_to_markdown('extracted_results.md', md_content)
        sys.exit(args.exit_code)
    else:
        print("❌ Gitleaks exited with unexpected exit code {0}".format(args.exit_code))
        md_content = ["### ❌ Gitleaks exited with unexpected exit code {0}".format(args.exit_code)]
        results_to_markdown('extracted_results.md', md_content)
        sys.exit(args.exit_code)