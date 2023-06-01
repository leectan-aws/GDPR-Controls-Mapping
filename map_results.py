import argparse
import json
import os.path
import sys
import csv
import traceback
from time import time
from prowler_scf_gdpr_map import prowler_v3_checks_map


def parse_args():
    parser = argparse.ArgumentParser(description='Map your Prowler check results to GDPR controls')
    parser.add_argument('-f', '--file', help='Full path to the file containing Prowler results',
                        action='store', dest='file_path', required=True)
    parser.add_argument('-t', '--format', help='Format type of the file containing Prowler results',
                        action='store', dest='file_format', default='csv', choices=['csv', 'json'],
                        required=False)
    parser_args = parser.parse_args()
    return parser_args


def load_prowler_csv_results(file_obj) -> dict:
    csv_results = dict()
    delimiter = ';'
    try:
        reader = csv.DictReader(file_obj, delimiter=delimiter)
        for row in reader:
            # Skip informational checks since these don't actually check anything in the account(s)
            if row['STATUS'] == 'INFO':
                continue
            if row['CHECK_ID'] not in csv_results:
                csv_results[row['CHECK_ID']] = {
                    "accounts_passing": [],
                    "total_accounts_passing": 0,
                    "resources_passing": 0,
                    "accounts_failing": [],
                    "total_accounts_failing": 0,
                    "resources_failing": 0,
                    "check_description": row['CHECK_TITLE'],
                    "impact": row['SEVERITY'],
                    "aws_service": row['SERVICE_NAME']
                }
            if row['STATUS'] == 'PASS':
                if row['ACCOUNT_ID'] not in csv_results[row['CHECK_ID']]["accounts_passing"]:
                    csv_results[row['CHECK_ID']]["accounts_passing"].append(row['ACCOUNT_ID'])
                    csv_results[row['CHECK_ID']]['total_accounts_passing'] += 1
                csv_results[row['CHECK_ID']]['resources_passing'] += 1
            elif row['STATUS'] == 'FAIL':
                if row['ACCOUNT_ID'] not in csv_results[row['CHECK_ID']]["accounts_failing"]:
                    csv_results[row['CHECK_ID']]["accounts_failing"].append(row['ACCOUNT_ID'])
                    csv_results[row['CHECK_ID']]['total_accounts_failing'] += 1
                csv_results[row['CHECK_ID']]['resources_failing'] += 1

    except Exception:
        print(f"Encountered an error while trying to read the CSV file:\n{traceback.format_exc()}")
        sys.exit(1)

    return map_output_to_controls(csv_results)


def load_prowler_json_results(file_obj) -> dict:
    json_results = dict()
    try:
        json_file = json.load(file_obj)
        for entry in json_file:
            # Skip informational checks since these don't actually check anything in the account(s)
            if entry['Status'] == 'INFO':
                continue
            if entry['CheckID'] not in json_results:
                json_results[entry['CheckID']] = {
                    "accounts_passing": [],
                    "total_accounts_passing": 0,
                    "resources_passing": 0,
                    "accounts_failing": [],
                    "total_accounts_failing": 0,
                    "resources_failing": 0,
                    "check_description": entry['CheckTitle'],
                    "impact": entry['Severity'],
                    "aws_service": entry['ServiceName']
                }
            if entry['Status'] == 'PASS':
                if entry['AccountId'] not in json_results[entry['CheckID']]["accounts_passing"]:
                    json_results[entry['CheckID']]["accounts_passing"].append(entry['AccountId'])
                    json_results[entry['CheckID']]['total_accounts_passing'] += 1
                json_results[entry['CheckID']]['resources_passing'] += 1
            elif entry['Status'] == 'FAIL':
                if entry['AccountId'] not in json_results[entry['CheckID']]["accounts_failing"]:
                    json_results[entry['CheckID']]["accounts_failing"].append(entry['AccountId'])
                    json_results[entry['CheckID']]['total_accounts_failing'] += 1
                json_results[entry['CheckID']]['resources_failing'] += 1
    except Exception:
        print(f"Encountered an error while trying to read the JSON file:\n{traceback.format_exc()}")
        sys.exit(1)
    return json_results


def map_output_to_controls(output):
    for key in output.keys():
        output[key]['scf_controls'] = prowler_v3_checks_map[key]['scf_controls']
        output[key]['gdpr_articles'] = prowler_v3_checks_map[key]['gdpr_articles']
    return output


def generate_output_files(output):
    timestamp = int(time())
    output_folder = 'output'
    filename = f"{output_folder}/prowler-to-aws-scf-gdpr-{timestamp}"

    # Create output folder if it doesn't exist
    try:
        os.makedirs(output_folder, exist_ok=True)
    except Exception:
        print(f"Encountered an error while trying to create output folder:\n{traceback.format_exc()}")
        sys.exit(1)

    # Write JSON output file
    try:
        with open(f"{filename}.json", 'w') as f:
            json.dump(output, f, ensure_ascii=False, indent=3)
    except Exception:
        print(f"Encountered an error while trying to save the JSON output file:\n{traceback.format_exc()}")
        sys.exit(1)

    # Write CSV output file
    try:
        with open(f"{filename}.csv", 'w') as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['Check Name', 'Check Description', 'AWS Service', 'Impact', "Accounts Passing",
                                 "Total Accounts Passing", "Resources Passing", "Accounts Failing",
                                 "Total Accounts Failing", "Resources Failing", 'SCF Controls', 'GDPR Articles'])
            for key in output.keys():
                scf_controls = '; '.join(output[key]['scf_controls']) if len(output[key]['scf_controls']) > 0 else ''
                gdpr_articles = '; '.join(output[key]['gdpr_articles']) if len(output[key]['gdpr_articles']) > 0 else ''
                accounts_passing = '; '.join(output[key]['accounts_passing']) if len(output[key]['accounts_passing']) > 0 else ''
                accounts_failing = '; '.join(output[key]['accounts_failing']) if len(output[key]['accounts_failing']) > 0 else ''
                csv_writer.writerow([key, output[key]['check_description'], output[key]['aws_service'],
                                     output[key]['impact'], accounts_passing, output[key]['total_accounts_passing'],
                                     output[key]['resources_passing'], accounts_failing, output[key]['total_accounts_failing'],
                                     output[key]['resources_failing'], scf_controls, gdpr_articles])
    except Exception:
        print(f"Encountered an error while trying to save the CSV output file:\n{traceback.format_exc()}")
        sys.exit(1)


def main():
    args = parse_args()
    try:
        f = open(args.file_path, newline='', mode='r')
    except FileNotFoundError:
        print(f"File {args.prowler_results_file} was not found. Please specify a valid file path.")
        sys.exit(1)
    except OSError:
        print(f"An OS error occurred while trying to open {args.file_path}. Please check the specified file.")
        sys.exit(1)
    except Exception as err:
        print(f"An unexpected error occurred while opening {args.file_path}.\n{repr(err)}")
        sys.exit(1)

    with f:
        if args.file_format == 'csv':
            prowler_results = load_prowler_csv_results(file_obj=f)
        elif args.file_format == 'json':
            prowler_results = load_prowler_json_results(file_obj=f)
    generate_output_files(prowler_results)


if __name__ == "__main__":
    main()
