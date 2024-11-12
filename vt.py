#!/usr/bin/python3
from dotenv import load_dotenv
from argparse import ArgumentParser
from pathlib import Path
import json
import os
import requests
import logging
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def convert_from_windows_path(path):
    '''
    Convert Windows path to unix-style path
    '''
    return path.replace('\\', '/')


def create_session(api_key):
    headers = {
        "User-Agent": "VT3 Tool",
        "accept": "application/json",
        "x-apikey": api_key
    }
    session = requests.Session()
    session.headers.update(headers)
    return session


def upload_file(session, base_url, file):
    '''
    Uploads a files to virustotal API for analysis
    '''
    try:
        file_size = os.path.getsize(file)
    except OSError:
        logging.error("Couldn't get file size.")
        return None

    try:
        file_contents = open(file, "rb")
    except FileNotFoundError:
        logging.error(f"File not found: {file}")
        return None

    files = {"file": (f"{file.name}", file_contents)}

    if file_size <= 33554432:
        url = base_url + "/files"
    elif file_size >= 33554432 and file_size <= 681574400:
        req_url = base_url + "/files/upload_url"
        resp = session.get(req_url)
        json_data = json.loads(resp.text)
        url = json_data['data']
    else:
        logging.error(f"File is too large for Virustotal API {str(file_size)}")
        return None

    resp = session.post(url, files=files)
    if resp.status_code == 200:
        logging.info("File uploaded successfully!")
        json_data = json.loads(resp.text)
        analysis_id = json_data['data']['id']
    else:
        logging.error(f"There was an error uploading the file: {resp.status_code} {resp.text}")
        return None
    return analysis_id


def get_file_analysis_report(session, base_url, analysis_id):
    '''
    Get the analysis report related to an upload file
    to determine if it's malicious
    '''
    url = base_url + "/analyses/" + analysis_id
    resp = session.get(url)
    if resp.status_code == 200:
        json_data = json.loads(resp.text)
        status = json_data['data']['attributes']['status']
        while status != "completed":
            logging.info(f"File is still being analyzed waiting 5 minutes...")
            time.sleep(300)
            resp = session.get(url)
            json_data = json.loads(resp.text)
            status = json_data['data']['attributes']['status']
            if status == "completed":
                break
        malicious_count = json_data['data']['attributes']['stats']['malicious']
        suspicious_count = json_data['data']['attributes']['stats']['suspicious']
        undetected_count = json_data['data']['attributes']['stats']['undetected']
        harmless_count = json_data['data']['attributes']['stats']['harmless']
        failure_count = json_data['data']['attributes']['stats']['failure']
        if malicious_count > 5:
            logging.warning(f"File is malicious! malicious_count: {malicious_count}")
        elif suspicious_count > 5:
            logging.warning(f"File is suspicious! suspicious_count: {suspicious_count}")
        else:
            logging.info("The File is likely clean...")
            logging.info(f"Results: malicious_count: {malicious_count}, undetected_count: {undetected_count}, harmless_count: {harmless_count}, failure_count: {failure_count}")
    else:
        logging.error(f"There was an error getting the analysis report: {resp.status_code} {resp.text}")


def scan_url(session, base_url, url):
    '''
    Scans a URL for malicious content
    '''
    scan_url = base_url + "/urls"
    params = {"url": url}
    resp = session.post(scan_url, data=params)
    if resp.status_code == 200:
        json_data = json.loads(resp.text)
        analysis_id = json_data['data']['id']
    elif resp.status_code == 400:
        logging.error(f"There was an error scanning URL: {url} {resp.status_code} {resp.text}")
        return None
    return analysis_id


def get_url_analysis_report(session, base_url, analysis_id):
    '''
    Get the report of a URL scan
    '''
    report_url = base_url + "/analyses/" + analysis_id
    resp = session.get(report_url)
    if resp.status_code == 200:
        json_data = json.loads(resp.text)
        status = json_data['data']['attributes']['status']
        while status != "completed":
            logging.info(f"URL is still being analyzed waiting 5 minutes...")
            time.sleep(300)
            resp = session.get(report_url)
            json_data = json.loads(resp.text)
            status = json_data['data']['attributes']['status']
            if status == "completed":
                break
        malicious_count = json_data['data']['attributes']['stats']['malicious']
        suspicious_count = json_data['data']['attributes']['stats']['suspicious']
        undetected_count = json_data['data']['attributes']['stats']['undetected']
        harmless_count = json_data['data']['attributes']['stats']['harmless']
        timeout_count = json_data['data']['attributes']['stats']['timeout']
        if malicious_count > 5:
            logging.warning(f"URL is malicious! malicious_count: {malicious_count}")
        elif suspicious_count > 5:
            logging.warning(f"URL is suspicious! suspicious_count: {suspicious_count}")
        else:
            logging.info("The URL is likely clean...")
            logging.info(f"Results: malicious_count: {malicious_count}, undetected_count: {undetected_count}, harmless_count: {harmless_count}, timeout_count: {timeout_count}")
    else:
        logging.error(f"There was an error getting the analysis report: {resp.status_code} {resp.text}")


def main():
    load_dotenv()
    api_key = os.getenv('VT_API_KEY')
    arg_parser = ArgumentParser()
    arg_parser.add_argument(
        '-f',
        '--file',
        required=False,
        help='Path to the file')
    arg_parser.add_argument(
        '-u',
        '--url',
        required=False,
        type=str,
        help='URL to scan')
    args = arg_parser.parse_args()
    api_base_url = "https://www.virustotal.com/api/v3"
    session = create_session(api_key)
    if args.url:
        analysis_id = scan_url(session, api_base_url, args.url)
        if analysis_id:
            get_url_analysis_report(session, api_base_url, analysis_id)
    elif args.file:
        file = r"{}".format(args.file)
        if "\\" in file:
            converted_file = convert_from_windows_path(file)
            clean_file = Path(converted_file)
        analysis_id = upload_file(session, api_base_url, clean_file)
        if analysis_id:
            get_file_analysis_report(session, api_base_url, analysis_id)


if __name__ == "__main__":
    main()
