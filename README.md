# vt
Simple script to scan file or url using virustotal's v3 API

# Requirements
**Only compatible with python3**

Must create a .env file with api key provided by Virustotal
```env
VT_API_KEY = "xxxx"
```
Install python-dotenv by running:
```bash
pipx install python-dotenv #using pipx to not break system dependencies (Linux)
-or-
pip install python-dotenv
```
# Running
provide one of the following arguments
1. -u or --url to scan a url
2. -f or --file to scan a file

Example:
```bash
python3 -u <url> # to scan URL
python3 -f /path/to/file to scan file.
```
