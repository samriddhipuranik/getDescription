from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

def fetch_cve_details(cve_id):
    cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    response = requests.get(cve_url)
    if response.status_code != 200:
        print(f"Failed to fetch CVE details for {cve_id}, status code: {response.status_code}")
        return None, None

    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract CVE description
    description_tag = soup.find('p', {'data-testid': 'vuln-description'})
    cve_description = description_tag.text.strip() if description_tag else "Description not found"
    print(f"CVE Description: {cve_description}")

    # Extract CWE ID link
    cwe_link = soup.find('a', href=re.compile(r'http://cwe.mitre.org/data/definitions/\d+\.html'))
    cwe_url = cwe_link['href'] if cwe_link else None
    print(f"CWE URL: {cwe_url}")

    return cve_description, cwe_url

def fetch_cwe_description(cwe_url):
    response = requests.get(cwe_url)
    if response.status_code != 200:
        print(f"Failed to fetch CWE details from {cwe_url}, status code: {response.status_code}")
        return "CWE description not found"

    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract CWE description
    description_tag = soup.find('div', {'id': 'Description'})
    cwe_description = description_tag.text.strip() if description_tag else "CWE description not found"
    print(f"CWE Description: {cwe_description}")

    return cwe_description

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_cve_info', methods=['POST'])
def get_cve_info():
    cve_id = request.form['cve_id']
    print(f"Received CVE ID: {cve_id}")
    cve_description, cwe_url = fetch_cve_details(cve_id)
    if cwe_url:
        cwe_description = fetch_cwe_description(cwe_url)
    else:
        cwe_description = "CWE ID not found"

    print(f"CVE Description: {cve_description}")
    print(f"CWE Description: {cwe_description}")

    return jsonify({
        'cve_description': cve_description,
        'cwe_description': cwe_description
    })

if __name__ == '__main__':
    app.run(debug=True)
