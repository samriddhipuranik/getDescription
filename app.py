from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_cve_info', methods=['POST'])
def get_cve_info():
    try:
        cve_id = request.form['cve_id']
        if not cve_id.startswith('CVE-'):
            return jsonify({"error": "Invalid CVE format"}), 400
        
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        response = requests.get(cve_url)
        
        if response.status_code != 200:
            return jsonify({"error": "Invalid CVE ID"}), 400

        soup = BeautifulSoup(response.text, 'html.parser')
        cve_description_tag = soup.find("p", {"data-testid": "vuln-description"})
        
        if not cve_description_tag:
            return jsonify({"error": "CVE description not found"}), 404
        
        cve_description = cve_description_tag.text.strip()
        cwe_tag = soup.find("td", {"data-testid": "vuln-CWEs-link-0"}).find("a")
        
        if not cwe_tag:
            return jsonify({"error": "CWE information not found"}), 404
        
        cwe_url = cwe_tag['href']
        cwe_id = cwe_tag.text.strip()
        cwe_response = requests.get(cwe_url)
        cwe_soup = BeautifulSoup(cwe_response.text, 'html.parser')
        cwe_description_tag = cwe_soup.find("div", {"id": "Description"})
        
        if not cwe_description_tag:
            return jsonify({"error": "CWE description not found"}), 404
        
        cwe_description = cwe_description_tag.text.strip()
        
        return jsonify({
            "cve_description": cve_description,
            "cwe_description": cwe_description
        })
    
    except Exception as e:
        app.logger.error(f"Exception occurred: {e}")
        return jsonify({"error": "An error occurred"}), 500

if __name__ == "__main__":
    app.run(debug=True)
