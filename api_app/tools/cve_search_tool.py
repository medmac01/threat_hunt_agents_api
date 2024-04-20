import requests
from bs4 import BeautifulSoup
from langchain.tools import tool
import json

class CVESearchTool():
  @tool("CVE search Tool")
  def cvesearch(keyword: str):
    "CVE (Common Vulnerabilities and Exposures) search tool is a useful tool to search for known security vulnerabilities and exposures in various software products, systems, and devices. It helps users to identify specific vulnerabilities by searching through the CVE database, which contains detailed information about vulnerabilities."
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}"
    
    # Fetch the HTML content
    response = requests.get(url)
    if response.status_code == 200:
        html_content = response.content

        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find CVE records
        cves = soup.find_all('td', {'valign': 'top', 'nowrap': 'nowrap'})

        # Create a dictionary to store CVEs and descriptions
        cve_dict = {}

        # Iterate through CVE records
        for cve in cves:
            cve_id = cve.text.strip()  # Extract CVE ID
            description = cve.find_next('td').text.strip()  # Extract Description
            cve_dict[cve_id] = description

        # Convert dictionary to JSON string
        json_string = json.dumps(cve_dict, indent=4)
        # return json_string
        return json_string
    else:
        print("Failed to fetch the page:", response.status_code)
        return None
