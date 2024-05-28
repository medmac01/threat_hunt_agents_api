import requests
from langchain.tools import tool
from langchain_community.llms import Ollama
import json

import sys
import os

from dotenv import load_dotenv

from datetime import datetime, timedelta
load_dotenv(override=True)

llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192)

def get_current_formatted_date():
    # Get the current date and time
    now = datetime.now()

    # Format the date and time in the desired format
    formatted_date = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    return formatted_date

def get_yesterday_formatted_date():
    # Get the current date and time
    now = datetime.now()
    # Calculate yesterday's date and time
    yesterday = now - timedelta(days=2)
    # Format the date and time in the desired format
    formatted_date = yesterday.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    return formatted_date

def format_cve(cve_response):
    """
    Takes a dictionary representing the API response and formats each CVE entry into a structured prompt for LLM.
    
    Parameters:
    - cve_response: A dictionary representing the API response containing CVE information.
    
    Returns:
    - A list of strings, each a formatted prompt for LLM based on the CVE entries in the response.
    """
    formatted_prompts = "CVE Search Results:\n\n"
    
    if len(cve_response['vulnerabilities']) == 0:

        formatted_prompts = "No CVEs found matching the search criteria."
        return formatted_prompts
    
    
    for vulnerability in cve_response['vulnerabilities']:
        cve = vulnerability.get('cve', {})
        # prompt = f"Explain {cve.get('id', 'N/A')} in simple terms:\n\n"
        prompt = f"- CVE ID: {cve.get('id', 'N/A')}\n"
        prompt += f"- Status: {cve.get('vulnStatus', 'Unknown')}\n"
        
        descriptions = cve.get('descriptions', [])
        description_text = descriptions[0].get('value', 'No description available.') if descriptions else "No description available."
        prompt += f"- Description: {description_text}\n"
        
        if 'metrics' in cve and 'cvssMetricV2' in cve['metrics']:
            cvss_metrics = cve['metrics']['cvssMetricV2'][0]
            prompt += f"- CVSS Score: {cvss_metrics.get('cvssData', {}).get('baseScore', 'Not available')} ({cvss_metrics.get('baseSeverity', 'Unknown')})\n"
        else:
            prompt += "- CVSS Score: Not available\n"
        
        configurations = cve.get('configurations', {})
        for conf in configurations:
            nodes = conf.get('nodes', [])
            affected_configs = []
            for node in nodes:
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', False):
                        affected_configs.append(cpe_match.get('criteria', 'Not specified'))
            prompt += f"- Affected Configurations: {', '.join(affected_configs) if affected_configs else 'Not specified'}\n"
        
        references = cve.get('references', [])
        ref_urls = ', '.join([ref.get('url', 'No URL') for ref in references])
        prompt += f"- References: {ref_urls if references else 'No references available.'}\n"
        
        
        formatted_prompts += prompt+"\n\n"
        print(formatted_prompts)

    # formatted_prompts += "\nSummarize the vulnerability, its impact, and any known mitigation strategies."
    
    return formatted_prompts

class CVESearchTool():
  @tool("CVE search Tool")
  def cvesearch(keyword: str, date: str = None):
    """
    Searches for CVEs based on a keyword or phrase and returns the results in JSON format.
    Use this when a user asks you about a certain CVE or a CVE related to a certain keyword. 
    And not necesserly the latest CVEs.
    Parameters:
    - keyword (str): A word or phrase to search for in the CVE descriptions.
    - date (str): An optional date to include in the search query.
    
    Returns:
    - JSON: A list of CVEs matching the keyword search.
    """

    if date:
        keyword = f"{keyword} {date}"
    # Encode the spaces in the keyword(s) as "%20" for the URL
    keyword_encoded = keyword.replace(" ", "%20")
    # keyword_encoded = keyword_encoded.join(" 2023")
    
    # Construct the URL for the API request
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword_encoded}&resultsPerPage=3"
    
    try:
        # Send the request to the NVD API
        response = requests.get(url)
        # Check if the request was successful
        if response.status_code == 200:
            # Return the JSON response
            return format_cve(response.json())
        else:
            return {"error": "Failed to fetch data from the NVD API.", "status_code": response.status_code}
    except Exception as e:
        return {"error": str(e)}

  @tool("Get latest CVEs, today's CVEs Tool")
  def get_latest_cves(keyword: str):
        """
        Fetches today's latest CVEs based on a keyword or phrase and returns the results in JSON format.
        Use this exclusively to get the latest CVEs, or for todays CVEs. When the user asks you about the latest CVEs out there.
        Parameters:
        - keyword (str): A word or phrase to search for in the CVE descriptions.
        Returns:
        - A list of CVEs matching the keyword search.
        """
        # Encode the spaces in the keyword(s) as "%20" for the URL
        keyword_encoded = keyword.replace(" ", "%20")
        # keyword_encoded = keyword_encoded.join(" 2023")
        
        # Construct the URL for the API request
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={get_yesterday_formatted_date()}&pubEndDate={get_current_formatted_date()}&keywordSearch={keyword_encoded}&cvssV3Severity=HIGH&resultsPerPage=3" if keyword != "" else f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={get_yesterday_formatted_date()}&pubEndDate={get_current_formatted_date()}&cvssV3Severity=HIGH&resultsPerPage=3"
        print(url)
        try:
            # Send the request to the NVD API
            response = requests.get(url)
            # Check if the request was successful
            if response.status_code == 200:
                # Return the JSON response
                formatted = format_cve(response.json())
                return llm.invoke("Summarize the following CVEs:\n\n"+formatted)
            else:
                return {"error": "Failed to fetch data from the NVD API.", "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}