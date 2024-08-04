from datetime import datetime, timedelta
import os
from langchain_community.llms import Ollama
import requests
from stix2 import MemoryStore
from elasticsearch import Elasticsearch
from collections import Counter

from pymisp import PyMISP

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

def get_day_suffix(day):
    if 4 <= day <= 20 or 24 <= day <= 30:
        return "th"
    else:
        return ["st", "nd", "rd"][day % 10 - 1]


def format_cve(cve_response, mode="normal", keyword=""):
    """
    Takes a dictionary representing the API response and formats each CVE entry into a structured prompt for LLM.
    
    Parameters:
    - cve_response: A dictionary representing the API response containing CVE information.
    
    Returns:
    - A list of strings, each a formatted prompt for LLM based on the CVE entries in the response.
    """

    # Get the current date and time
    now = datetime.now()
    day = now.day

    formatted_prompts = f"CVE Search Results for {keyword}:\n\n \n " if mode == "normal" else f"""Latest CVEs for {now.strftime(f"%A, %B {day}{get_day_suffix(day)} %Y")} related to {keyword} :\n\n"""
    
    if len(cve_response['vulnerabilities']) == 0:

        formatted_prompts = "No CVEs found matching the search criteria."
        return formatted_prompts
    
    
    for vulnerability in cve_response['vulnerabilities']:
        cve = vulnerability.get('cve', {})
        prompt = f"- CVE ID: {cve.get('id', 'N/A')}\n"
        prompt += f"- Status: {cve.get('vulnStatus', 'Unknown')}\n"
        
        if mode == "normal":
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
        
        if mode == "normal":
            references = cve.get('references', [])
            ref_urls = ', '.join([ref.get('url', 'No URL') for ref in references])
            prompt += f"- References: {ref_urls if references else 'No references available.'}\n"
            
        
        formatted_prompts += prompt+"\n\n"
    
    return formatted_prompts

def llm_invoke(input):
    """
    Invokes the LLM with the given input text.
    
    Parameters:
    - input: The input text to be processed by the LLM.
    
    Returns:
    - The response generated by the LLM.
    """
    # Invoke the LLM with the input text
    llm = Ollama(model="openhermes", base_url=os.getenv("OLLAMA_HOST"), temperature=0.3, num_predict=1024, num_ctx=8192)
    response = llm.invoke(input)
    return str(response)


def get_mitre_data_from_branch(domain, branch="master"):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    BASE_URL = f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json"
    stix_json = requests.get(BASE_URL).json()
    return MemoryStore(stix_data=stix_json["objects"])

def format_virustotal_results(results):
    """
    This function takes the raw results from a VirusTotal scan and returns a human-readable string.

    Parameters:
    results (dict): The raw results from a VirusTotal scan.

    Returns:
    str: A formatted string summarizing the scan results.
    """
    md5 = results.get('md5', 'N/A')
    sha1 = results.get('sha1', 'N/A')
    sha256 = results.get('sha256', 'N/A')
    scan_date = results.get('scan_date', 'N/A')
    positives = results.get('positives', 'N/A')
    total = results.get('total', 'N/A')
    permalink = results.get('permalink', 'N/A')

    formatted_results = [
        f"VirusTotal Scan Results:",
        f"========================",
        f"MD5: {md5}",
        f"SHA-1: {sha1}",
        f"SHA-256: {sha256}",
        f"Scan Date: {scan_date}",
        f"Detections: {positives}/{total}",
        f"Detailed Report: {permalink}",
        "",
        "Detailed Scan Results:",
        "======================"
    ]

    scans = results.get('scans', {})
    for scanner, scan_data in scans.items():
        detected = scan_data.get('detected', False)
        result = scan_data.get('result', 'N/A')
        version = scan_data.get('version', 'N/A')
        update = scan_data.get('update', 'N/A')

        formatted_results.append(
            f"Scanner: {scanner}\n"
            f"  Detected: {'Yes' if detected else 'No'}\n"
            f"  Result: {result}\n"
            f"  Version: {version}\n"
            f"  Last Update: {update}\n"
        )

    return "\n".join(formatted_results)

def elastic_client():
    """
    This function creates an Elasticsearch client and returns it.

    Returns:
    Elasticsearch: An Elasticsearch client.
    """

    return Elasticsearch(
            os.getenv('ES_URL'),
            basic_auth=("elastic",os.getenv("ES_PASSWORD"))
        )

def summarize_alerts(alerts):
    summary = {
        "total_alerts": len(alerts),
        "signatures": set(),
        "top_src_ips": [],
        "top_dst_ips": [],
        "severity_count": Counter(),
        "categories": set()
    }
    
    src_ip_counter = Counter()
    dst_ip_counter = Counter()
    
    for alert in alerts:
        # Count signatures
        signature = alert['_source']['alert']['signature']
        summary["signatures"].add(signature)
        
        # Count src_ip and dst_ip
        src_ip = alert['_source'].get('src_ip')
        if src_ip:
            src_ip_counter[src_ip] += 1
        
        dst_ip = alert['_source'].get('dest_ip')
        if dst_ip:
            dst_ip_counter[dst_ip] += 1
        
        # Count severity
        severity = alert['_source']['alert']['severity']
        summary["severity_count"][severity] += 1
        
        # Collect categories
        category = alert['_source']['alert']['category']
        summary["categories"].add(category)
    
    # Get top 5 src_ip and dst_ip
    summary["top_src_ips"] = src_ip_counter.most_common(3)
    summary["top_dst_ips"] = dst_ip_counter.most_common(3)
    
    return str(summary)

def misp_client():
    """
    This function creates a PyMISP client and returns it.

    Returns:
    PyMISP: A PyMISP client.
    """
    return PyMISP(url=os.getenv('MISP_URL'), key=os.getenv('MISP_KEY'), ssl=False)

def get_mitre_store():
    return {
        "enterprise": get_mitre_data_from_branch("enterprise-attack"),
        "mobile": get_mitre_data_from_branch("mobile-attack"),
        "ics": get_mitre_data_from_branch("ics-attack")
            }