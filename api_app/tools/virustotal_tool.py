from langchain.tools import tool
from langchain_community.llms import Ollama
import os
from dotenv import load_dotenv
import requests

load_dotenv(override=True)

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


class VirusTotalTool:
    @tool("VirusTotal scanner", return_direct=True)
    def scanner(resource: str, scan_type: str = 'hash'):
        """Useful tool to scan a hash or URL using VirusTotal
        Parameters:
        - hash: The hash to scan
        - url: The URL to scan
        - scan_type: The type of resource to scan (hash, ip or url)
        Returns:
        - The scan results
        """
        base_url = 'https://www.virustotal.com/vtapi/v2/'
        api_key = os.getenv('VIRUSTOTAL_API_KEY')

        # Determine if the resource is a hash or a URL
        if resource.startswith('http://') or resource.startswith('https://'):
            # It's a URL
            params = {'apikey': api_key, 'url': resource}
            scan_url = base_url + 'url/scan'
            report_url = base_url + 'url/report'

        if scan_type == 'ip':
            # It's an IP address
            params = {'apikey': api_key, 'ip': resource}
            scan_url = base_url + 'ip-address/report'
            report_url = base_url + 'ip-address/report'
            
        else:
            # Assume it's a hash
            params = {'apikey': api_key, 'resource': resource}
            scan_url = base_url + 'file/report'
            report_url = base_url + 'file/report'
        
        # First, submit the resource for scanning (if it's a URL)
        if 'url' in scan_url:
            response = requests.post(scan_url, data=params)
            response.raise_for_status()  # Raise an error for bad status codes

        # Now, retrieve the scan report
        response = requests.get(report_url, params=params)
        response.raise_for_status()  # Raise an error for bad status codes
        return str(response.json())
