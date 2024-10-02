from langchain.tools import tool
import os, requests
from .utils import format_virustotal_results


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

            # Determine if the resource is a hash, URL, or IP based on scan_type
            if scan_type == 'url' or (resource.startswith('http://') or resource.startswith('https://')):
                # It's a URL
                params = {'apikey': api_key, 'url': resource}
                scan_url = base_url + 'url/scan'
                report_url = base_url + 'url/report'
                response = requests.post(scan_url, data=params)  # Submit the URL for scanning
                response.raise_for_status()  # Raise an error for bad status codes

            elif scan_type == 'ip':
                # It's an IP address
                params = {'apikey': api_key, 'ip': resource}
                scan_url = base_url + 'ip-address/report'
                report_url = base_url + 'ip-address/report'
                
            else:
                # Assume it's a hash
                params = {'apikey': api_key, 'resource': resource}
                scan_url = base_url + 'file/report'
                report_url = base_url + 'file/report'
            
            # Now, retrieve the scan report
            response = requests.get(report_url, params=params)
            response.raise_for_status()  # Raise an error for bad status codes
            return str(response.json())