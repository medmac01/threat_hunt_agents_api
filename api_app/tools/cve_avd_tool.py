import requests
from langchain.tools import tool

from .utils import format_cve, get_current_formatted_date, get_yesterday_formatted_date, get_day_suffix, llm_invoke

class CVESearchTool():
  @tool("CVE search Tool", return_direct=True)
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
    
    # Construct the URL for the API request
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword_encoded}&resultsPerPage=3"
    
    try:
        # Send the request to the NVD API
        response = requests.get(url)
        # Check if the request was successful
        if response.status_code == 200:
            # Return the JSON response
            formatted = format_cve(response.json(), mode="normal", keyword=keyword)
            return formatted
        else:
            return {"error": "Failed to fetch data from the NVD API.", "status_code": response.status_code}
    except Exception as e:
        return {"error": str(e)}

  @tool("Get latest CVEs, today's CVEs Tool", return_direct=True)
  def get_latest_cves(keyword: str = ""):
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
        
        # Construct the URL for the API request
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={get_yesterday_formatted_date()}&pubEndDate={get_current_formatted_date()}&keywordSearch={keyword_encoded}&cvssV3Severity=HIGH&resultsPerPage=3" if keyword != "" else f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={get_yesterday_formatted_date()}&pubEndDate={get_current_formatted_date()}&cvssV3Severity=HIGH&resultsPerPage=3"
        print("DEBUG: ", url)
        try:
            # Send the request to the NVD API
            response = requests.get(url)
            # Check if the request was successful
            if response.status_code == 200:
                # Return the JSON response
                formatted = format_cve(response.json(), mode="latest", keyword=keyword)
                return llm_invoke("Summarize the following CVEs in bullet points while keeping technical details:\n\n"+formatted)
            else:
                return {"error": "Failed to fetch data from the NVD API.", "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}
