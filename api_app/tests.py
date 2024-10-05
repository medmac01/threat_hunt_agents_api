from django.urls import reverse
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

from unittest import TestCase
from unittest.mock import patch, MagicMock
from requests.exceptions import RequestException

from .tools.elastic import InternalThreatSearch
from .tools.cve import CVESearchTool
from .tools.misp import MISPTool
from .tools.virustotal import VirusTotalTool
from .tools.mitre import MitreTool

from .tools.utils import elastic_client, summarize_alerts, get_current_formatted_date, get_yesterday_formatted_date, get_day_suffix, llm_invoke, misp_client, format_cve, format_virustotal_results, get_mitre_store

from .chat.setup_agents import setup_agents, def_invoke
from .agents.hypotesis import HypothesisAgent
from .agents.investigator import InvestigationAgent
from .agents.router import RouterAgent
from langchain.tools import Tool

import os

class AppEndpointTests(APITestCase):
    """
    Test cases for the API endpoints
    """

    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(username='test', password='password')
        self.token = Token.objects.create(user=self.user)
        self.client = APIClient()

        # Authenticate the client
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    @patch('api_app.views.invoke')
    def test_answer_v2_success(self, mock_invoke):
        """
        Test the answer_v2 endpoint with a POST request
        Mocks the invoke function to return a response

        Asserts that the response is correct, and that the invoke function was called with the correct parameters
        """
        url = reverse('answer_v2')
        data = {
            'query': 'Hello!',
            'new_chat': True
        }

        # Create a mock response for the invoke function
        mock_response = {
            'output': 'Hi, how can I help you today?',
            'title': 'New Chat'
        }

        # Mock the response of the invoke function
        mock_invoke.return_value = mock_response

        # Test POST request with valid data
        response = self.client.post(url, data, format='json')

        # Assert that the mock was called with expected parameters
        mock_invoke.assert_called_once_with(data['query'], new_chat=data['new_chat'])

        # Assertions to verify the response is correct
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('input', response.data)
        self.assertIn('output', response.data)
        self.assertEqual(response.data['input'], data)
        self.assertEqual(response.data['output'], mock_response['output'])

    def test_answer_v2_invalid_method(self):
        """
        Test the answer_v2 endpoint with a GET request
        Asserts that the response is a 405 Method Not Allowed
        """
        url = reverse('answer_v2')

        # Test GET request to a POST-only endpoint
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch('api_app.views.get_available_models')
    def test_get_models_success(self, mock_get):
        """
        Test the get_models endpoint with a GET request
        Mocks the get_models function to return a response
        """
        url = reverse('get_models')

        # Create a mock response for the GET request
        mock_response = {
            'models': ['llama-3', 'openhermes', 'codestral']
        }

        # Mock the response of the GET request
        mock_get.return_value = mock_response

        # Test GET request to retrieve models
        response = self.client.get(url)


        # Assertions to verify the response is correct
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('models', response.data)
        self.assertEqual(response.data['models'], ['llama-3', 'openhermes', 'codestral'])

        # Assert that the mock was called
        mock_get.assert_called_once()

    def test_get_models_invalid_method(self):
        """
        Test the get_models endpoint with a POST request
        Asserts that the response is a 405 Method Not Allowed
        """
        url = reverse('get_models')

        # Test POST request to a GET-only endpoint
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch('api_app.views.clear')
    def test_clear_chat_success(self, mock_clear):
        """
        Test the clear_chat endpoint with a POST request
        Mocks the clear function to return a response
        """
        url = reverse('clear_chat')

        # Mock the response of the clear function
        mock_clear.return_value = True  # Simulating successful chat clear

        # Test POST request to clear chat
        response = self.client.post(url, format='json')

        # Assertions to verify the response is correct
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('operation', response.data)
        self.assertEqual(response.data['operation'], 'clear_chat')
        self.assertEqual(response.data['status'], 'success')  # Check if status reflects success

        # Assert that the mock was called once
        mock_clear.assert_called_once()

    def test_clear_chat_invalid_method(self):
        """
        Test the clear_chat endpoint with a GET request
        Asserts that the response is a 405 Method Not Allowed
        """
        url = reverse('clear_chat')

        # Test GET request to a POST-only endpoint
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class TestInternalThreatSearch(TestCase):
    """
    Test cases for the InternalThreatSearch tool
    """

    @patch('api_app.tools.elastic.elastic_client')
    def test_search_by_ip_found(self, mock_elastic_client):
        """
        Test the search_by_ip method of the InternalThreatSearch tool
        Mocks the elasticsearch client to return a response with alerts
        Asserts that the method returns the correct alerts
        """
        # Mocking the elasticsearch response
        mock_response = {
            'hits': {
                'hits': [
                    {'_source': {'src_ip': '192.168.1.1', 'alert': 'Test Alert 1'}},
                    {'_source': {'src_ip': '192.168.1.1', 'alert': 'Test Alert 2'}}
                ]
            }
        }
        mock_elastic_client().search.return_value = mock_response

        # Call the method
        search_tool = InternalThreatSearch()
        result = search_tool.search_by_ip('192.168.1.1')

        # Assertions
        expected_result = str([{'src_ip': '192.168.1.1', 'alert': 'Test Alert 1'}, {'src_ip': '192.168.1.1', 'alert': 'Test Alert 2'}])
        self.assertEqual(result, expected_result)

    @patch('api_app.tools.elastic.elastic_client')
    def test_search_by_ip_not_found(self, mock_elastic_client):
        """
        Test the search_by_ip method of the InternalThreatSearch tool
        Mocks the elasticsearch client to return no results
        Asserts that the method returns the correct message "No alerts found for the specified IP address"
        """

        # Mocking the elasticsearch response for no results
        mock_response = {
            'hits': {
                'hits': []
            }
        }
        mock_elastic_client().search.return_value = mock_response

        # Call the method
        search_tool = InternalThreatSearch()
        result = search_tool.search_by_ip('10.0.0.1')

        # Assertions
        expected_result = "No alerts found for the specified IP address 10.0.0.1"
        self.assertEqual(result, expected_result)

    @patch('api_app.tools.elastic.elastic_client')
    def test_geolocate_ip_found(self, mock_elastic_client):
        """
        Test the geolocate_ip method of the InternalThreatSearch tool
        Mocks the elasticsearch client to return geolocation data
        Asserts that the method returns the correct geolocation data
        """

        # Mocking the elasticsearch response for geolocation data
        mock_response = {
            'hits': {
                'hits': [
                    {'_source': {'src_ip': '192.168.1.1', 'geoip': 'Location 1'}},
                    {'_source': {'src_ip': '192.168.1.2', 'geoip': 'Location 2'}}
                ]
            }
        }
        mock_elastic_client().search.return_value = mock_response

        # Call the method
        search_tool = InternalThreatSearch()
        result = search_tool.geolocate_ip('192.168.1.1')

        # Assertions
        expected_result = str([{'src_ip': '192.168.1.1', 'geoip': 'Location 1'}, {'src_ip': '192.168.1.2', 'geoip': 'Location 2'}])
        self.assertEqual(result, expected_result)

    @patch('api_app.tools.elastic.elastic_client')
    def test_geolocate_ip_not_found(self, mock_elastic_client):
        """
        Test the geolocate_ip method of the InternalThreatSearch tool
        Mocks the elasticsearch client to return no results
        Asserts that the method returns the correct message "No geolocation found for the specified IP address..."
        """
        # Mocking the elasticsearch response for no results
        mock_response = {
            'hits': {
                'hits': []
            }
        }
        mock_elastic_client().search.return_value = mock_response

        # Call the method
        search_tool = InternalThreatSearch()
        result = search_tool.geolocate_ip('10.0.0.1')

        # Assertions
        expected_result = "No geolocation found for the specified IP address 10.0.0.1, this can be due to the IP is not in the database, or it doesn't have a geolocation associated."
        self.assertEqual(result, expected_result)

    @patch('api_app.tools.elastic.elastic_client')
    @patch('api_app.tools.elastic.get_current_formatted_date')
    @patch('api_app.tools.elastic.summarize_alerts')
    def test_get_summary(self, mock_summarize_alerts, mock_get_current_formatted_date, mock_elastic_client):
        """
        Test the get_summary method of the InternalThreatSearch tool
        Mocks the elasticsearch client to return alerts
        Mocks the summarize_alerts function to return a summary
        Asserts that the method returns the correct summary
        """

        # Mocking the formatted date function
        mock_get_current_formatted_date.return_value = "2024-04-01"

        # Mocking the elasticsearch response for summary
        mock_response = {
            'hits': {
                'hits': [
                    {'_source': {'alert': 'Test Alert 1'}},
                    {'_source': {'alert': 'Test Alert 2'}}
                ]
            }
        }
        mock_elastic_client().search.return_value = mock_response
        mock_summarize_alerts.return_value = "Summary of alerts"

        # Call the method
        search_tool = InternalThreatSearch()
        result = search_tool.get_summary('2024-03-31')

        # Assertions
        self.assertEqual(result, "Summary of alerts")
        mock_summarize_alerts.assert_called_once()

    @patch('api_app.tools.elastic.elastic_client')
    @patch('api_app.tools.elastic.get_current_formatted_date')
    def test_get_summary_no_alerts(self, mock_get_current_formatted_date, mock_elastic_client):
        """
        Test the get_summary method of the InternalThreatSearch tool
        Mocks the elasticsearch client to return no alerts
        Asserts that the method returns the correct message "No alerts found for the specified date..."
        """
        # Mocking the formatted date function
        mock_get_current_formatted_date.return_value = "2024-04-01"

        # Mocking the elasticsearch response for no alerts
        mock_response = {
            'hits': {
                'hits': []
            }
        }
        mock_elastic_client().search.return_value = mock_response

        # Call the method
        search_tool = InternalThreatSearch()
        result = search_tool.get_summary('2024-03-31')

        # Assertions
        expected_result = "No alerts found for the specified date 2024-03-31"
        self.assertEqual(result, expected_result)


class TestCVESearchTool(TestCase):

    @patch('api_app.tools.cve.requests.get')  
    @patch('api_app.tools.cve.format_cve')   
    def test_cvesearch_success(self, mock_format_cve, mock_get):
        """
        Test the cvesearch method of the CVESearchTool
        Mocks the requests.get function to return a successful response
        Mocks the format_cve function to return a formatted output
        Asserts that the method returns the correct formatted output
        """

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cves": [{"id": "CVE-XXXX-XXXXX", "description": "Sample CVE"}]}
        mock_get.return_value = mock_response

        # Mock formatting function
        mock_format_cve.return_value = """Formatted CVE output
        CVE-ID: CVE-XXXX-XXXXX
        Description: Sample CVE
        CVSS Score: 0.0
        Published Date: 2024-10-01
        """


        client = CVESearchTool()
        result = client.cvesearch.run(tool_input={"keyword":"CVE-XXXX-XXXXX", "date":"2024-10-01"})

        # Verify the expected URL was used in the request
        mock_get.assert_called_once_with('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=CVE-XXXX-XXXXX%202024-10-01&resultsPerPage=3')
        # Verify the response was formatted
        mock_format_cve.assert_called_once_with(mock_response.json(), mode="normal", keyword="CVE-XXXX-XXXXX 2024-10-01")
        # Check the result
        self.assertEqual(result, """Formatted CVE output
        CVE-ID: CVE-XXXX-XXXXX
        Description: Sample CVE
        CVSS Score: 0.0
        Published Date: 2024-10-01
        """)

    @patch('api_app.tools.cve.requests.get')
    def test_cvesearch_failed_request(self, mock_get):
        """
        Test the cvesearch method of the CVESearchTool
        Mocks the requests.get function to return a failed response
        Asserts that the method returns the correct error message
        """

        # Mock a failed response
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = CVESearchTool.cvesearch.run(tool_input={"keyword":"CVE-XXXX-XXXXX"})

        # Verify the error handling
        self.assertEqual(result, {"error": "Failed to fetch data from the NVD API.", "status_code": 500})

    @patch('api_app.tools.cve.requests.get')
    def test_cvesearch_exception(self, mock_get):
        """
        Test the cvesearch method of the CVESearchTool
        Mocks the requests.get function to raise an exception
        Asserts that the method returns the correct error message
        """

        # Mock an exception being raised
        mock_get.side_effect = RequestException("Connection error")

        result = CVESearchTool.cvesearch.run(tool_input={"keyword":"CVE-XXXX-XXXXX"})

        # Verify the exception handling
        self.assertEqual(result, {"error": "Connection error"})

    @patch('api_app.tools.cve.requests.get')
    @patch('api_app.tools.cve.format_cve')
    @patch('api_app.tools.cve.llm_invoke')  # Mock the LLM invocation
    def test_get_latest_cves_success(self, mock_llm_invoke, mock_format_cve, mock_get):
        """
        Test the get_latest_cves method of the CVESearchTool
        Mocks the requests.get function to return a successful response
        Mocks the format_cve function to return a formatted output
        Mocks the LLM invocation to return a summarized output
        Asserts that the method returns the correct summarized output
        """

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cves": [{"id": "CVE-2024-5678", "description": "Latest CVE"}]}
        mock_get.return_value = mock_response

        # Mock formatting function
        mock_format_cve.return_value = "Formatted latest CVEs"
        # Mock LLM invocation
        mock_llm_invoke.return_value = "Summarized CVEs in bullet points"

        result = CVESearchTool.get_latest_cves.run(tool_input={"keyword": "latest keyword"})

        # Verify the expected URL was used in the request
        mock_get.assert_called_once()
        # Verify the format function was called
        mock_format_cve.assert_called_once_with(mock_response.json(), mode="latest", keyword="latest keyword")
        # Verify the LLM invocation
        mock_llm_invoke.assert_called_once_with("Summarize the following CVEs in bullet points while keeping technical details:\n\nFormatted latest CVEs")
        # Check the result
        self.assertEqual(result, "Summarized CVEs in bullet points")

    @patch('api_app.tools.cve.requests.get')
    def test_get_latest_cves_failed_request(self, mock_get):
        """
        Test the get_latest_cves method of the CVESearchTool
        Mocks the requests.get function to return a failed response
        Asserts that the method returns the correct error message
        """
        # Mock a failed response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = CVESearchTool.get_latest_cves.run(tool_input={"keyword": ""})

        # Verify the error handling
        self.assertEqual(result, {"error": "Failed to fetch data from the NVD API.", "status_code": 404})

    @patch('api_app.tools.cve.requests.get')
    def test_get_latest_cves_exception(self, mock_get):
        """
        Test the get_latest_cves method of the CVESearchTool
        Mocks the requests.get function to raise an exception
        Asserts that the method returns the correct error message
        """

        # Mock an exception being raised
        mock_get.side_effect = RequestException("Service unavailable")

        result = CVESearchTool.get_latest_cves.run(tool_input={"keyword": ""})

        # Verify the exception handling
        self.assertEqual(result, {"error": "Service unavailable"})

class TestMISPTool(TestCase):
    """ 
    Test cases for the MISPTool
    """

    @patch('api_app.tools.misp.misp_client')  # Mocking the misp_client function
    def test_search_success(self, mock_misp_client):
        """
        Test the search method of the MISPTool
        Mocks the misp_client to return a successful response
        Asserts that the method returns the correct search results
        """
        # Mock the MISP search response
        mock_events = {
            'Attribute': [{'id': 1, 'value': 'malicious.com'}, {'id': 2, 'value': 'suspicious.com'}]
        }
        mock_misp_client.return_value.search.return_value = mock_events
        
        # Create an instance of MISPTool
        tool = MISPTool()
        
        # Call the search method
        result = tool.search("malicious.com")

        # Assertions
        self.assertIn("Search results for malicious.com", result)
        self.assertIn("malicious.com", result)
        self.assertIn("suspicious.com", result)

    @patch('api_app.tools.misp.misp_client')
    def test_search_no_events(self, mock_misp_client):
        """
        Test the search method of the MISPTool
        Mocks the misp_client to return no events
        Asserts that the method returns the correct message "No events found matching the search criteria."
        """
        # Mock the MISP search response with no events
        mock_events = {'Attribute': []}
        mock_misp_client.return_value.search.return_value = mock_events
        
        tool = MISPTool()
        
        result = tool.search("unknown.com")

        # Assertions
        self.assertEqual(result, "No events found matching the search criteria.")

    @patch('api_app.tools.misp.misp_client')
    def test_search_by_date(self, mock_misp_client):
        """
        Test the search_by_date method of the MISPTool
        Mocks the misp_client to return events matching the date
        Asserts that the method returns the correct search results
        """
        # Mock the MISP search response
        mock_events = {'Attribute': [{'id': 3, 'date': '2024-10-01'}]}
        mock_misp_client.return_value.search.return_value = mock_events
        
        tool = MISPTool()
        
        result = tool.search_by_date.run(tool_input={"date_from":"2024-10-01", "date_to":"2024-10-01"})

        # Assertions
        self.assertIn("2024-10-01", result)

    @patch('api_app.tools.misp.misp_client')
    def test_search_by_event_id(self, mock_misp_client):
        """
        Test the search_by_event_id method of the MISPTool
        Mocks the misp_client to return events matching the event ID
        Asserts that the method returns the correct search results"""
        # Mock the MISP search response
        mock_events = {'Attribute': [{'id': 1, 'event_id': 123, 'value': 'malicious.com'}]}
        mock_misp_client.return_value.search.return_value = mock_events
        
        tool = MISPTool()
        
        result = tool.search_by_event_id.run(tool_input={'event_id':123})

        # Assertions
        self.assertIn("123", result)
        self.assertIn("malicious.com", result)



class TestVirusTotalTool(TestCase):
    """
    Test cases for the VirusTotalTool
    """

    @patch('api_app.tools.virustotal.requests.get')  # Mocking the requests.get function
    @patch('api_app.tools.virustotal.requests.post')  # Mocking the requests.post function
    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'test_api_key'})  # Mocking environment variable
    def test_scanner_hash_success(self, mock_post, mock_get):
        """
        Test the scanner method of the VirusTotalTool with a hash
        Mocks the requests.post and requests.get functions to return successful responses
        Asserts that the method returns the correct scan results
        """

        # Mock the get response for hash scanning
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {'response_code': 1, 'scan_results': 'Hash scan results'}
        mock_get.return_value = mock_get_response
        
        # Create an instance of VirusTotalTool
        tool = VirusTotalTool()

        # Call the scanner method with a hash
        result = tool.scanner.run(tool_input={'resource':'d41d8cd98f00b204e9800998ecf8427e', 'scan_type':'hash'})

        # Assertions
        self.assertIn('Hash scan results', result)
        mock_get.assert_called_once_with(
            'https://www.virustotal.com/vtapi/v2/file/report', 
            params={'apikey': 'test_api_key', 'resource': 'd41d8cd98f00b204e9800998ecf8427e'}
        )

    @patch('api_app.tools.virustotal.requests.get')
    @patch('api_app.tools.virustotal.requests.post')
    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'test_api_key'})
    def test_scanner_url_success(self, mock_post, mock_get):
        """
        Test the scanner method of the VirusTotalTool with a URL
        Mocks the requests.post and requests.get functions to return successful responses
        Asserts that the method returns the correct scan results
        """
        # Mock the post response for URL scanning
        mock_post_response = MagicMock()
        mock_post_response.json.return_value = {'response_code': 1, 'scan_results': 'URL scan queued'}
        mock_post.return_value = mock_post_response
        
        # Mock the get response for URL scanning
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {'response_code': 1, 'scan_results': 'URL scan results'}
        mock_get.return_value = mock_get_response
        
        tool = VirusTotalTool()

        # Call the scanner method with a URL
        result = tool.scanner.run(tool_input={'resource':'https://example.com', 'scan_type':'url'})


        # Assertions
        self.assertIn('URL scan results', result)
        mock_post.assert_called_once_with(
            'https://www.virustotal.com/vtapi/v2/url/scan', 
            data={'apikey': 'test_api_key', 'url': 'https://example.com'}
        )
        mock_get.assert_called_once_with(
            'https://www.virustotal.com/vtapi/v2/url/report', 
            params={'apikey': 'test_api_key', 'url': 'https://example.com'}
        )

    @patch('api_app.tools.virustotal.requests.get')
    @patch('api_app.tools.virustotal.requests.post')
    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'test_api_key'})
    def test_scanner_ip_success(self, mock_post, mock_get):
        """
        Test the scanner method of the VirusTotalTool with an IP
        Mocks the requests.get function to return successful responses
        Asserts that the method returns the correct scan results
        """
        # Mock the get response for IP scanning
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {'response_code': 1, 'scan_results': 'IP scan results'}
        mock_get.return_value = mock_get_response
        
        tool = VirusTotalTool()

        # Call the scanner method with an IP
        result = tool.scanner.run(tool_input={'resource':'8.8.8.8', 'scan_type':'ip'})


        # Assertions
        self.assertIn('IP scan results', result)
        mock_get.assert_called_once_with(
            'https://www.virustotal.com/vtapi/v2/ip-address/report', 
            params={'apikey': 'test_api_key', 'ip': '8.8.8.8'}
        )

    @patch('api_app.tools.virustotal.requests.get')
    @patch('api_app.tools.virustotal.requests.post')
    @patch.dict(os.environ, {'VIRUSTOTAL_API_KEY': 'test_api_key'})
    def test_scanner_invalid_resource(self, mock_post, mock_get):
        """
        Test the scanner method of the VirusTotalTool with an invalid resource type
        Mocks the requests.get function to return an error response
        Mocks the requests.post function to return an error response
        Asserts that the method returns the correct error message
        """
        # Mock the get response for an invalid resource type
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {'response_code': 0, 'error': 'Invalid resource'}
        mock_get.return_value = mock_get_response
        
        tool = VirusTotalTool()

        # Call the scanner method with an invalid resource type
        result = tool.scanner.run(tool_input={'resource':'invalid_resource', 'scan_type':'hash'})

        # Assertions
        self.assertIn('Invalid resource', result)
        mock_get.assert_called_once_with(
            'https://www.virustotal.com/vtapi/v2/file/report', 
            params={'apikey': 'test_api_key', 'resource': 'invalid_resource'}
        )


class TestMitreTool(TestCase):

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_technique_by_id_success(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = [{"id": "T1003", "name": "Credential Dumping"}]
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_technique_by_id.run(tool_input={'domain':'enterprise', 'technique_id':'T1003'})
        self.assertEqual(result, [{"id": "T1003", "name": "Credential Dumping"}])
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_technique_by_id_not_found(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = []
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_technique_by_id.run(tool_input={'domain':'enterprise', 'technique_id':'T90099'})
        self.assertEqual(result, "No technique found with that ID")
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_technique_by_name_success(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = [{"id": "T1003", "name": "Credential Dumping"}]
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_technique_by_name.run(tool_input={'domain':'enterprise', 'technique_name':'Credential Dumping'})
        self.assertEqual(result, [{"id": "T1003", "name": "Credential Dumping"}])
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_technique_by_name_not_found(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = []
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_technique_by_name.run(tool_input={'domain':'enterprise', 'technique_name':'Nonexistent Technique'})
        self.assertEqual(result, "No technique found with that name")
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_malware_by_name_success(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = [{"id": "S0012", "name": "Malware-X"}]
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_malware_by_name.run(tool_input={'domain':'enterprise', 'malware_name':'Malware-X'})
        self.assertEqual(result, [{"id": "S0012", "name": "Malware-X"}])
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_malware_by_name_not_found(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = []
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_malware_by_name.run(tool_input={'domain':'enterprise', 'malware_name':'Nonexistent Malware :)'})
        self.assertEqual(result, "No malware found with that name")
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_tactic_by_keyword_success(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = [{"id": "TA0001", "name": "Initial Access", "description": "Gain entry to a system"}]
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_tactic_by_keyword.run(tool_input={'domain':'enterprise', 'keyword':'Initial Access'})
        self.assertEqual(result, {"id": "TA0001", "name": "Initial Access", "description": "Gain entry to a system"})
        mock_store.query.assert_called_once()

    @patch('api_app.tools.mitre.get_mitre_store')
    def test_get_tactic_by_keyword_not_found(self, mock_mitre_store):
        # Mock the store return for domain
        mock_store = MagicMock()
        mock_store.query.return_value = []
        mock_mitre_store.return_value = {'enterprise': mock_store}

        result = MitreTool.get_tactic_by_keyword.run(tool_input={'domain':'enterprise', 'keyword':'something'})

        self.assertEqual(result, "No tactics/techniques matches the keyword you provided")
        mock_store.query.assert_called_once()

class TestAgentSetup(TestCase):
    """
    Test cases for the setup_agents function
    This mainly tests the initialization of the agents
    """
    @patch('api_app.agents.hypotesis.HypothesisAgent')
    @patch('api_app.agents.investigator.InvestigationAgent')
    @patch('api_app.agents.router.RouterAgent')
    def test_setup_agents_initialization(self, MockRouterAgent, MockInvestigationAgent, MockHypothesisAgent):
        """
        Test the setup_agents function
        Mocks the agents to return instances
        Asserts that the agents are initialized correctly
        """
        # Mock the agents
        mock_hyp_agent = MockHypothesisAgent.return_value
        mock_inv_agent = MockInvestigationAgent.return_value
        mock_router_agent = MockRouterAgent.return_value

        # Run setup_agents
        router_agent, hyp_agent, inv_agent = setup_agents()


        # Check that the router agent has the correct tools
        self.assertEqual(len(router_agent.tools), 2)
        self.assertIsInstance(router_agent.tools[0], Tool)
        self.assertIsInstance(router_agent.tools[1], Tool)

        # Check the names of the tools
        self.assertEqual(router_agent.tools[0].name, "Investigate Tool")
        self.assertEqual(router_agent.tools[1].name, "Hypothesis Tool")









