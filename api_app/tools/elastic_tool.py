from langchain.tools import tool
import os
from .utils import elastic_client, summarize_alerts, get_current_formatted_date


class InternalThreatSearch():

    @tool("Alert search by IP address Tool", return_direct=True)
    def search_by_ip(ip: str) -> str:
      """Useful tool to search for an alert by its ip in an internal logs database, and return the full alert details if there is a match
      Parameters:
      - ip: The ip to search for
      Returns:
      - The full details of the alert with the specified ip
      """

      index_pattern = 'logstash-*-alert-*'

      search_query = {
          "query": {
              "bool": {
                  "should": [
                      {"match": {"src_ip": ip}},
                      {"match": {"dest_ip": ip}}
                  ]
              }
          }
      }

      # Execute the search query
      res = elastic_client().search(index=index_pattern, body=search_query, error_trace=True, source_excludes=["event", "payload", "log", "@version", "type", "payload_printable", "http", "tcp", "packet", "metadata"])
      if res['hits']['hits']:
        hits = res["hits"]["hits"][:3]
        alerts = [x['_source'] for x in hits]

        return str(alerts)

      else:
        return f"No alerts found for the specified IP address {ip}"  

    @tool("IP Address Lookup and Geolocation Tool")
    def geolocate_ip(ip:str):
        """Useful tool to get the geolocation of an IP address, and return the details if there is a match
        Parameters:
        - ip: The ip to search for
        Returns:
        - The geolocation details of the IP address
        """

        index_pattern = 'logstash-*-alert-*'

        # Define the search query
        search_query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"src_ip": ip}},
                        {"match": {"dest_ip": ip}}
                    ]
                }
            }
        }



        # Perform the search

        response = elastic_client().search(index=index_pattern, body=search_query, error_trace=True, source=["src_ip","dest_ip","ether","geoip"])
        if response['hits']['hits']:
            hits = response["hits"]["hits"]
            alerts = [x['_source'] for x in hits]

            return str(alerts)

        else:
            return f"No geolocation found for the specified IP address {ip}, this can be due to the IP is not in the database, or it doesn't have a geolocation associated."  

    @tool("Get Summary of Alerts", return_direct=True)
    def get_summary(date: str = None, size: int = 50):
        """Useful tool to get a summary of the latest alerts in the internal logs database
        Parameters:
        - date: The date to search for alerts (format: YYYY-MM-DD) (optional)
        - size: The number of alerts to return (default: 50)
        Returns:
        - A summary of the latest alerts in the internal logs database
        """

        index_pattern = 'logstash-*-alert-*'

        # Define the search query
        search_query = {
            "size": size,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": date if date else "2024-03-01",
                        "lt": get_current_formatted_date()  # one day after the specific date
                    }
                }
            }
        }

        # Perform the search
        response = elastic_client().search(index=index_pattern, body=search_query, source_excludes=["event", "payload", "log", "@version", "type", "payload_printable"])

        if response['hits']['hits']:
            hits = response["hits"]["hits"]

            return summarize_alerts(hits)
        
        else:
            return f"No alerts found for the specified date {date}"
        
      
