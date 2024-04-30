import requests
from bs4 import BeautifulSoup
from elasticsearch import Elasticsearch
from langchain.tools import tool

es = Elasticsearch(
      "https://localhost:9200",
      basic_auth=("elastic","dVJI85*y60R3ZVbECj1w"),
      ca_certs="/Volumes/macOS/Projects/PFE UM6P/elasticsearch-8.12.1/config/certs/http_ca.crt"
    )


class EventSearchTool():
    @tool("Event search Tool")
    def search(keyword: str):
      """Useful tool to search for an indicator of compromise or an security event
      Parameters:
      - keyword: The keyword to search for
      Returns:
      - A list of events that match the keyword
      """

      
      # if not es.ping():
      #   raise "ElasticNotReachable"
      
      query = {
          "match": {"value": {
              "query": keyword
          }}
      }

      # Execute the search query
      res = es.search(size=5, index="all_events_full", query=query, knn=None, _source=["event_id", "event_title", "event_date", "category", "attribute_tags", "type", "value"])
      hits = res["hits"]["hits"]
      events = [x['_source'] for x in hits]

      return events
    

    @tool("Event search by event_id Tool")
    def get_event_by_id(id:str):
      """Useful tool to search for an event by its id, and return the full event details
      Parameters:
      - id: The event id to search for
      Returns:
      - The full details of the event with the specified id
      """

      if not es.ping():
        raise "ElasticNotReachable"
      res = es.search(index="all_events_full", query={"match": {"event_id": id}}, _source=["event_id", "event_title", "event_date", "category", "attribute_tags", "type", "value"])
      hits = res["hits"]["hits"]
      events = [x['_source'] for x in hits]

      return events
      
