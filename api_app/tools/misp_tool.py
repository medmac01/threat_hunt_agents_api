from langchain.tools import tool
# import pymisp


from pymisp import PyMISP
from dotenv import load_dotenv
import os

load_dotenv(override=True)

URL = os.getenv('MISP_URL')
KEY = os.getenv('MISP_KEY')
verify_cert = False

print(URL, KEY)

misp = PyMISP(url=URL, key=KEY, ssl=verify_cert)

class MispTool():
    @tool("MISP search Tool by keyword")
    def search(keyword: str):
      """Useful tool to search for an indicator of compromise or an security event by keyword
      Parameters:
      - keyword: The keyword to search for
      Returns:
      - A list of events that match the keyword
      """

      events = misp.search(controller='attributes', value=keyword, limit=5, metadata=True, include_event_tags=False, include_context=False, return_format='json', sg_reference_only=True)
      
      if len(events['Attribute']) == 0:
        return "No events found matching the search criteria."
      
      results = """Answer user question using these search results:\n\n"""
      return results + str(events)
    
    @tool("MISP search Tool by date")
    def search_by_date(date_from: str = None, date_to: str = None):
      """Useful tool to retrieve events that match a specific date or date range, use this if you know the date of the event
      Parameters:
      - date_from: The start date of the event
      - date_to: The end date of the event
      Not necessary to provide both dates, you can provide one or the other

      Returns:
      - A list of events that match the date or date range
      """

      events = misp.search(controller='attributes',date_from=date_from, date_to=date_to, limit=5)
      return events

    @tool("MISP search Tool by event_id")
    def search_by_event_id(event_id: str | int):
      """Useful tool to retrieve events by their ID, use this if you know the ID of the event.
      Parameters:
      - event_id: The ID of the event
      Returns:
      - A list of events that match the event ID
      """

      events = misp.search(controller='attributes', eventid=event_id, limit=1)
      return events
    