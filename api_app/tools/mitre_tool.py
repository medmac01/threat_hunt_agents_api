from stix2 import Filter
from langchain.tools import tool
from .utils import get_mitre_store


class MitreTool():

    @tool("MITRE Technique search by ID", return_direct=True)
    def get_technique_by_id(domain: str, technique_id: str):
        """Get the technique by its ID. Domain should be 'enterprise', 'mobile' or 'ics'
        Techniques represent 'how' an adversary achieves a tactical goal by performing an action. For example, an adversary may dump credentials to achieve credential access.
        """
        result = get_mitre_store()[domain].query([Filter('external_references.external_id', '=', technique_id)])
        return result if result else "No technique found with that ID"
    
    @tool("MITRE Technique search by name", return_direct=True)
    def get_technique_by_name(domain: str, technique_name: str):
        """Get the technique by its name. Domain should be 'enterprise', 'mobile' or 'ics'
        Techniques represent 'how' an adversary achieves a tactical goal by performing an action. For example, an adversary may dump credentials to achieve credential access."""
        result = get_mitre_store()[domain].query([Filter('name', 'contains', technique_name), Filter('type', '=', 'attack-pattern')])
        return result if result else "No technique found with that name"
    
    @tool("MITRE Malware search by name", return_direct=True)
    def get_malware_by_name(domain: str, malware_name: str):
        """Get the malware by its name. Domain should be 'enterprise', 'mobile' or 'ics'
        Malware represents software used to achieve a tactical goal by performing an action. For example, an adversary may use malware to achieve initial access."""
        result = get_mitre_store()[domain].query([Filter('name', 'contains', malware_name), Filter('type', '=', 'malware')])
        return result if result else "No malware found with that name"
    
    @tool("MITRE Technique search by keyword", return_direct=True)
    def get_tactic_by_keyword(domain: str, keyword: str):
        """Search for tactics/techniques by a keyword. Domain should be 'enterprise', 'mobile' or 'ics'
        Tactics represent the "why" of an ATT&CK technique or sub-technique. It is the adversary's tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access."""
        result = get_mitre_store()[domain].query([Filter('description', 'contains', keyword)], Filter('type', '=', 'attack-pattern'))
        return result[0] if result else "No tactics/techniques matches the keyword you provided"