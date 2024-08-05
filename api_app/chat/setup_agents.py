from ..agents.hypotesis import HypothesisAgent
from ..agents.investigator import InvestigationAgent
from ..agents.router import RouterAgent
from ..chat.prompts import HYPOTHESIS_PROMPT_TEMPLATE, INVESTIGATOR_PROMPT_TEMPLATE, ROUTER_PROMPT_TEMPLATE
from langchain.agents import AgentType
from langchain.tools import Tool

def def_invoke(agent):
    """
    Invokes the conversational agent.
    Parameters:
    input_text: (str) The input text to be processed by the agent.
    """
    def invoke(input_text):
        cnv_agent = agent.cnv_agent
        results = cnv_agent({"input":input_text})
        return results['output']
    
    return invoke


def setup_agents():
    """
    Initializes the agent.
    """
    hyp_agent = HypothesisAgent(
        agent_type=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
        mem_key='chat_history',
        mem_k=2,
        agent_prompt=HYPOTHESIS_PROMPT_TEMPLATE,
    )

    inv_agent = InvestigationAgent(
        mem_key='chat_history',
        mem_k=2,
        agent_prompt=INVESTIGATOR_PROMPT_TEMPLATE,
        agent_type=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION
    )

    router_agent = RouterAgent(agent_type=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
        mem_key='chat_history',
        mem_k=5,
        agent_prompt=ROUTER_PROMPT_TEMPLATE,
        agent_verbose=True
    )


    router_agent.tools = [Tool(name="Investigate Tool", 
                            description="This tool will help you execute a query to find information about a security event.(Can be a MISP event, CVE, MITRE attack or technique, malware...) Just provide the request and get the response.", 
                            func=def_invoke(inv_agent),
                            return_direct=False),

                        Tool(name="Hypothesis Tool",
                            description="This tool will help you search network internal logs for any Indicators of compromise (specific ip address, hostname). Just provide the request and get the response.",
                            func=def_invoke(hyp_agent),
                            return_direct=False)]

    return router_agent, hyp_agent, inv_agent