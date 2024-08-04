from langchain.agents import AgentType
from langchain.tools import Tool
from langfuse.decorators import observe

from .investigator import invoke as investigator_invoke
from .hypotesis import invoke as hypotesis_invoke
 
from .prompts import ROUTER_PROMPT_TEMPLATE
from .utils import generate_title

from .agent import RouterAgent


router_agent = RouterAgent(agent_type=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
    mem_key='chat_history',
    mem_k=5,
    agent_prompt=ROUTER_PROMPT_TEMPLATE,
    agent_verbose=True
)

router_agent.tools = [Tool(name="Investigate Tool", 
                        description="This tool will help you execute a query to find information about a security event.(Can be a MISP event, CVE, MITRE attack or technique, malware...) Just provide the request and get the response.", 
                        func=investigator_invoke,
                        return_direct=False),

                    Tool(name="Hypothesis Tool",
                        description="This tool will help you search network internal logs for any Indicators of compromise (specific ip address, hostname). Just provide the request and get the response.",
                        func=hypotesis_invoke,
                        return_direct=False)]

agent = router_agent.cnv_agent

@observe()
def invoke(input_text, title=True, llm="openhermes", new_chat=False):
    """
    Invokes the router agent.
    Parameters:
    input_text: (str) The input text to be processed by the agent.
    title: (bool) Whether to generate a title for the response.
    llm: (str) The language model to be used.
    new_chat: (bool) Whether to start a new chat.
    """
   
    return {"output":agent({"input":input_text}),
            "title":generate_title(input_text)} if title else {"output":agent({"input":input_text})}

    
def stream(llm="codestral"):
    """
    Streams the output of the agent.
    """

    return agent

def clear():
    """
    Clears the memory of the agent.
    """
    
    return router_agent.clear_memory() 



