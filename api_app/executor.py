from langfuse.decorators import observe
from .chat.setup_agents import setup_agents
from .agents.hypotesis import HypothesisAgent
from .agents.investigator import InvestigationAgent
from .agents.router import RouterAgent
from .agents.agent import LLM
from .chat.utils import generate_title

# Initialize the agents
router_agent, inv_agent, hyp_agent = setup_agents()


# @observe(as_type="generation")
@observe()
def invoke(input_text, title=True, new_chat=False, llm: LLM = LLM.CODESTRAL):
    """
    Invokes the router agent.
    Parameters:
    input_text: (str) The input text to be processed by the agent.
    title: (bool) Whether to generate a title for the response.
    llm: (LLM) The language model to use.
    new_chat: (bool) Whether to start a new chat.
    """

    # Set the language model
# router_agent.llm = router_agent.llms[llm]

    # Clear the chat if new_chat is True
    if new_chat:
        clear()

    # Set the agent executor
    agent_executor = router_agent.cnv_agent
   
    # Return the output of the agent
    return {"output":agent_executor({"input":input_text}),
            "title":generate_title(input_text)} if title else {"output":agent_executor({"input":input_text})}

    
def stream(llm: LLM = LLM.CODESTRAL):
    """
    Streams the output of the agent.
    """

    return router_agent.cnv_agent

def clear():
    """
    Clears the memory of the agent.
    Parameters:
    agent: (RouterAgent | InvestigationAgent | HypothesisAgent) The agent to clear the memory of.
    Returns:
    bool: True if the memory was cleared successfully, False otherwise.
    """
    router_agent.clear_memory()
    inv_agent.clear_memory()
    hyp_agent.clear_memory()

    return True



