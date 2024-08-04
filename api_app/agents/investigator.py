from langchain.agents import AgentType
from langfuse.decorators import observe

from .prompts import INVESTIGATOR_PROMPT_TEMPLATE

from .agent import InvestigationAgent

conversational_agent = InvestigationAgent(
    mem_key='chat_history',
    mem_k=2,
    agent_prompt=INVESTIGATOR_PROMPT_TEMPLATE,
    agent_type=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION
).cnv_agent

@observe()
def invoke(input_text):
    """
    Invokes the conversational agent.
    Parameters:
    input_text: (str) The input text to be processed by the agent.
    """
    
    results = conversational_agent({"input":input_text})
    return results['output']
