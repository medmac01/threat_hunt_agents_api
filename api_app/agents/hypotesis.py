from langchain.agents import AgentType
from langfuse.decorators import observe

from .agent import HypothesisAgent
from .prompts import HYPOTHESIS_PROMPT_TEMPLATE

conversational_agent = HypothesisAgent(
    agent_type=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    mem_key='chat_history',
    mem_k=2,
    agent_prompt=HYPOTHESIS_PROMPT_TEMPLATE,
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
