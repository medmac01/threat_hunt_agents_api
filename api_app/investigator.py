from langchain_community.llms import Ollama

from langchain import hub

from agentops.langchain_callback_handler import LangchainCallbackHandler as AgentOpsLangchainCallbackHandler

from langchain.chains.conversation.memory import ConversationBufferWindowMemory

from .tools.cve_avd_tool import CVESearchTool
from .tools.misp_tool import MispTool
from .tools.coder_tool import CoderTool
from .tools.mitre_tool import MitreTool

from langchain.agents import initialize_agent, AgentType, load_tools

from dotenv import load_dotenv
import os
import re

load_dotenv(override=True)

llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.3, num_predict=-1)
# wrn = Ollama(model="wrn", base_url=os.getenv('OLLAMA_HOST'))
# llama3 = Ollama(model="llama3", base_url=os.getenv('OLLAMA_HOST'), temperature=0.3)


cve_search_tool = CVESearchTool().cvesearch
fetch_cve_tool = CVESearchTool().get_latest_cves
misp_search_tool =  MispTool().search
misp_search_by_date_tool = MispTool().search_by_date
misp_search_by_event_id_tool = MispTool().search_by_event_id
# coder_tool = CoderTool().code_generation_tool Disabled for now for more stability

get_technique_by_id = MitreTool().get_technique_by_id
get_technique_by_name = MitreTool().get_technique_by_name
get_malware_by_name = MitreTool().get_malware_by_name
get_tactic_by_keyword = MitreTool().get_tactic_by_keyword

tools = [cve_search_tool, fetch_cve_tool, misp_search_tool, misp_search_by_date_tool, misp_search_by_event_id_tool, 
         get_technique_by_id, get_technique_by_name, get_malware_by_name, get_tactic_by_keyword]

# conversational agent memory
memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=4,
    return_messages=True
)


#Error handling
def _handle_error(error) -> str:

    pattern = r'```(?!json)(.*?)```'
    match = re.search(pattern, str(error), re.DOTALL)
    if match: 
        return "The answer contained a code blob which caused the parsing to fail, i recovered the code blob. Just use it to answer the user question: " + match.group(1)
    else: 
        return llm.invoke(f"""Try to summarize and explain the following error into 1 short and consice sentence and give a small indication to correct the error: {error} """)


prompt = hub.pull("hwchase17/react-chat-json")
# create our agent
conversational_agent = initialize_agent(
    # agent="chat-conversational-react-description",
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    tools=tools,
    prompt=prompt,
    llm=llm,
    verbose=True,
    max_iterations=5,
    memory=memory,
    early_stopping_method='generate',
    # callbacks=[agentops_handler],
    handle_parsing_errors=_handle_error,
    return_intermediate_steps=False,
    max_execution_time=40,
)

template = conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template

conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = """You are a cyber security analyst agent, you role is to respond to the human queries in a technical way while providing detailed explanations when providing final answer."""

def invoke(input_text):
    results = conversational_agent({"input":input_text})
    return results['output']
