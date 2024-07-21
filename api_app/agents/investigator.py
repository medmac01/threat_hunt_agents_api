from langchain_community.llms import Ollama

from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langfuse.callback import CallbackHandler

from ..tools.cve_avd_tool import CVESearchTool
# from ..tools.misp_tool import MispTool
#from ..tools.coder_tool import CoderTool -------> Deprecated
from ..tools.mitre_tool import MitreTool
from ..tools.virustotal_tool import VirusTotalTool

from langchain.agents import initialize_agent, AgentType
from langfuse.decorators import observe

import os, re

from .prompts import INVESTIGATOR_SYSTEM_PROMPT, INVESTIGATOR_PROMPT_TEMPLATE, REACT_PROMPT
from .utils import get_chat_id

codestral = Ollama(model="codestral", base_url=os.getenv('OLLAMA_HOST'), temperature=0.5, num_predict=8192, num_ctx=16384, system=INVESTIGATOR_SYSTEM_PROMPT)
llama3 = Ollama(model="llama3", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system=INVESTIGATOR_SYSTEM_PROMPT)
openhermes = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system=INVESTIGATOR_SYSTEM_PROMPT)


cve_search_tool = CVESearchTool().cvesearch
fetch_cve_tool = CVESearchTool().get_latest_cves
get_technique_by_id = MitreTool().get_technique_by_id
get_technique_by_name = MitreTool().get_technique_by_name
get_malware_by_name = MitreTool().get_malware_by_name
get_tactic_by_keyword = MitreTool().get_tactic_by_keyword
virus_total_tool = VirusTotalTool().scanner
# misp_search_tool = MispTool().search
# misp_search_by_date_tool = MispTool().search_by_date
# misp_search_by_event_id_tool = MispTool().search_by_event_id


tools = [cve_search_tool, fetch_cve_tool, 
         get_technique_by_id, get_technique_by_name, get_malware_by_name, get_tactic_by_keyword, virus_total_tool]
# tools = [cve_search_tool, fetch_cve_tool, misp_search_tool, misp_search_by_date_tool, misp_search_by_event_id_tool, 
#          get_technique_by_id, get_technique_by_name, get_malware_by_name, get_tactic_by_keyword, virus_total_tool]

memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=3,
    return_messages=True
)

llm = openhermes

#Error handling
def _handle_error(error) -> str:

    pattern = r'```(?!json)(.*?)```'
    match = re.search(pattern, str(error), re.DOTALL)
    if match: 
        return "The answer contained a code blob which caused the parsing to fail, i recovered the code blob. Just use it to answer the user question: " + match.group(1)
    else: 
        return llm.invoke(f"""Try to summarize and explain the following error into 1 short and consice sentence and give a small indication to correct the error: {error} """)


langfuse_handler = CallbackHandler(
        secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
        public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
        host=os.getenv("LANGFUSE_API_URL"),
        debug=False,
        session_id=f"chain_inv_{get_chat_id()}"
    )

conversational_agent = initialize_agent(
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    tools=tools,
    prompt=REACT_PROMPT,
    llm=llm,
    verbose=True,
    max_iterations=1,
    memory=memory,
    early_stopping_method='generate',
    callbacks=[langfuse_handler],
    handle_parsing_errors=_handle_error,
    return_intermediate_steps=False,
    max_execution_time=40,
)

template = conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template
conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = INVESTIGATOR_PROMPT_TEMPLATE + template

@observe()
def invoke(input_text):
    results = conversational_agent({"input":input_text})
    return results['output']
