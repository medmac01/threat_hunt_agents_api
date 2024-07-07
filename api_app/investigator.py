from langchain_community.llms import Ollama
from langchain_community.chat_models import ChatOllama

from langchain import hub

#from agentops.langchain_callback_handler import LangchainCallbackHandler as AgentOpsLangchainCallbackHandler

from langchain.chains.conversation.memory import ConversationBufferWindowMemory

from .tools.cve_avd_tool import CVESearchTool
from .tools.misp_tool import MispTool
from .tools.coder_tool import CoderTool
from .tools.mitre_tool import MitreTool
from .tools.virustotal_tool import VirusTotalTool

from langchain.agents import initialize_agent, AgentType, load_tools
from langchain.evaluation import load_evaluator


from dotenv import load_dotenv
import os
import re

from uuid import uuid4

load_dotenv(override=True)

unique_id = uuid4().hex[0:8]

os.environ["LANGCHAIN_TRACING_V2"]="true"
os.environ["LANGCHAIN_ENDPOINT"]="https://api.smith.langchain.com"
os.environ["LANGCHAIN_API_KEY"]=os.getenv("LANGCHAIN_API_KEY")
os.environ["LANGCHAIN_PROJECT"]="inv_agent"
# llm = Cohere(model="c4ai-aya-23", cohere_api_key="xwQEiqU1kYFXZxECK7aquQPyXDx9uUTU4j44pHB2", temperature=0.4, user_agent="langchain", max_tokens=512)
codestral = Ollama(model="codestral", base_url=os.getenv('OLLAMA_HOST'), temperature=0.5, num_predict=8192, num_ctx=16384, system="""You are designed to help with a variety of tasks, ranging from answering technical questions and providing detailed explanations to offering summaries and conducting thorough cybersecurity analyses. Your role also involves preserving crucial information, such as code blocks and links, and delivering answers in a structured format.""")
llama3 = Ollama(model="llama3", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system="""You are designed to help with a variety of tasks, ranging from answering technical questions and providing detailed explanations to offering summaries and conducting thorough cybersecurity analyses. Your role also involves preserving crucial information, such as code blocks and links, and delivering answers in a structured format.""")
openhermes = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system="""You are designed to help with a variety of tasks, ranging from answering technical questions and providing detailed explanations to offering summaries and conducting thorough cybersecurity analyses. Your role also involves preserving crucial information, such as code blocks and links, and delivering answers in a structured format.""")


cve_search_tool = CVESearchTool().cvesearch
fetch_cve_tool = CVESearchTool().get_latest_cves
misp_search_tool = MispTool().search
misp_search_by_date_tool = MispTool().search_by_date
misp_search_by_event_id_tool = MispTool().search_by_event_id
# coder_tool = CoderTool().code_generation_tool Disabled for now for more stability

get_technique_by_id = MitreTool().get_technique_by_id
get_technique_by_name = MitreTool().get_technique_by_name
get_malware_by_name = MitreTool().get_malware_by_name
get_tactic_by_keyword = MitreTool().get_tactic_by_keyword

virus_total_tool = VirusTotalTool().scanner

tools = [cve_search_tool, fetch_cve_tool, misp_search_tool, misp_search_by_date_tool, misp_search_by_event_id_tool, 
         get_technique_by_id, get_technique_by_name, get_malware_by_name, get_tactic_by_keyword, virus_total_tool]

# conversational agent memory
memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=4,
    return_messages=True
)

#agentops_handler = AgentOpsLangchainCallbackHandler(api_key=os.getenv("AGENTOPS_API_KEY"), tags=['Langchain Example'])
from .router import get_selected_llm
llm = get_selected_llm()

#Error handling
def _handle_error(error) -> str:

    pattern = r'```(?!json)(.*?)```'
    match = re.search(pattern, str(error), re.DOTALL)
    if match: 
        return "The answer contained a code blob which caused the parsing to fail, i recovered the code blob. Just use it to answer the user question: " + match.group(1)
    else: 
        return llm.invoke(f"""Try to summarize and explain the following error into 1 short and consice sentence and give a small indication to correct the error: {error} """)


prompt = """
Answer the following questions as best you can. You have access to the following tools:

{tools}

The way you use the tools is by specifying a json blob.
Specifically, this json should have a `action` key (with the name of the tool to use) and a `action_input` key (with the input to the tool going here).

The only values that should be in the "action" field are: {tool_names}

The $JSON_BLOB should only contain a SINGLE action, do NOT return a list of multiple actions. Here is an example of a valid $JSON_BLOB:

```
{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}
```

ALWAYS use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action:
```
$JSON_BLOB
```
Observation: the result of the action
... (this Thought/Action/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question, using the information from the observations. The final answer should be extra-long, well detailed and purely technical.

Begin! Reminder to always use the exact characters `Final Answer` when responding."""

# prompt = hub.pull("hwchase17/react-chat-json")
# create our agent
conversational_agent = initialize_agent(
    # agent="chat-conversational-react-description",
    agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
    tools=tools,
    prompt=prompt,
    llm=llm,
    verbose=True,
    max_iterations=1,
    memory=memory,
    early_stopping_method='generate',
    # callbacks=[agentops_handler],
    handle_parsing_errors=_handle_error,
    return_intermediate_steps=False,
    max_execution_time=40,
)


# conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = """
# 'Respond to the human as helpfully and accurately as possible. 
# You should use the tools available to you to help answer the question.
# Your final answer should be technical, well explained, and accurate.
# You have access to the following tools:\n\n\n\nUse a json blob to specify a tool by providing an action key (tool name) and an action_input key (tool input).\n\nValid "action" values: "Final Answer" or \n\nProvide only ONE action per $JSON_BLOB, as shown:\n\n```\n{{\n  "action": $TOOL_NAME,\n  "action_input": $INPUT\n}}\n```\n\nFollow this format:\n\nQuestion: input question to answer\nThought: consider previous and subsequent steps\nAction:\n```\n$JSON_BLOB\n```\nObservation: action result\n... (repeat Thought/Action/Observation N times)\nThought: I know what to respond\nAction:\n```\n{{\n  "action": "Final Answer",\n  "action_input": "Final response to human"\n}}\n```\n\nBegin! Reminder to ALWAYS respond with a valid json blob of a single action. Use tools if necessary. Respond directly if appropriate. Format is Action:```$JSON_BLOB```then Observation:.\nThought:'
# """


def invoke(input_text):
    # if llm == "codestral":
    #     sel_llm = codestral
    # elif llm == "llama3":
    #     sel_llm = llama3
    # elif llm == "openhermes":
    #     sel_llm = openhermes
    # else:
    #     return {"error": "Invalid LLM"}

    conversational_agent = initialize_agent(
        # agent="chat-conversational-react-description",
        agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
        tools=tools,
        prompt=prompt,
        llm=llm,
        verbose=True,
        max_iterations=1,
        memory=memory,
        early_stopping_method='generate',
        # callbacks=[agentops_handler],
        handle_parsing_errors=_handle_error,
        return_intermediate_steps=False,
        max_execution_time=40,
    )

    template = conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template

    conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = """You are a cyber security analyst, you role is to respond to the human queries in a technical way while providing detailed explanations when providing final answer. 
    You have access to tools that will help you answer the user queries (You will find the tools available below). You MUST pick the right tool precisely based on what the user asked you to search for.
    The tools are a little bit similar to each other, so you should be careful about which tool to use. Like for example when searching for CVEs, there is a tool that retrieves latest CVEs, and there is another one which searches for CVEs based on a keyword but not necessarly the latest. You should be careful about that.
    The tools observations will contain the results of the tools you used, and the final answer should be a technical, well explained, and should contains as much information as possible. DON'T SUMMARIZE PLEASE, SINCE THAT WILL LEAD TO INFORMATION LOSS.
    YOU MUST FORWARD THE SAME RESULTS ,WORD BY WORD, DON'T MODIFY ANYTHING""" + template

    results = conversational_agent({"input":input_text})
    return results['output']
