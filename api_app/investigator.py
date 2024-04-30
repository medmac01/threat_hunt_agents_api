from langchain_community.llms import Ollama

from langchain import hub

from agentops.langchain_callback_handler import LangchainCallbackHandler as AgentOpsLangchainCallbackHandler

from langchain.chains.conversation.memory import ConversationBufferWindowMemory

from .tools.cve_avd_tool import CVESearchTool
from .tools.misp_tool import MispTool
from .tools.coder_tool import CoderTool

from langchain.agents import initialize_agent, AgentType, load_tools

from dotenv import load_dotenv
import os
import re

load_dotenv(override=True)


llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.3, num_predict=-1, num_ctx=8192)
wrn = Ollama(model="wrn", base_url=os.getenv('OLLAMA_HOST'))
llama3 = Ollama(model="llama3", base_url=os.getenv('OLLAMA_HOST'), temperature=0.3)


cve_search_tool = CVESearchTool().cvesearch
misp_search_tool =  MispTool().search
misp_search_by_date_tool = MispTool().search_by_date
misp_search_by_event_id_tool = MispTool().search_by_event_id
coder_tool = CoderTool().code_generation_tool

tools = [cve_search_tool, misp_search_tool, misp_search_by_date_tool, misp_search_by_event_id_tool, coder_tool]

# conversational agent memory
memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=3,
    return_messages=True
)

agentops_handler = AgentOpsLangchainCallbackHandler(api_key=os.getenv("AGENTOPS_API_KEY"), tags=['Langchain Example'])

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
    # handle_parsing_errors=True,
    # return_intermediate_steps=True,
    max_execution_time=40,
)

# conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = """
# 'Respond to the human as helpfully and accurately as possible. 
# You should use the tools available to you to help answer the question.
# Your final answer should be technical, well explained, and accurate.
# You have access to the following tools:\n\n\n\nUse a json blob to specify a tool by providing an action key (tool name) and an action_input key (tool input).\n\nValid "action" values: "Final Answer" or \n\nProvide only ONE action per $JSON_BLOB, as shown:\n\n```\n{{\n  "action": $TOOL_NAME,\n  "action_input": $INPUT\n}}\n```\n\nFollow this format:\n\nQuestion: input question to answer\nThought: consider previous and subsequent steps\nAction:\n```\n$JSON_BLOB\n```\nObservation: action result\n... (repeat Thought/Action/Observation N times)\nThought: I know what to respond\nAction:\n```\n{{\n  "action": "Final Answer",\n  "action_input": "Final response to human"\n}}\n```\n\nBegin! Reminder to ALWAYS respond with a valid json blob of a single action. Use tools if necessary. Respond directly if appropriate. Format is Action:```$JSON_BLOB```then Observation:.\nThought:'
# """

def invoke(input_text):
    return conversational_agent({"input":input_text})