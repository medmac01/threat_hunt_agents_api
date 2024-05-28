from langchain_community.llms import Ollama

from langchain import hub

from agentops.langchain_callback_handler import LangchainCallbackHandler as AgentOpsLangchainCallbackHandler

from langchain.chains.conversation.memory import ConversationBufferWindowMemory

from langchain.agents import initialize_agent, AgentType, load_tools

from langchain.tools import StructuredTool, Tool, ShellTool

from dotenv import load_dotenv
import os
import re, json

from langchain.agents import create_json_agent
from langchain.agents.agent_toolkits import JsonToolkit
from langchain.tools.json.tool import JsonSpec

from .investigator import *
from .investigator import invoke as investigator_invoke

load_dotenv(override=True)


llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.3, num_predict=-1)
wrn = Ollama(model="wrn", base_url=os.getenv('OLLAMA_HOST'))

# def get_json_agent(json_path: str):
#     with open(json_path) as f:
#         data = json.load(f)
#     json_spec = JsonSpec(dict_=data, max_value_length=4000)
#     json_toolkit = JsonToolkit(spec=json_spec)

#     json_agent = create_json_agent(
#         llm=llm,
#         toolkit=json_toolkit,
#         verbose=True
#     )
#     return json_agent

# def investigate_agent():
#     """
#     This function will help you execute a query to find information about a security event. Just provide the request and get the response.
#     Parameters:
#     - request: The request to search for
#     Returns:
#     - The response of the search
#     """

#     def investigate(request: str):
#         json_agent = get_json_agent("./inventory_prices_dict.json")
#         result = json_agent.run(
#             f"""get the price of {inventory_item} from the json file.
#             Find the closest match to the item you're looking for in that json, e.g.
#              if you're looking for "mahogany oak table" and that is not in the json, use "table".
#             Be mindful of the format of the json - there is no list that you can access via [0], so don't try to do that
#             """)
#         return result

investigate_tool = Tool(name="Investigate Tool", 
                        description="This tool will help you execute a query to find information about a security event.(Can be a MISP event, CVE, MITRE attack or technique, malware...) Just provide the request and get the response.", 
                        func=investigator_invoke)

# shell_tool = ShellTool() Disabled for stability
tools = [investigate_tool]


memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=4,
    return_messages=True
)

agent = initialize_agent(
    agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
    tools=tools,
    # prompt=prompt,
    llm=llm,
    verbose=True,
    max_iterations=5,
    memory=memory,
    early_stopping_method='generate',
    # return_intermediate_steps=True,
    handle_parsing_errors=True,
    max_execution_time=40,
)

template = agent.agent.llm_chain.prompt.messages[0].prompt.template

agent.agent.llm_chain.prompt.messages[0].prompt.template = """You are a cyber security analyst called Sonic Cyber Assistant, you were built by a team of engineers at UM6P and DGSSI. you role is to respond to the human queries in a technical way while providing detailed explanations when providing final answer.
You are provided with a set of tools to help you answer the questions. Use the tools to help you answer the questions.
Always delegate any search or investigation query to the Investigate Tool. The Investigate Tool will perform the search for you and provide the results, which you will use to answer the user's question. If the Investigate Tool's response contains some important information, answer the user's question while providing the information.
Also try to preserve any code blocks in the response as well as links, as they may contain important information.
If the question is not clear, ask the user to clarify the question.
One important thing to remember is that if the question is composed of multiple questions, answer each question separately in a sequential manner.
NEVER ANSWER QUESTIONS THAT ARE NOT RELATED TO CYBERSECURITY.
"""
# print(agent.agent.llm_chain.prompt.messages[0].prompt.template)


def generate_title(input_text):
    return llm.invoke(f"Generate a title for the following question: {input_text}, the title should be short and concise.")

def invoke(input_text, title=True):
    return {"output":agent({"input":input_text}),
            "title":generate_title(input_text)} if title else {"output":agent({"input":input_text})}

def clear_chat():
    try:
        memory.clear()
    except Exception as e:
        return False
    return True