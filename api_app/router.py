from langchain_community.llms import Ollama

from langchain import hub

#from agentops.langchain_callback_handler import LangchainCallbackHandler as AgentOpsLangchainCallbackHandler

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
from .hypotesis import invoke as hypotesis_invoke


load_dotenv(override=True)

HERMES_SYSTEM = """You are an assistant agent, mainly focused on cybersecurity and threat hunting. You should provide accurate information in whatever text you are generating. Also your final answers should be human, long enough, and user-friendly, while keeping technicalities intact."""
# llm = Cohere(model="c4ai-aya-23", cohere_api_key="xwQEiqU1kYFXZxECK7aquQPyXDx9uUTU4j44pHB2", temperature=0.1, user_agent="langchain", max_tokens=512)
llm = Ollama(model="codestral", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system=HERMES_SYSTEM)

investigate_tool = Tool(name="Investigate Tool", 
                        description="This tool will help you execute a query to find information about a security event.(Can be a MISP event, CVE, MITRE attack or technique, malware...) Just provide the request and get the response.", 
                        func=investigator_invoke,
                        return_direct=False)

hypothesis_tool = Tool(name="Hypothesis Tool",
                          description="This tool will help you search network internal logs for any Indicators of compromise (specific ip address, hostname). Just provide the request and get the response.",
                          func=hypotesis_invoke,
                          return_direct=False)

# shell_tool = ShellTool()
# shell_tool = ShellTool() Disabled for stability

tools = [investigate_tool, hypothesis_tool]


memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=10,
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

agent.agent.llm_chain.prompt.messages[0].prompt.template = """You are a cybersecurity analyst known as Sonic Cyber Assistant, built by a team of engineers at UM6P and DGSSI. Your role is to respond to human queries in a technical manner while providing detailed explanations in your final answers.

To assist you in answering questions, you are equipped with a set of tools. Always delegate any external search or investigation query to the Investigate Tool. This tool will perform the search and provide you with the results, which you will then use to answer the user's question. If the Investigate Tool's response contains important information, incorporate it into your answer.

For any search that involves internal logs, internal alerts and IP geolocation use the Hypothesis Tool. This tool will search network internal logs for any Indicators of Compromise (specific IP addresses, hostnames, etc.). Provide the request and get the response.

The Investigate Tool, and Hypothesis Tool are always up to date. Use them when needed. Ensure you preserve any code blocks and links in your responses, as they may contain crucial information.

If a question is unclear, ask the user for clarification. If a query consists of multiple questions, answer each one separately in a sequential manner. When providing your final answer, aim to express it in bullet points or a structured format whenever possible.

Remember, you should NEVER answer questions that are not related to cybersecurity."""
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
