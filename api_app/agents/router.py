from langchain_community.llms import Ollama
from langfuse.callback import CallbackHandler
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langchain.agents import initialize_agent, AgentType
from langchain.callbacks.streaming_stdout_final_only import FinalStreamingStdOutCallbackHandler
from langchain.tools import Tool
from langfuse.decorators import observe

import os

from .investigator import invoke as investigator_invoke
from .hypotesis import invoke as hypotesis_invoke
 
from .prompts import HERMES_SYSTEM, ROUTER_PROMPT_TEMPLATE
from .utils import get_chat_id, set_new_chat_id

codestral = Ollama(model="codestral", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system=HERMES_SYSTEM, callbacks=[FinalStreamingStdOutCallbackHandler(answer_prefix_tokens=["Final", "Answer", '",', "\n" , ' "', "action", "_", "input", '":', ' "'])])
llama3 = Ollama(model="llama3", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system=HERMES_SYSTEM)
openhermes = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.2, num_predict=4096, num_ctx=8192, system=HERMES_SYSTEM, callbacks=[FinalStreamingStdOutCallbackHandler(answer_prefix_tokens=["Final", "Answer", '",', "\n" , ' "', "action", "_", "input", '":', ' "'])])


investigate_tool = Tool(name="Investigate Tool", 
                        description="This tool will help you execute a query to find information about a security event.(Can be a MISP event, CVE, MITRE attack or technique, malware...) Just provide the request and get the response.", 
                        func=investigator_invoke,
                        return_direct=False)

hypothesis_tool = Tool(name="Hypothesis Tool",
                          description="This tool will help you search network internal logs for any Indicators of compromise (specific ip address, hostname). Just provide the request and get the response.",
                          func=hypotesis_invoke,
                          return_direct=False)

tools = [investigate_tool, hypothesis_tool]


memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=5,
    return_messages=True
)

langfuse_handler = CallbackHandler(
        secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
        public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
        host=os.getenv("LANGFUSE_API_URL"),
        debug=False,
        session_id=f"conv_router_{get_chat_id()}"   
)


def generate_title(input_text):
    return openhermes.invoke(f"Generate a title for the following question: {input_text}, the title should be short and concise.")

@observe()
def invoke(input_text, title=True, llm="openhermes", new_chat=False):
    if llm == "codestral":
        llm = codestral
    elif llm == "llama3":
        llm = llama3
    elif llm == "openhermes":
        llm = openhermes
    else:
        return {"output":"Invalid LLM model"}
    
    if new_chat:        
        memory.clear()
        langfuse_handler.session_id = f"conv_router_{set_new_chat_id()}"


    agent = initialize_agent(
    agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
    tools=tools,
    llm=llm,
    verbose=False,
    max_iterations=5,
    memory=memory,
    early_stopping_method='generate',
    handle_parsing_errors=True,
    max_execution_time=40,
    callbacks=[langfuse_handler]
    )

    agent.agent.llm_chain.prompt.messages[0].prompt.template = ROUTER_PROMPT_TEMPLATE


    return {"output":agent({"input":input_text}),
            "title":generate_title(input_text)} if title else {"output":agent({"input":input_text})}

    
def stream(llm="codestral"):
    if llm == "codestral":
        llm = codestral
    elif llm == "llama3":
        llm = llama3
    elif llm == "openhermes":
        llm = openhermes
    else:
        return {"output":"Invalid LLM model"}
    
    
    agent = initialize_agent(
    agent=AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION,
    tools=tools,
    llm=llm,
    verbose=True,
    max_iterations=5,
    memory=memory,
    early_stopping_method='generate',
    handle_parsing_errors=True,
    max_execution_time=40,
    callbacks=[langfuse_handler]
    )
    agent.agent.llm_chain.prompt.messages[0].prompt.template = ROUTER_PROMPT_TEMPLATE
    
    return agent

def clear_chat():
    try:
        memory.clear()
    except Exception as e:
        return False
    return True


def get_models():
    models = {"models":[
        {"openhermes" : "OpenHermes-7B (Fast)"},
        {"codestral" : "Codestral-22B (Smart, slightly slower)"},
        {"llama3" : "Llama3-8b (Beta)"},
    ]}

    return models

