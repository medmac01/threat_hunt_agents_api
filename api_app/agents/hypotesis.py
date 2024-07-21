from langchain_community.llms import Ollama
from langchain.chains.conversation.memory import ConversationBufferWindowMemory

from langchain.agents import initialize_agent, AgentType
from langfuse.callback import CallbackHandler
from langfuse.decorators import observe

import os, re

from ..tools.elastic_tool import InternalThreatSearch

from .utils import get_chat_id
from .prompts import REACT_PROMPT, HYPOTHESIS_PROMPT_TEMPLATE

llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.5, num_predict=8192, num_ctx=16384, system="""You are designed to help with a variety of tasks, ranging from answering technical questions and providing detailed explanations to offering summaries and conducting thorough cybersecurity analyses. Your role also involves preserving crucial information, such as code blocks and links, and delivering answers in a structured format.""")

alert_search_by_ip = InternalThreatSearch().search_by_ip
geolocate_ip = InternalThreatSearch().geolocate_ip
summary_alerts = InternalThreatSearch().get_summary

tools = [alert_search_by_ip, geolocate_ip, summary_alerts]


memory = ConversationBufferWindowMemory(
    memory_key='chat_history',
    k=2,
    return_messages=True
)

langfuse_handler = CallbackHandler(
        secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
        public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
        host=os.getenv("LANGFUSE_API_URL"),
        debug=False,
        session_id=f"conv_hyp_{get_chat_id()}"
    )

#Error handling
def _handle_error(error) -> str:

    pattern = r'```(?!json)(.*?)```'
    match = re.search(pattern, str(error), re.DOTALL)
    if match: 
        return "The answer contained a code blob which caused the parsing to fail, i recovered the code blob. Just use it to answer the user question: " + match.group(1)
    else: 
        return llm.invoke(f"""Try to summarize and explain the following error into 1 short and consice sentence and give a small indication to correct the error: {error} """)




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
conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = HYPOTHESIS_PROMPT_TEMPLATE + template

@observe()
def invoke(input_text):
    results = conversational_agent({"input":input_text})
    return results['output']
