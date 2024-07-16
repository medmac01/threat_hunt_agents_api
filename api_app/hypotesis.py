from langchain_community.llms import Ollama

from langchain import hub

from langchain.chains.conversation.memory import ConversationBufferWindowMemory


from langchain.agents import initialize_agent, AgentType, load_tools


from dotenv import load_dotenv
import os
import re

from uuid import uuid4

from .tools.elastic_tool import InternalThreatSearch

load_dotenv(override=True)

unique_id = uuid4().hex[0:8]

os.environ["LANGCHAIN_TRACING_V2"]="true"
os.environ["LANGCHAIN_ENDPOINT"]="https://api.smith.langchain.com"
os.environ["LANGCHAIN_API_KEY"]="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"
os.environ["LANGCHAIN_PROJECT"]="hyp_agent"

llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.5, num_predict=8192, num_ctx=16384, system="""You are designed to help with a variety of tasks, ranging from answering technical questions and providing detailed explanations to offering summaries and conducting thorough cybersecurity analyses. Your role also involves preserving crucial information, such as code blocks and links, and delivering answers in a structured format.""")

alert_search_by_ip = InternalThreatSearch().search_by_ip
geolocate_ip = InternalThreatSearch().geolocate_ip
summary_alerts = InternalThreatSearch().get_summary

tools = [alert_search_by_ip, geolocate_ip, summary_alerts]

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
The tools are a little bit similar to each other, so you should be careful about which tool to use. 
The tools observations will contain the results of the tools you used, and the final answer should be a technical, well explained, and should contains as much information as possible.
""" + template

def invoke(input_text):
    results = conversational_agent({"input":input_text})
    return results['output']
