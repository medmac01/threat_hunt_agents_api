# Utilities used by the agents app
import os
from uuid import uuid4
from langchain_community.llms.ollama import Ollama

global CHAT_ID
CHAT_ID = str(uuid4())[:6]

def set_new_chat_id():
    """
    Generates a new chat id.
    """
    CHAT_ID = str(uuid4())[:6]
    return CHAT_ID

def get_chat_id():
    """
    Returns the current chat id.
    """
    return CHAT_ID

def generate_title(input_text):
    """
    Generates a title for the input text.
    Parameters:
    input_text: (str) The input text to generate a title for.
    """

    llm = Ollama(model="openhermes", base_url=os.getenv('OLLAMA_HOST'), temperature=0.4, num_predict=512, num_ctx=1024)
    return llm.invoke(f"Generate a title for the following question: {input_text}, the title should be short and concise.")

def clear_chat(agent= None):
    """
    Clears the memory of the agent.
    Parameters:
    agent: (RouterAgent | InvestigatorAgent | HypothesisAgent) The agent to clear the memory of.
    """

    try:
        agent.clear_memory()
    except Exception as e:
        return False
    return True


def get_models():
    """
    Returns the available models.
    """

    models = {"models":[
        {"openhermes" : "OpenHermes-7B (Fast)"},
        {"codestral" : "Codestral-22B (Smart, slightly slower)"},
        {"llama3" : "Llama3-8b (Beta)"},
    ]}

    return models
