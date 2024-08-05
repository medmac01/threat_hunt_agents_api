import os
from typing import Dict
from langchain_community.llms.ollama import Ollama
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langfuse.callback import CallbackHandler
from langchain.agents import AgentType

from enum import Enum


class LLM(Enum):
    CODESTRAL = 'codestral'
    LLAMA3 = 'llama3'
    OPENHERMES = 'openhermes'


class Agent:
    def __init__(
            self,
            mem_key = 'chat_history',
            mem_k = 2,
            mem_return_messages = True,
            langfuse_secret_key = None,
            langfuse_public_key = None,
            langfuse_host = None,
            langfuse_debug = False,
            langfuse_session_id = None,
            agent_type : AgentType = None,
            agent_prompt = None,
            agent_verbose = True,
            agent_max_iterations = 1,
            agent_early_stopping_method = 'generate',
            agent_intermediate_steps = False,
            agent_max_execution_time = 40,
        ):

        # Setup LLMS
        self.llms : Dict[LLM:Ollama] = {}
        for llm in LLM:
            self.llms[llm] = Ollama(
                model=llm.value,
                base_url=os.getenv('OLLAMA_HOST'),
                temperature=0.2,
                num_predict=4096,
                num_ctx=8192,
            )

        self._llm_internal : Ollama = None

        # Setup Memory
        self._memory = ConversationBufferWindowMemory(
            memory_key=mem_key,
            k=mem_k,
            return_messages=mem_return_messages
        )

        # Setup Langfuse
        if langfuse_secret_key is None:
            langfuse_secret_key = os.getenv("LANGFUSE_SECRET_KEY")
        if langfuse_public_key is None:
            langfuse_public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
        if langfuse_host is None:
            langfuse_host = os.getenv("LANGFUSE_API_URL")
        
        self._langfuse_handler = CallbackHandler(
            secret_key=langfuse_secret_key,
            public_key=langfuse_public_key,
            host=langfuse_host,
            debug=langfuse_debug,
            session_id=langfuse_session_id,
            enabled=os.getenv("LANGFUSE_ENABLE_TRACING", True)
        )

        # Setup Agent
        self._agent_type = agent_type
        self._agent_prompt = agent_prompt
        self._agent_verbose = agent_verbose
        self._agent_max_iterations = agent_max_iterations
        self._agent_early_stopping_method = agent_early_stopping_method
        self._agent_intermediate_steps = agent_intermediate_steps
        self._agent_max_execution_time = agent_max_execution_time


    def _handle_agent_error(self, error) -> str:
        raise NotImplementedError()

    @property
    def tools(self):
        return []
    
    @property   
    def llm(self):
        return self._llm_internal
    
    @llm.setter
    def llm(self, value):
        self._llm_internal = value  

    def clear_memory(self):
        return self._memory.clear()


