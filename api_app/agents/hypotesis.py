from typing import List
from .agent import Agent, LLM
from ..chat.utils import get_chat_id
from ..tools.elastic_tool import InternalThreatSearch
from ..chat.prompts import HYPOTHESIS_PROMPT_TEMPLATE
from langchain.agents import initialize_agent, AgentType
from langchain_community.llms.ollama import Ollama
from langchain.agents.agent import AgentExecutor

class HypothesisAgent(Agent):
    
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
            agent_type = None,
            agent_prompt = None,
            agent_verbose = True,
            agent_max_iterations = 1,
            agent_early_stopping_method = 'generate',
            agent_intermediate_steps = False,
            agent_max_execution_time = 40,
        ):

        if langfuse_session_id is None:
            langfuse_session_id = f"conv_hyp_{get_chat_id()}"


        super().__init__(
            mem_key = mem_key,
            mem_k = mem_k,
            mem_return_messages = mem_return_messages,
            langfuse_secret_key = langfuse_secret_key,
            langfuse_public_key = langfuse_public_key,
            langfuse_host = langfuse_host,
            langfuse_debug = langfuse_debug,
            langfuse_session_id = langfuse_session_id,
            agent_type = agent_type,
            agent_prompt = agent_prompt,
            agent_verbose = agent_verbose,
            agent_max_iterations = agent_max_iterations,
            agent_early_stopping_method = agent_early_stopping_method,
            agent_intermediate_steps = agent_intermediate_steps,
            agent_max_execution_time = agent_max_execution_time,
        )

    def _handle_agent_error(self, error) -> str:
            pass
    
    @property
    def tools(self):
        return [
            InternalThreatSearch().search_by_ip, 
            InternalThreatSearch().geolocate_ip, 
            InternalThreatSearch().get_summary
        ]
    
    @property
    def llm(self) -> Ollama:
        selected_llm = self.llms[LLM.OPENHERMES]
        selected_llm.temperature = 0.2
        selected_llm.num_predict = 4096
        selected_llm.system = ""
        return selected_llm

    
    @property
    def agent_type(self):
        return AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION    
    
    @property
    def cnv_agent(self) -> AgentExecutor:
        conversational_agent = initialize_agent(
            agent=self._agent_type,
            tools=self.tools,
            prompt=self._agent_prompt,
            llm=self.llm,
            verbose=self._agent_verbose,
            max_iterations=self._agent_max_iterations,
            memory=self._memory,
            early_stopping_method=self._agent_early_stopping_method,
            callbacks=[self._langfuse_handler],
            handle_parsing_errors=self._handle_agent_error,
            return_intermediate_steps=self._agent_intermediate_steps,
            max_execution_time=self._agent_max_execution_time
        )

        template = conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template
        conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = HYPOTHESIS_PROMPT_TEMPLATE + template

        return conversational_agent
    