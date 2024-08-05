from .agent import Agent, LLM
from langchain.agents import AgentType
from ..chat.prompts import ROUTER_PROMPT_TEMPLATE, HERMES_SYSTEM
from ..chat.utils import get_chat_id
from langchain.agents import initialize_agent, AgentType

class RouterAgent(Agent):
    
    def __init__(
            self,
            mem_key = 'chat_history',
            mem_k = 5,
            mem_return_messages = True,
            langfuse_secret_key = None,
            langfuse_public_key = None,
            langfuse_host = None,
            langfuse_debug = False,
            langfuse_session_id = None,
            agent_type = None,
            agent_prompt = None,
            agent_verbose = False,
            agent_max_iterations = 5,
            agent_early_stopping_method = 'generate',
            agent_intermediate_steps = False,
            agent_max_execution_time = 40,
        ):

        self._tools = []

        if langfuse_session_id is None:
            langfuse_session_id = f"conv_router_{get_chat_id()}"


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
        return self._tools
    
    @tools.setter
    def tools(self, value):
        self._tools = value

    @property
    def llm(self):
        selected_llm = self.llms[LLM.CODESTRAL]
        selected_llm.temperature = 0.2
        selected_llm.num_predict = 4096
        selected_llm.system = HERMES_SYSTEM
        # llm.callbacks = [FinalStreamingStdOutCallbackHandler(answer_prefix_tokens=["Final", "Answer", '",', "\n" , ' "', "action", "_", "input", '":', ' "'])]
        return selected_llm
    
    
    @property
    def agent_type(self):
        return AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION
    
    @property
    def cnv_agent(self):

        conversational_agent = initialize_agent(
            agent=self._agent_type,
            tools=self._tools,
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

        conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = ROUTER_PROMPT_TEMPLATE


        return conversational_agent
    
    