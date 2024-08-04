import os, re
from langchain_community.llms.ollama import Ollama
from langchain.chains.conversation.memory import ConversationBufferWindowMemory
from langfuse.callback import CallbackHandler
from langchain.agents import initialize_agent, AgentType
from langchain.callbacks.streaming_stdout_final_only import FinalStreamingStdOutCallbackHandler

from langchain.tools import Tool


from langchain.agents.structured_chat.base import create_structured_chat_agent

from enum import Enum

from api_app.agents.prompts import HYPOTHESIS_PROMPT_TEMPLATE, INVESTIGATOR_SYSTEM_PROMPT, REACT_PROMPT, INVESTIGATOR_PROMPT_TEMPLATE, HERMES_SYSTEM, ROUTER_PROMPT_TEMPLATE
from api_app.agents.utils import get_chat_id

from ..tools.elastic_tool import InternalThreatSearch
from ..tools.cve_avd_tool import CVESearchTool
# from ..tools.misp_tool import MispTool
# from ..tools.coder_tool import CoderTool -------> Deprecated
from ..tools.mitre_tool import MitreTool
from ..tools.virustotal_tool import VirusTotalTool

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
            agent_type = None,
            agent_prompt = None,
            agent_verbose = True,
            agent_max_iterations = 1,
            agent_early_stopping_method = 'generate',
            agent_intermediate_steps = False,
            agent_max_execution_time = 40,
        ):

        # Setup LLMS
        self.llms = {}
        for llm in LLM:
            self.llms[llm] = Ollama(
                model=llm.value,
                base_url=os.getenv('OLLAMA_HOST'),
                temperature=0.2,
                num_predict=4096,
                num_ctx=8192,
            )

        self._llm_internal = None

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
            session_id=langfuse_session_id
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
    def _llm(self):
        return self._llm_internal
    
    @_llm.setter
    def _llm(self, value):
        self._llm_internal = value  

    def clear_memory(self):
        self._memory.clear()
        return True



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
    def _llm(self):
        llm = self.llms[LLM.OPENHERMES]
        llm.temperature = 0.2
        llm.num_predict = 4096
        llm.system = ""
        return llm

    
    @property
    def agent_type(self):
        return AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION    
    
    @property
    def cnv_agent(self):

        conversational_agent = initialize_agent(
            agent=self._agent_type,
            tools=self.tools,
            prompt=self._agent_prompt,
            llm=self._llm,
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
    
    

class InvestigationAgent(Agent):
    
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
            langfuse_session_id = f"conv_inv_{get_chat_id()}"


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
        pattern = r'```(?!json)(.*?)```'
        match = re.search(pattern, str(error), re.DOTALL)
        if match: 
            return "The answer contained a code blob which caused the parsing to fail, i recovered the code blob. Just use it to answer the user question: " + match.group(1)
        else: 
            return self.llms[LLM.OPENHERMES].invoke(f"""Try to summarize and explain the following error into 1 short and consice sentence and give a small indication to correct the error: {error} """)

    
    @property
    def tools(self):
        return [
            CVESearchTool().cvesearch,
            CVESearchTool().get_latest_cves,
            MitreTool().get_technique_by_id,
            MitreTool().get_technique_by_name,
            MitreTool().get_malware_by_name,
            MitreTool().get_tactic_by_keyword,
            VirusTotalTool().scanner
        ]
    
    @property
    def _llm(self):
        llm = self.llms[LLM.OPENHERMES]
        llm.temperature = 0.25
        llm.num_predict = 4096
        llm.system = INVESTIGATOR_SYSTEM_PROMPT
        return llm

    
    @property
    def agent_type(self):
        return AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION    

    
    @property
    def cnv_agent(self):

        conversational_agent = initialize_agent(
            agent=self._agent_type,
            tools=self.tools,
            prompt=self._agent_prompt,
            llm=self._llm,
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
        conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = INVESTIGATOR_PROMPT_TEMPLATE + template

        return conversational_agent
    
    

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
    def _llm(self):
        llm = self.llms[LLM.CODESTRAL]
        llm.temperature = 0.2
        llm.num_predict = 4096
        llm.system = HERMES_SYSTEM
        # llm.callbacks = [FinalStreamingStdOutCallbackHandler(answer_prefix_tokens=["Final", "Answer", '",', "\n" , ' "', "action", "_", "input", '":', ' "'])]
        return llm

    
    @property
    def agent_type(self):
        return AgentType.CHAT_CONVERSATIONAL_REACT_DESCRIPTION
    
    @property
    def cnv_agent(self):

        conversational_agent = initialize_agent(
            agent=self._agent_type,
            tools=self._tools,
            prompt=self._agent_prompt,
            llm=self._llm,
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
    
    