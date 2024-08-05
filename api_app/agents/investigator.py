import re
from .agent import Agent, LLM
from ..chat.utils import get_chat_id
from ..tools.cve_avd_tool import CVESearchTool
from ..tools.misp_tool import MISPTool
from ..tools.mitre_tool import MitreTool
from ..tools.virustotal_tool import VirusTotalTool

from ..chat.prompts import INVESTIGATOR_PROMPT_TEMPLATE, INVESTIGATOR_SYSTEM_PROMPT
from langchain.agents import initialize_agent, AgentType

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
            VirusTotalTool().scanner,
            MISPTool().search,
            MISPTool().search_by_date,
            MISPTool().search_by_event_id
        ]
    
    @property
    def llm(self):
        selected_llm = self.llms[LLM.OPENHERMES]
        selected_llm.temperature = 0.25
        selected_llm.num_predict = 4096
        selected_llm.system = INVESTIGATOR_SYSTEM_PROMPT
        return selected_llm

    
    @property
    def agent_type(self):
        return AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION    

    
    @property
    def cnv_agent(self):

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
        conversational_agent.agent.llm_chain.prompt.messages[0].prompt.template = INVESTIGATOR_PROMPT_TEMPLATE + template

        return conversational_agent
    