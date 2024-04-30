from langchain.tools import tool
from langchain_community.llms import Ollama

import os
from dotenv import load_dotenv
load_dotenv(override=True)

wrn = Ollama(model="wrn", base_url=os.getenv('OLLAMA_HOST'), num_predict=512, temperature=0.2,
             system="""
    You are a coder and you are trying to generate a code snippet based on a given prompt.
    The code snippet should be in the programming language that's asked for.
    Don't Wrap the function in a markdown code block. Return it as a text.
""")


class CoderTool():
  @tool("Code Generation Tool")
  def code_generation_tool(prompt: str, language: str = "python"):
    """The code generation tool is a tool that can generate code snippets based on a given prompt. 
    It uses a language model to generate code snippets that are relevant to the given prompt.
    Parameters:
    - prompt: The prompt for which the code snippet should be generated.
    - language: The programming language in which the code snippet should be generated. Default is python.
    Returns:
    - A code snippet generated based on the given prompt.
    """

    print(prompt)
    response = wrn.invoke(prompt)
    response = response.replace("```", "")
    return f"'{response}'"