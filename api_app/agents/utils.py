# Utilities used by the agents app

from uuid import uuid4

global CHAT_ID
CHAT_ID = str(uuid4())[:6]

def set_new_chat_id():
    CHAT_ID = str(uuid4())[:6]
    return CHAT_ID

def get_chat_id():
    return CHAT_ID