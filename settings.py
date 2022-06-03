#Settings.py for loxone_websockets_demo.py

from dotenv import load_dotenv, find_dotenv   #install package python-dotenv
import os        #to access environment variables in .env

class Env:
    prefix = None
    defaults = {}
    
    # Provide a prefix to be used, else ""
    def __init__(self, prefix):
        load_dotenv(find_dotenv())
        self.prefix = prefix
    
    def setDefaults(self, new_defaults: dict):
        self.defaults = new_defaults
    
    def __getattr__(self, name):
    # will only get called for undefined attributes
        env_found = os.getenv("{}{}".format(self.prefix, name.upper()))
        if env_found:
            return env_found
        else:
            return self.defaults[name]
        


