import json
import pickle

import symzzer.tainter.utils as utils
from symzzer.tainter.opcodes import opcodeToType
import  symzzer.logAnalyzer as logAnalyzer
from symzzer.logAnalyzer import FeedbackFactory
from z3 import *
from symzzer.setting import logger

def taint(logSample, transferEntry):
    flag=True
    applyfunc=logSample[0][2][0]
    for line in logSample:  
        _, instr, args, types = line
        args = utils.buildArgs(instr, args, types)
        if args[0]==applyfunc:
            if instr=='i64.ne' or instr=='i64.eq':
                if args[4]=='6138663591592764928' or args[3]=='6138663591592764928':         
                    flag=False
                    break
    return flag


