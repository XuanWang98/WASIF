import json
import pickle

import symzzer.tainter.utils as utils
from symzzer.tainter.opcodes import opcodeToType
import  symzzer.logAnalyzer as logAnalyzer
from symzzer.logAnalyzer import FeedbackFactory
from z3 import *
from symzzer.setting import logger

def taint(logSample, transferEntry,out):
    taintSource=['db_get_i64','db_find_i64','db_lowerbound_i64','tapos_block_prefix','tapos_block_num','current_time']  #污染源
    flag=False
    flagSend=False
    flagAssert=False
    funclist=[]

    for line in logSample:  
        _, instr, args, types = line
        args = utils.buildArgs(instr, args, types)
        if instr == 'call':   
            funcName = FeedbackFactory().isImportFunc(args[3])
            #print('---', target, '->', funcName)
            if funcName in taintSource:
                funclist.append(funcName)
            if funcName=="send_inline":
                return True
    
            if funcName=="eosio_assert" and flagSend :
                flagAssert=True
    if flagAssert:# or "eosio_assert_message assertion failure" in out :
        if funclist :
            flag=True
                

    print(funclist,flag)
    return flag



