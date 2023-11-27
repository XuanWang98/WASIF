import json
import pickle

import symzzer.tainter.utils as utils
from symzzer.tainter.opcodes import opcodeToType
import  symzzer.logAnalyzer as logAnalyzer
from symzzer.logAnalyzer import FeedbackFactory
from z3 import *
from symzzer.setting import logger
import symzzer.setting as setting

def taint(logSample, transferEntry,currentActionId, sensitiveFuncList,contractName):
     
    flag=None
    beginfunc=False
    callsend=False
    local={}
    transfer_data = {'from': None,'to': None,'quantity': None,'memo': None}
    transfer = ['from', 'to', 'quantity', 'memo']
    attackerString=setting.forgedNotificationAgentName
    contract = FeedbackFactory().name2uint64(contractName)
    attacker=FeedbackFactory().name2uint64(attackerString)
    if sensitiveFuncList:
        flag=True
    for line in logSample: 
        _, instr, args, types = line  
        args = utils.buildArgs(instr, args, types)
        if instr == 'call':   
            funcName = FeedbackFactory().isImportFunc(args[3])           
            if funcName=='send_inline':
                callsend=True
        if instr=='i64.ne' or instr=='i64.eq':     
            if not callsend :#and transfer_data and transfer_data['to'] is not None:
                integer_value = int(simplify(args[3]).as_long())
                integer_value1 = int(simplify(args[4]).as_long())
                #if args[3].size()==args[4].size()==transfer_data['to'] :
                if (integer_value1==attacker and integer_value==contract) or (integer_value1==contract and integer_value==attacker):
                    flag=False
                    break
    # print( str(transfer_data) +"\n")
    print(flag)
    return flag



