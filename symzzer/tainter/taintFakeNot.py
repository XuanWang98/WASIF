import json
import pickle

import symzzer.tainter.utils as utils
from symzzer.tainter.opcodes import opcodeToType
import  symzzer.logAnalyzer as logAnalyzer
from symzzer.logAnalyzer import FeedbackFactory
from z3 import *
from symzzer.setting import logger

def taint(logSample, transferEntry,currentActionId, sensitiveFuncList):
    
    taintArgument=[]  #污染数据
    flag=None
    beginfunc=False
    callsend=False
    local={}
    transfer_data = {'from': None,'to': None,'quantity': None,'memo': None}
    transfer = ['from', 'to', 'quantity', 'memo']

    if sensitiveFuncList:
        flag=True
    for line in logSample:  
        _, instr, args, types = line  
        args = utils.buildArgs(instr, args, types)
        # print('POST', args)

        if instr=='local.get':      #[124, 9, 'local.get', 2, 6458348590130003968]
            if args[0]== transferEntry:
                local.setdefault(args[3], args[4])
                if transfer and len(transfer) > args[3] and args[3]>0 :
                    key_index = args[3]-1
                    value = args[4]
                    transfer_data[transfer[key_index]] = value

        if instr == 'call':   
            funcName = FeedbackFactory().isImportFunc(args[3])           
            if funcName=='send_inline':
                callsend=True
        if instr=='i64.ne' or instr=='i64.eq':      #to==_self
            if not callsend and transfer_data and transfer_data['to'] is not None:
                if args[3].size()==args[4].size()==transfer_data['to'] :
                    if args[3]==transfer_data['to'] and args[4]==transfer_data['to']:
                        flag=False
                        break
    print( str(transfer_data) +"\n")
    print(flag)
    return flag



