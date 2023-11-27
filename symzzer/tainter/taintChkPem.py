import json
import pickle

import symzzer.tainter.utils as utils
from symzzer.tainter.opcodes import opcodeToType
import  symzzer.logAnalyzer as logAnalyzer
from symzzer.logAnalyzer import FeedbackFactory
from symzzer.argumentFactory import ArgumentFactory
from z3 import *
from symzzer.setting import logger

def taint(logSample, transferEntry,sensitiveFuncList,usedFuncList,contractName,testArgument):
    taintSource=['require_auth','require_auth2','has_auth']  
    taintArgument=[]  
    beginfunc=False
    callsend=False
    local={}
    print(transferEntry)
    flag=None
    funcName=''
    accountName=''
    
    parsed_data = json.loads(testArgument)
    
    first_value = next(iter(parsed_data.values()), None)
    if first_value is not None:
        # if isinstance(first_value, int):
        first_value = str(first_value)
        print(first_value)
        accountName=FeedbackFactory().name2uint64(first_value)
    print(accountName)
    contractName = FeedbackFactory().name2uint64(contractName)
    # print("*"*20)
    # testeosfrom=FeedbackFactory().uint2name(6608374120994176)
    # print(testeosfrom)
    # eosio=6458349202794610688
    # nameosio=FeedbackFactory().uint2name(eosio)
    # print(nameosio)
    
    # if sensitiveFuncList or any(item.startswith("db") for item in usedFuncList):
    if [item for item in sensitiveFuncList if not item.startswith("db_find")] or [item for item in usedFuncList if item.startswith("db") and not item.startswith("db_find")]:
        print(usedFuncList)
        logger.info(f'================= taintSource : {taintSource} ==========================')
        flag=True
    for line in logSample:  #遍历日志信息
        _, instr, args, types = line

        args = utils.buildArgs(instr, args, types)
        #print('POST', args)

        if instr=='call_indirect':
            beginfunc=True
        # if instr=='local.get':      #[125, 5, 'local.get', 1, 14605619250450998272]
        #     if beginfunc :
        #         # local.setdefault(args[3], args[4])
        #         if args[3]==1:
        #             #taintArgument.append(args[4])
        #             value = simplify(args[4]).as_long()        
        #             taintArgument.append(integer_value)

        if instr == 'call':   
            funcName = FeedbackFactory().isImportFunc(args[3])
            #print('---', target, '->', funcName)
            if funcName in taintSource:
                print(funcName)
                #if len(local)>1:
                integer_value = int(simplify(args[4]).as_long())
                testname=FeedbackFactory().uint2name(integer_value)
                print("testname:"+testname)
                if integer_value in taintArgument or integer_value==contractName or integer_value==accountName:
                    if not callsend:
                        # flag=False
                        # break
                        return False
            if funcName=='send_inline':
                callsend=True
        
                
        if instr=='call_post': 
            # if funcName in taintSource:
            if funcName=='current_receiver':
                # taintArgument.append(args[3])
                value = simplify(args[3]).as_long()        
                integer_value = int(value)          
                taintArgument.append(integer_value)
                    
    print("flag：",flag)
    return flag



