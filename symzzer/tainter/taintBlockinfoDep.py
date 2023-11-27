import json
import pickle

import symzzer.tainter.utils as utils
from symzzer.tainter.opcodes import opcodeToType
import  symzzer.logAnalyzer as logAnalyzer
from symzzer.logAnalyzer import FeedbackFactory
from z3 import *
from symzzer.setting import logger

def taint(logSample, transferEntry):
    taintSource=['tapos_block_prefix','tapos_block_num','current_time']  
    taintArgument=[]  
    blocks=[]
    block=[]
    taintBlock=[]
    flag=False
    flagSend=False
    taintEndBlock=0
    converts=['i64.extend_i32_s', 'i64.extend_i32_u', 'i32.wrap_i64', 'trunc_f64_u32_s', 'i32.trunc_f32_u', 'i64.trunc_f64_s', 'i64.trunc_f64_u', 'f32.convert_i32_s', 'f32.convert_i32_u', 'f64.convert_i64_s', 'f64.convert_i64_u']
    logger.info(f'================= taintSource : {taintSource} ==========================')

    for line in logSample:  
        _, instr, args, types = line
        # if instr=='begin_block' :
        #     block=[_, instr, args]
        #     blocks.append(block)

        if instr=='end_block':
            blocks.pop()
        #print('block：'+str(blocks))

        # if instr == 'call':
        #     target = args[2]
            
        #print('PRE', args)
        args = utils.buildArgs(instr, args, types)
        
        #print('POST', args)
        if instr=='begin_block' :
            blocks.append(args)


        if instr == 'call':   #定位call指令，识别调用函数。
            callName=None
            funcName = FeedbackFactory().isImportFunc(args[3])
            #print('---', target, '->', funcName)
            # for func in taintSource:  #如果调用到了taintSource中的函数：
            #     if funcName==func :
            #         callName=func
            #         break
            if funcName in taintSource:
                if previousArgs[2]=='br_if':
                    value = simplify(previousArgs[5] ).as_long()
                    taintEndBlock = int(value)                           #[33, 430, 'br_if', 0, 8, 1818]
            if funcName=='send_inline':
                flagSend=True
                if taintBlock :
                    # if blocks[-1]==taintBlock[-1]:  
                    if blocks[-1]==taintBlock[0]:
                        flag=True
                        break
        if taintBlock:
            if instr=='end_block' :      #[33, 1818, 'end_block', 8]
                if args[1]==taintEndBlock:
                    if flagSend==True:
                        flag=True
                        break
        if instr in converts:
            # if [len(vector) == args[3] and vector == args[3] for vector in taintArgument]:
            value = simplify(args[3]).as_long()        
            integer_value = int(value)          
            if integer_value in taintArgument:
                value = simplify(args[4]).as_long()        
                integer_value = int(value) 
                taintArgument.append(integer_value)
            
        if instr=='call_post' and len(args) >= 4:  
            if funcName in taintSource:
                # taintArgument.append(args[3])
                value = simplify(args[3]).as_long()       
                integer_value = int(value)          
                taintArgument.append(integer_value)
        
        operator=opcodeToType[instr]
        if operator=='binary':  
            if taintArgument:
                if int(simplify(args[3]).as_long()) in taintArgument or int(simplify(args[4]).as_long()) in taintArgument:    
                    logger.info(f'================= Binary operation : {instr} ==========================')
                    logger.info(f'================= Number of tainted operations : {args[3]} , {args[4]} ==========================')
                    value = simplify(args[5]).as_long()
                    integer_value = int(value)
                    taintArgument.append(integer_value)
        eq=['i32.eq' ,'i64.eq' ,'i32.eqz' ,'i64.eqz' ]
        if instr in eq : 
            if args[3] in taintArgument:
                taintBlock.append(blocks[-1])
        previousArgs=args 
   
    return flag



