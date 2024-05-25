import os
import subprocess
import time
import timeout_decorator
import json
import itertools
import logging
import random
import copy
import z3
import traceback
import sys
import re
import collections

import symzzer.setting as setting
from symzzer.setting import logger

from symzzer.node import Node, PriorityQueue
from symzzer.logAnalyzer import FeedbackFactory
from symzzer.argumentFactory import ArgumentFactory, ABIObj
import symzzer.utils as utils
import threading
from symzzer.tainter.wasabiHooker import Wasabi
import symzzer.tainter.utils as taintutils
from symzzer.tainter.opcodes import opcodeToType
import symzzer.tainter.taintFakeEos  as taintFakeEos
import symzzer.tainter.taintFakeNotcopy as taintFakeNot
import symzzer.tainter.taintChkPem as taintChkPem
import symzzer.tainter.taintRollback as taintRollback
import symzzer.tainter.taintBlockinfoDep as taintBlockinfoDep

# global variable
idxPeriod = 1

DISABLE = '0'
ENABLE  = '1'
FFMODE  = '2'
ROUND = -1
hasTransfer=None
Location_sensitiveFunc = collections.namedtuple('Location', ['func', 'shift', 'sensitiveFunc'])
seneitiveLocation=[]


def executeCommand(arguments, mustExecute = False):
    cmd = ' '.join(arguments)
    print("[-] executeCommand::", cmd)
    if mustExecute:
        testRound = 16
        while testRound > 0:
            testRound -= 1
            returnValue, out = subprocess.getstatusoutput(cmd)
            print("[-] executeCommand::", returnValue, out)
            if returnValue == 1 and "Expired Transaction" in out:
                continue
                
            elif returnValue in [0, 1]:
                return returnValue, out
        return False, ""

    else:
        r, o = subprocess.getstatusoutput(cmd)
        print(o)
        return r, o


def createAccount(name, publicKey, mustExecute = False):
    #executeCommand(setting.cleosExecutable + ' create account eosio ' + name + ' ' + publicKey, mustExecute)
    executeCommand([setting.cleosExecutable, 'create', 'account', 'eosio', name, publicKey], mustExecute)

def setContract(name, contractAddress, permission, mustExecute = False):
    #executeCommand(setting.cleosExecutable + ' set contract ' + name + ' ' + contractAddress, mustExecute)
    executeCommand([setting.cleosExecutable, 'set', 'contract', name, contractAddress, '-p', permission], mustExecute=mustExecute)

def pushAction(contract, action, arguments, permission, mustExecute = False):
    print(' '.join([setting.cleosExecutable, 'push', 'action', contract, action, '\'' + arguments + '\'', '-p', permission]))
    logger.debug(' '.join([setting.cleosExecutable, 'push', 'action', contract, action, '\'' + arguments + '\'', '-p', permission])) #, '>> /dev/null 2>&1' if rpsRequired else ''
    return executeCommand([setting.cleosExecutable, 'push', 'action', 
     contract, action, '\'' + arguments + '\'', '-p', permission], mustExecute)#'--json' if rpsRequired else "--console"
     #, '' if rpsRequired else '>> /dev/null 2>&1'
    
def addCodePermission(name, mustExecute = False):
    #executeCommand(setting.cleosExecutable + ' set account permission ' + name + ' active --add-code', mustExecute)
    executeCommand([setting.cleosExecutable, 'set', 'account', 'permission', name, 'active', '--add-code'], mustExecute)

def getCurrency(account, permission, mustExecute = False):
    #executeCommand(setting.cleosExecutable + ' push action ' + contract + ' ' + action + ' \'' + arguments + '\' -p ' + permission + '@active', mustExecute)
    _, rt = executeCommand([setting.cleosExecutable, 'get', 'currency', 'balance', permission, account, 'EOS'], mustExecute)
    tmp = rt.split(' ')[0]
    return float(tmp) if tmp else 0


def initEosEnv():
    # os.system('killall nodeos')
    # os.system('killall keosd')  
    # os.system('rm -rf ' + setting.eosFilePath)
    # os.system('rm ./nodeos.log')
    # os.system("rm -rf .local/share/eosio/ /root/eosio-wallet/")
    # os.system('keosd --max-body-size 100000000 &')
    # os.system("cleos wallet create -f /root/passwd")
    # os.system('cat ~/passwd | cleos wallet unlock')
    # os.system("cleos wallet import --private-key 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
    # os.system(setting.nodeosExecutable + ' -e -p eosio\
    #                         --plugin eosio::chain_api_plugin \
    #                         --plugin eosio::http_plugin \
    #                         --plugin eosio::history_plugin \
    #                         --plugin eosio::history_api_plugin\
    #                         --access-control-allow-origin=\'*\' \
    #                         --contracts-console \
    #                         --http-validate-host=false \
    #                         --verbose-http-errors \
    #                         --max-transaction-time=1000 \
    #                         --max-body-size=102400000 \
    #                         --genesis-json genesis.json \
    #                         >> nodeos.log 2>&1 &')
    # time.sleep(2)
    # exit(0)

    # createAccount('clerk', setting.eosioTokenPublicKey, True)
    createAccount('eosio.token', setting.eosioTokenPublicKey, True)
    setContract('eosio.token', setting.eosioTokenContract, 'eosio.token@active', True)
    # print("set contract eosio.token")
    createAccount('bob', setting.eosioTokenPublicKey, True)
    addCodePermission('bob', True)

    pushAction('eosio.token', 'create', '["eosio","20000000000000.0000 EOS"]', 'eosio.token@active', True)
    pushAction('eosio.token', 'issue', '["eosio", "20000000000000.0000 EOS",""]', 'eosio@active', True)

    createAccount(setting.fakeTransferAgentName, setting.eosioTokenPublicKey, True)
    createAccount('fakeosio', setting.eosioTokenPublicKey, True)
    setContract(setting.fakeTransferAgentName, setting.eosioTokenContract, f'{setting.fakeTransferAgentName}@active', True)
    addCodePermission(setting.fakeTransferAgentName, True)
    addCodePermission('fakeosio', True)

    pushAction(setting.fakeTransferAgentName, 'create', '["fakeosio","200000000000000.0000 EOS"]', f'{setting.fakeTransferAgentName}@active', True)# fake EOS
    
    pushAction(setting.fakeTransferAgentName, 'issue', '["fakeosio", "20000000000000.0000 EOS",""]', 'fakeosio@active', True)
    
    pushAction('eosio.token', 'transfer', '["eosio","fakeosio","10000000.0000 EOS",""]', 'eosio@active', True)
    # pushAction('fake.token', 'transfer', '["e","fakeosio","10000000.0000 EOS",""]', 'eosio@active', True)
    
    createAccount('testeosfrom', setting.eosioTokenPublicKey, True)
    addCodePermission('testeosfrom', True)
    pushAction('eosio.token', 'transfer', '["eosio","testeosfrom","10000000.0000 EOS",""]', 'eosio@active', True)


    createAccount(setting.forgedNotificationTokenFromName, setting.eosioTokenPublicKey, True)
    pushAction('eosio.token', 'transfer', f'["eosio","{setting.forgedNotificationTokenFromName}","10000000.0000 EOS",""]', 'eosio@active', True)
    addCodePermission(setting.forgedNotificationTokenFromName, True)
    createAccount(setting.forgedNotificationAgentName, setting.eosioTokenPublicKey, True)
    setContract(setting.forgedNotificationAgentName, setting.atkforgContract, f'{setting.forgedNotificationAgentName}@active', True)
    pushAction(setting.forgedNotificationAgentName, 'regist', f'["{setting.contractName}"]', 'eosio@active', True)
    addCodePermission(setting.forgedNotificationAgentName, True)

  

    createAccount('atknoti', setting.eosioTokenPublicKey, True)
    setContract('atknoti', setting.atknotiContract, 'atknoti@active', True)
    addCodePermission('atknoti', True)

    # createAccount('atkrero', setting.eosioTokenPublicKey, True)
    # setContract('atkrero', setting.atkreroContract, 'atkrero@active', True)
    # addCodePermission('atkrero', True)

    if setting.useAccountPool:
        createAccount('fuzzacc1', aPublicKey, True)
        createAccount('fuzzacc2', aPublicKey, True)
        createAccount('fuzzacc3', aPublicKey, True)
        os.system('cp ./accounts.conf ' + os.getenv('HOME') + '/.local/share/eosio/')

    # init contract
    pathContract =  setting.pathHookContract + setting.contractName
    # os.system('eosio-cpp -o ' + setting.contractName+'.wasm' + ' ' + pathContract+'.cpp' + ' -DCONTRACT_NAME=\\"' + setting.contractName + '\\"')

    createAccount(setting.contractName, setting.aPublicKey)
    addCodePermission(setting.contractName)
    setContract(setting.contractName, pathContract, setting.contractName+'@active')
    

def fuzz(pathWasm, contractABI, feedbackFactory, in_atk=()):
    contractName = setting.contractName
    # tmpLogger = utils.Logger(os.getenv('HOME') + '/dynamicAnalyze/EOSFuzzer/symzzer/.tmpRes.txt')

    global idxPeriod
    global hasTransfer
    logging.info(f"{'='*20} {contractName} {'='*20}")

    testDataFactory = ArgumentFactory(contractABI, contractName)    

    initEosEnv() 

    os.system(f'rm -r {setting.logPath}* ; rm {setting.plogPath}')
    pushAction('eosio.token', 'transfer', '[ "testeosfrom", "' + setting.contractName + '","100.0000 EOS","FUZZER"]', 'testeosfrom@active', mustExecute=True)    

    feedbackFactory.getTransferEntry() 
    with open(f"{setting.pathHookContract}/actPartly.txt", 'w') as f:
        f.write( str(feedbackFactory.applyFuncId) + " " + str(feedbackFactory.transferEntry))
    transferEntry=feedbackFactory.transferEntry
    if transferEntry>0:
        hasTransfer=True

    # return False

    acceptEOSToken = False
    isFixForgedBug = False
    rejectFakeos = list()
    pmSafeActs = list()

    candidateKinds = [0, 1, 2, 3, 4]
    '''
    0: invoke one action of S
    1: fake notification payload    
    2: fake EOS payload.1  
    3: fake EOS payload.2
    4: transfer valid EOS
    '''
    global ROUND
    idxPeriod = 0
    kind = -1
    if setting.isChkOOB == FFMODE:
        kind = random.choice([0, 4])

    elif setting.isFakeEos == FFMODE:
        kind = random.choice([2, 3])


    elif setting.isFakeNot == FFMODE:
        kind = random.choice([0, 1, 4])

    pathWat=f'/home/wx/wasif/wasm2wat/{setting.contractName}.wat'
    cmd = f'wasm2wat {pathWasm} -o {pathWat}'       #wasm2wat
    returnValue, out =subprocess.getstatusoutput(cmd) 
    # print(returnValue, out)

    shift=0
    global seneitiveLocation
    with open(pathWat, "r") as file:    
        for line in file:   
            if line.lstrip().startswith("(func (;"):
                shift = 0
                func = int(re.search(r"\(func\s*\(;(\d+);", line).group(1))
            if line.lstrip().startswith("call"):
                index = ''.join(filter(str.isdigit, line))
                callName =FeedbackFactory().isImportFunc(int(index))
                if callName in setting.SensitiveFunc:
                    location = Location_sensitiveFunc(func,shift,callName)
                    seneitiveLocation.append(location)
            shift += 1
    # print("[-] seneitiveLocation :  ",seneitiveLocation)
    
    funcPriority=[]
    if any(importFunc.startswith("db") for importFunc in feedbackFactory.importsFunc) and (kind == -1 or kind==0) :  
        kind = 0
        funcIndex = dict()
        for func in testDataFactory.abi.actionNames:   
            testDataFactory.generateNewData(func, kind)  
            testArgumentStr = testDataFactory.testArgument    
            os.system(f"rm {setting.logPath}/* ; rm {setting.plogPath}")
            cmd = ' '.join(['cleos', 'push', 'action', testDataFactory.executedContractName,
                    func, '\'' + testArgumentStr + '\'', '-p', f'{testDataFactory.activeAccount}@active']) 
            returnValue, out = subprocess.getstatusoutput(cmd)  #执行命令
            feedbackFactory.processLog(1)
            funcIndex[func] = feedbackFactory.functionIndex 
        
        function_contents = {}
        func_index=-1
        with open(pathWat, "r") as file:   
            for line in file:   
                if line.lstrip().startswith("(func (;"):
                    func_index = int(re.search(r"\(func\s*\(;(\d+);", line).group(1))
                    function_contents[func_index] = []
                if "(table" in line or "(memory" in line or "(global" in line or "(export" in line:
                    break
                if func_index>0:
                    function_contents[func_index].append(line.strip())
        allFunc={}
        for name, index in funcIndex.items():  
            callIndex = []
            allFunc[name]=[]
            if index>0:
                instrs=function_contents[index] 
                for instr in instrs:
                    if 'call' in instr:
                        digits = int(''.join(filter(str.isdigit, instr)))  
                        callIndex.append(digits)
                # print(callIndex)
                for i in callIndex:     
                    if i in function_contents:
                        for j in function_contents[i]:
                            if 'call' in j:
                                digits = ''.join(filter(str.isdigit, j))
                                callIndex.append(digits)
                # print(callIndex)
                for c in callIndex:
                    funcName =FeedbackFactory().isImportFunc(int(c))   
                    allFunc[name].append(funcName) 

        priority={}
        
        for funcName ,importFuncs in allFunc.items():
            priority[funcName]=0
            for importFunc in importFuncs:
                if importFunc in setting.import_weights:    
                    priority[funcName]+=setting.import_weights[importFunc]  

        funcPriority = [key for key, value in sorted(priority.items(), key=lambda item: item[1], reverse=True) if value > 0]
        original_list = [key for key, value in sorted(priority.items(), key=lambda item: item[1], reverse=True) if value > 0]
        funcPriority = []
        for item in original_list:
            funcPriority.extend([item, item])
 
    while idxPeriod <= setting.maxPeriod:
        if len(funcPriority)>0 :#and any(item.startswith("db") for item in feedbackFactory.sensitiveFuncList ):
            funcPriority.pop(0)
        print("[+] round = ", idxPeriod)
        _fc = ":ALL"
        idxPeriod += 1

        if isFixForgedBug and 1 in candidateKinds:
            candidateKinds.remove(1)
        if acceptEOSToken and 2 in candidateKinds:
            candidateKinds.remove(2)
            candidateKinds.remove(3)
        if kind != 0:
            kind = 0
        if len(funcPriority) > 0:
            kind = 0
            _fc = funcPriority[0]
        else:
            kind = random.choice(candidateKinds)

        if setting.isChkOOB == FFMODE:
            kind = random.choice([0, 4])

        elif setting.isFakeEos == FFMODE:
            kind = random.choice([2, 3])


        elif setting.isFakeNot == FFMODE:
            kind = 1
        elif setting.isRollback == FFMODE:
            kind =0

               
        kind = 0
        _fc = "test"
        print('[-] kind = ', kind)
        testDataFactory.generateNewData(_fc, kind)   
        currentFuncName = testDataFactory.functionName
        logger.info(f'================= testing {currentFuncName} ==========================')
        testDataFactory.generateNewDataType(currentFuncName)  
        
        fbSeed = feedbackFactory.seeds(kind, currentFuncName)    
        testArgumentStr = json.dumps(fbSeed) if fbSeed != [] else testDataFactory.testArgument    

        os.system(f"rm {setting.logPath}/* ; rm {setting.plogPath}")

        cmd = ' '.join(['cleos', 'push', 'action', testDataFactory.executedContractName,
                 currentFuncName, '\'' + testArgumentStr + '\'', '-p', f'{testDataFactory.activeAccount}@active'])
        
        logger.info(cmd)  
        feedbackFactory.cmds.append(cmd)

        PriBalance = getCurrency(setting.contractName, 'eosio.token')
        atkPriBalance = getCurrency("testeosfrom", 'eosio.token')
        print('[+] Execute Cleos CMD: ', cmd)
        returnValue, out = subprocess.getstatusoutput(cmd) 
        AftBalance = getCurrency(setting.contractName, 'eosio.token')
        atkAftBalance = getCurrency("testeosfrom", 'eosio.token')
        print('[+] target currency: ', PriBalance, AftBalance)
        print('[+] atker currency: ', atkPriBalance, atkAftBalance)

        print(returnValue, out)
        
        if os.listdir(setting.logPath):
            setting.timePoints.append((int(sorted(os.listdir(setting.logPath), key=lambda fname: int(fname[4:-4]))[0][4:-4]), time.time()))
        
        print(setting.timePoints)

        os.system(f'cp {setting.logPath}/* {setting.pathHookContract}/rLogs/') # for coverage

        isExecuted = True if returnValue == 0 else False
        if 'ABI has an unsupported version' in out:
            return False
        if 'Duplicate transaction' in out or 'Expired Transaction' in out:
            continue
        if not feedbackFactory.processLog('Error' not in out):
            if kind in (2,3):
                if kind not in rejectFakeos:
                    rejectFakeos.append(kind)
                if len(rejectFakeos) == 2 and setting.isFakeEos == FFMODE:
                    return True
            if kind == 1 and setting.isFakeNot == FFMODE:
                return True
            continue

        if setting.isChkOOB != DISABLE and kind == 0 and 'out of bounds memory access' in out:
            setting.bugSet.append(3)
            return True
            # print(feedbackFactory.firstActLog[-1])
            atkFID, atkOffset, atkClen = in_atk
            # print(feedbackFactory.firstActLog[-1], '============', atkFID)
            func, offset = feedbackFactory.firstActLog[-1][2][:2]
            if func != atkFID:
                continue
            elif func == atkFID and offset == atkOffset + atkClen - 1:# crach with OUT OF BRAND
                return True

        print("+++++++++++++++++++++++++++++++++++++++++++++++++==")
        try:
            feedbackFactory.locateActionPos(index=0, txFuncName=currentFuncName)  
        except :
            print("[-] fuzzActions:: ERROR when location actions\n")
            continue

        logTuple = [feedbackFactory.firstActLog, feedbackFactory.firstActPos] # logs, line_pos
        with open(f"{setting.pathHookContract}/pLogs/{idxPeriod}_{kind}.json", 'w') as f:
            json.dump([logTuple, testDataFactory.testArgumentType, json.loads(testArgumentStr), cmd], f)
        caseInfo=feedbackFactory.caseInfo
        startPos, endPos, currentActionId, sensitiveFuncList = caseInfo
     
        if setting.detectVul:
            try:
                if setting.isChkPems != DISABLE and 6 not in setting.bugSet :
                    print("-----------------------------testing missing authorization verification ---------------")       
                    if 6 not in setting.bugSet:
                        if taintChkPem.taint(feedbackFactory.firstActLog , transferEntry,feedbackFactory.sensitiveFuncList,feedbackFactory.usedFuncList,contractName,testDataFactory.testArgument):
                            # success
                            logging.info("permission check fault")
                            setting.bugSet.append(6)
                       
                    if setting.isChkPems == FFMODE and 6 in setting.bugSet :
                        ROUND = idxPeriod
                        return True
                    # else:
                    #     pmSafeActs.append(currentFuncName)
                    #     if len(pmSafeActs) == len(testDataFactory.abi.actionNames):
                    #         return False

                if setting.isBlockinfoDep != DISABLE and 7 not in setting.bugSet :
                    print("-----------------------------testing blockinfodep ---------------")                          
                    if 7 not in setting.bugSet:
                        if taintBlockinfoDep.taint(feedbackFactory.firstActLog ,transferEntry):
                            # success
                            logging.info("Tapos Warning")
                            setting.bugSet.append(7)
                           
                    if setting.isBlockinfoDep == FFMODE and 7 in setting.bugSet :
                        ROUND = idxPeriod
                        return True
                        
                    # if (setting.isBlockinfoDep, setting.isRollback) == (ENABLE, ENABLE) \
                    #         and (7 in setting.bugSet and 8 in setting.bugSet):
                    #     return True

               
                if setting.isRollback != DISABLE and 8 not in setting.bugSet :
                    print("-----------------------------testing Rollback ---------------")                         
                    if 8 not in setting.bugSet:
                        if taintRollback.taint(feedbackFactory.firstActLog ,transferEntry,out):
                            # success
                            logging.info("Rollback Warning")
                            setting.bugSet.append(8)
                            
                    if setting.isRollback == FFMODE and 8 in setting.bugSet :
                        ROUND = idxPeriod
                        return True



                if setting.isFakeNot != DISABLE and isFixForgedBug == False and kind == 1 and hasTransfer:                              
                    if 1 not in setting.bugSet:
                        flag=taintFakeNot.taint(feedbackFactory.firstActLog ,transferEntry,currentActionId, sensitiveFuncList,contractName) 
                        if flag==False:
                            setting.bugSet.append(-11)
                            if setting.isFakeNot == FFMODE:
                                return True      
                        if flag:                     
                            setting.bugSet.append(1)                      
                    # if setting.isFakeNot == FFMODE and 1 in setting.bugSet :
                    #     print(setting.bugSet)
                    #     ROUND = idxPeriod
                    #     return True
                        

                if setting.isFakeEos != DISABLE and kind in [2, 3] and 2 not in setting.bugSet :
                    print("-----------------------------testing fake eos ---------------")           
                    if 2 not in setting.bugSet:
                        if taintFakeEos.taint(feedbackFactory.firstActLog ,transferEntry):
                            logger.info(f"Has fake transfer bug;Fake EOS kind={kind}")
                            setting.bugSet.append(2)
                           

                    if setting.isFakeEos == FFMODE and 2 in setting.bugSet :
                        ROUND = idxPeriod
                        return True
            except:
                print('[-] Scanner Error')
                traceback.print_exc()
        # if kind == 1:
        #     exit(0)

            
        if True and (kind == 0 or (kind in (1, 4) and feedbackFactory.transferEntry == feedbackFactory.caseInfo[2])):
            
            
            print('-------------------- emulator -------------------', idxPeriod)
            if setting.globalDebug:
                print("??? test argument=", testArgumentStr)
                print("??? test argument types =", testDataFactory.testArgumentType)

            cleosJson = json.loads(testArgumentStr)   
            inputType = testDataFactory.testArgumentType

            wasabi = Wasabi(inputType, cleosJson, feedbackFactory.importsFunc, feedbackFactory.firstActEntry)

            startPos, endPos, _, _ = feedbackFactory.caseInfo 
            actionLog = feedbackFactory.firstActLog[startPos-1:endPos]
            if kind==0:
                if(len(actionLog)<5):
                    testDataFactory.abi.actionNames.remove(currentFuncName)
                    continue
            for line in actionLog:
                try:
                    
                    _, instr, args, types = line
                    # print("--debug:logAll:--", instr, args, types,"STACK",wasabi.analysis.stack.peek(), cmd)
                    # print('-actFuzzer: args=',args)
                    symArgs = taintutils.buildArgs(instr, args, types)
                    # print('[-] -actFuzzer: symArgs=',symArgs)
                    # print("[-] wasabi hook-begin")
                    wasabi.lowlevelHooks(instr, symArgs)
                    # print("[-] wasabi hook-end")

                except Exception as e:
                    print('[-] EOSVM Model ERROR:', e)
                    break # drop

            # exit() @@@@@@
            print('[++] ',wasabi.analysis.queue)
            queueSolver=[]
            if len(wasabi.analysis.queue) > 1 :
                shift_values = []
                z3Solver = dict()

                for item in wasabi.analysis.queue:
                    fbTuple, _ = item
                    # print("fbTuple:", fbTuple)
                    match = re.search(r'shift=(\d+)', str(fbTuple))
                    if match:
                        shift_values.append(int(match.group(1))) 
                print(shift_values) 
            

                # for location_str in seneitiveLocation :
                for i in range(len(shift_values)) :
                    # shift = re.search(r'shift=(\d+)', str(location_str))
                    z3Solver[shift_values[i]]=[]
                    for location_str in seneitiveLocation :
                    # for i in range(len(shift_values)) :
                        shift = re.search(r'shift=(\d+)', str(location_str))
                        if i+1 < len(shift_values):
                            if  int(shift.group(1)) > shift_values[i] and int(shift.group(1)) < shift_values[i+1] :
                                # print(shift_values[i],location_str)
                                # z3Solver[shift_values[i]]=[]
                                match = re.search(r"sensitiveFunc='([^']+)'", str(location_str))
                                if match:
                                    sensitive_func_value = match.group(1)
                                    z3Solver[shift_values[i]].append(sensitive_func_value)
                                    # print("sensitiveFunc的值是:", sensitive_func_value)
                        else:
                            if int(shift.group(1)) > shift_values[i] :
                                # z3Solver[shift_values[i]]=[]
                                match = re.search(r"sensitiveFunc='([^']+)'", str(location_str))
                                if match:
                                    sensitive_func_value = match.group(1)
                                    z3Solver[shift_values[i]].append(sensitive_func_value)
                                # print(shift_values[i],location_str)
                # print(z3Solver)
                
                for key, values in z3Solver.items():

                    if 'tapos_block_prefix' in values or 'tapos_block_num' in values :#and 'send_inline' in values:
                        # print(key)                      
                        for item in wasabi.analysis.queue:
                            shift_match = re.search(r'shift=(\d+)', str(item))                         
                            if shift_match:
                                shift_value = int(shift_match.group(1))
                                if shift_value == key:
                                    queueSolver.append(item)
            threadPool = list()
            for _, constraint in queueSolver if queueSolver else wasabi.analysis.queue:
                i_context = z3.Context() 
                i_constraint = copy.deepcopy(constraint).translate(i_context)  
                thread = utils.myThread(i_constraint, i_context) 
                thread.start() 
                threadPool.append(thread)
                print('[-] threadPool : ',threadPool)
                #print(threading.active_count())
                #print(threading.enumerate())

            
            # exit()   
            z3Models = list()
            for thread in threadPool:               
                thread.join()  
                z3Models.append(thread.get_result())
            print("[-] z3Models : ",z3Models)
            print("[-] wasabi.analysis.queue : ",wasabi.analysis.queue)                    
            if queueSolver :
                seedQueue=queueSolver
            else :
                seedQueue=wasabi.analysis.queue
            for cfb, z3Model in zip([cfb for cfb, _ in seedQueue], z3Models):
           
                if z3Model == [None]:
                    continue
                try:
                    wasabi.analysis.seedMining(cfb, z3Model)
                except:
                    pass
                    # abi mismatch
            

            print("[+] =========== output new seeds ====================")
            print(wasabi.analysis.cleosArgs)
            # exit()
            newSeeds = list()
            f = lambda data, k : list(data.keys())[k]  
            for location, argPosTuple, value in wasabi.analysis.cleosArgs:
               

                if location in feedbackFactory.touchedBrs[(kind, currentFuncName)]:
                    continue

                # print('[+] New Seed Tuple:', argPosTuple, value, seed) 
                seed = cleosJson.copy()   
                layout_o, layout_i = argPosTuple
                # layout_o---0:from  1:to  2:quantity 3:memo
                key = f(cleosJson, layout_o)
                if layout_i != -1:
                    # struct
                    if setting.globalDebug:
                        print(seed, key, layout_i, '@@')
                    ikey = f(seed[key], layout_i)
                    seed[key][ikey] = value
                    if setting.globalDebug:
                        print(f"cmd={cmd} ---- newSeed={seed}, argPosTuple={argPosTuple}, value={value}")

                else:
                    seed[key] = value 

                
                newSeed = (location, seed)
                feedbackFactory.seedDict[(kind, currentFuncName)].append(newSeed)
                print(feedbackFactory.seedDict)
                feedbackFactory.touchedBrs[(kind, currentFuncName)].add(location)
                print(feedbackFactory.touchedBrs)
                print(json.dumps(seed))
                print(feedbackFactory.seedDict[currentFuncName])
                # exit()
                print('[+] newSeed generated:', newSeed)
        
            print('[+++++++++++] ============ runtime debug ================')
            for cmd in feedbackFactory.seedDict[(kind, currentFuncName)]:
                print("[+] seed Pools:", cmd, '\n') 
            # exit()
        
     
    return True
