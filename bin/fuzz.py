import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import time
import json
from func_timeout import func_timeout, FunctionTimedOut

import symzzer.setting as setting
from symzzer.utils import EOSPonserException
import symzzer.fuzzActions as fuzzActions

# if setting.mode == 0:
    # from symzzer.fuzzertestAllActionCoverageMode0 import fuzz
# else:
#     from symzzer.fuzzertestAllActionCoverage import fuzz
from symzzer.fuzzActions import fuzz
from symzzer.argumentFactory import ABIObj
from symzzer.logAnalyzer import FeedbackFactory

TIMEOUT = 5

##初始化、modify .abi、new abi、初始化参数：.wasm instrumentation、wasabi、for analysis
def init_static(contractName, pathWasm, pathABI):
    os.system(f"rm .tmpRes.txt")

    # init ./rt_info
    rtContractDir = f'{setting.pathHookContract}/{contractName}/'   #'./rt///batdappboomx/'
    os.system(f'rm -rf {setting.pathHookContract} ; mkdir {rtContractDir} -p')
    
    # modify .abi
    with open(pathABI,'r') as f:
        normalABI = json.load(f)   #把传入的abi文件加载到normalABI中
    print(pathABI)
    if 'transfer' not in [item['name'] for item in normalABI['actions']]:   #？？？？？？
        normalABI['actions'].append(        
            {"name":"transfer","type":"transfer","ricardian_contract":""}
        )
        normalABI['structs'].append(
            {"name":"transfer","base":"","fields":[{"name":"from","type":"name"},{"name":"to","type":"name"},{"name":"quantity","type":"asset"},{"name":"memo","type":"string"}]}
        )
    # new abi
    with open(f'{rtContractDir}/{contractName}.abi', 'w') as f:
        json.dump(normalABI, f)   #json.dump()可以存储。
        #json.dump(）用于json文件读写，json.dump(x,f)，x是对象，f是一个文件对象，将json字符串写入到文件中。

    # .wasm instrumentation
    os.system(f'cp {pathWasm} {setting.pathHookContract}') # original wasm
    #cp 指令用于复制文件或目录，如同时指定两个以上的文件或目录，且最后的目的地是一个已经存在的目录，则它会把前面指定的所有文件或目录复制到此目录下，若同时指定多个文件或目录，而最后的目的地并非一个已存在的目录，则会出现错误信息。
    #把'/home/wx/wasif/examples/batdappboomx/batdappboomx.wasm'复制到./.rt文件夹中
#
    # wasabi
    os.system(f'wasabi {pathWasm} ./out')
    os.system(f"mv ./{pathWasm.split('/')[-1].split('.wasm')[0]}.txt {setting.pathHookContract}/{contractName}.txt")
    os.system(f'mv ./out/*.wasm {rtContractDir}/{contractName}.wasm')
    os.system(f'rm -rf ./out')

    # for analysis
    os.system(f"mkdir {setting.pathHookContract}/rLogs/") #       raw logs
    os.system(f"mkdir {setting.pathHookContract}/pLogs/") # processed logs
    
    return ABIObj(f'{rtContractDir}/{contractName}.abi'), FeedbackFactory() #（解析后的ABI文件，）


def find_fakeNotif_atk(contractName, feedbackFactory):
    _base = f'{setting.pathHookContract}/pLogs/'
    for _fname in os.listdir(_base):
        if _fname.split('_')[1][0] != '1':
            continue
        # recovery
        with open(_base + _fname, 'r') as f:
            (logJson, entry), _, _, _ = json.load(f)

        # find atk   
        currentActionId = logJson[entry+1][2][0]
        if currentActionId != feedbackFactory.transferEntry:
            continue# keep trying

        # in first action, contract is safe with (to != self / !(to == self))
        a = feedbackFactory.name2uint64(setting.forgedNotificationAgentName)
        b = feedbackFactory.name2uint64(contractName)
        for tmpidx, item in enumerate(logJson[entry:]):
            _ , instr , args, _ = item
            if instr == 'end_function' and args[0] == currentActionId:
                # action terminated
                break
            if args[0] != currentActionId:
                # not in action
                continue

            if instr in ['i64.ne', 'i64.eq']:
                operand1 = args[3]<<32 | args[2] 
                operand2 = args[5]<<32 | args[4] 
                _res = args[6]
                if ((a, b) == (operand1, operand2) or (a, b) == (operand2, operand1)):
                    print(f'[+] Fake Notification has fix:: ' +\
                        f'action@{currentActionId}:row_{args[1]} checks to({a}) != _self({b})')
                    return tuple(args[:2] + [instr])
    return ()

def find_fakeos_atk(contractName, feedbackFactory):
    _base = f'{setting.pathHookContract}/pLogs/'
    for _fname in os.listdir(_base):
        if _fname.split('_')[1][0] not in  ('2', '3'):
            continue
    
        with open(_base + _fname, 'r') as f:
            (logJson, entry), _, _, _ = json.load(f)
            
        a = feedbackFactory.name2uint64(contractName) # [code]
        b = feedbackFactory.name2uint64("eosio.token")

        for _ , instr , args, _  in logJson[:entry]:
            if args[0] != feedbackFactory.applyFuncId:
                continue

            if instr == 'i64.eq':
                operand1 = args[3] <<32 | args[2] 
                operand2 = args[5] <<32 | args[4] 
                _res = args[6]
                if ((a, b) == (operand1, operand2) or (a, b) == (operand2, operand1)):
                    print(f'[+] Fakeos has fix:: ' +\
                        f'apply():row_{args[1]} checks code == eoso.token')
                    return tuple(args[:2] + [instr])
    return ()

##Fuzzingloop
def fuzzTimeLimiter(pathWasm,contractABI, feedbackFactory, in_atk=()):
    print("fuzzing...")
    failCnt = 8
    while failCnt > 0:
        failCnt -= 1
        try:
            retVal = func_timeout(setting.timeoutSeconds, fuzz, args=(pathWasm,contractABI, feedbackFactory, in_atk))   # 关键的执行语句！！
            # retVal = fuzz(pathWasm,contractABI, feedbackFactory, in_atk)    ##fuzz
            break
        except FunctionTimedOut:
            print(f"[-] fuzz:: Fuzzer was terminated in {setting.timeoutSeconds}s.\n")
            break
        except EOSPonserException as e:
            print(f"[-] fuzz:: No EOSPonser. Try Again")
            continue
        except Exception:
            continue
    
    
    if failCnt == 0:
        print(f"[-] fuzz:: No EOSPonser. Exit")
        exit(-1)
    if fuzzActions.hasTransfer:         
        if setting.isFakeNot != '0':
            if -11 in setting.bugSet:
                if 1 in setting.bugSet:
                    setting.bugSet.remove(1)
                # setting.bugSet.remove(-11)
                setting.bugSet = [x for x in setting.bugSet if x != -11]
            else:
                if 1 not in setting.bugSet:
                    setting.bugSet.append(1)

def main():
    isInject = False
    # CLI
    fields = ['code', 'abi', 'name', 'round', 'timeout', 'savefile', 'vuls']
    config = {f: None for f in fields} 
    config['flags'] = set()   #添加了一个set集合，里面不能包含重复的元素，接收一个list作为参数

    field_iter = iter(fields)   #iter() 函数用来生成迭代器。https://www.runoob.com/python/python-func-iter.html
    for arg in sys.argv[1:]:   #python using sys.args.py “whoami”，那么我们使用sys.argv[1]获取的就是“whoami”这个参数；第一个“arg”为：'/home/wx/wasif/examples/batdappboomx/batdappboomx.wasm'。https://blog.csdn.net/bro_two/article/details/81708193
        if arg.startswith('--'):   ##startsWith()方法用来判断当前字符串是否是以另外一个给定的子字符串“开头”的，根据判断结果返回 true 或 false。
            # '--isInjected'
            config['flags'].add(arg[2:].upper())  # 为什么是：139879781580400：'DETECT_VULS'???????????????????
        else:
            field = next(field_iter)   # next() 返回迭代器的下一个项目。从第一个“code”开始，然后是“abi”
            config[field] = arg
#
    if config['code'] is None or config['abi'] is None:
        # e.g. python -m bin.fuzz test/contracts/hello/hello.wasm test/contracts/hello/hello.abi hello 30 120 .rt/ --detect_vuls 0111
        #      python -m bin.fuzz test/contracts/hello/hello.wasm test/contracts/hello/hello.abi hello 30 120 .rt/ --detect_vuls 1000
        #      python -m bin.fuzz /home/toor/benchmark/fixed_receipt_withABI/eosbetdice11_2018-10-20_00_04_45/eosbetdice11_2018-10-20_00_04_45.wasm /home/toor/benchmark/fixed_receipt_withABI/eosbetdice11_2018-10-20_00_04_45/eosbetdice11_2018-10-20_00_04_45.abi eosbetdice11  50 120 .rt/ --detect_vuls 0100 --inject
    
        print('Usage: %s [flags] <code> <abi> <name> [round] [timeout] [savefile] [vuls]' % \
               sys.argv[0], file=sys.stderr)
        exit(-1)

    setting.contractName = config['name'] if config['name'] != 'NULL' else config['code'].split('/')[-1].split('.wasm')[0].split('_')[0].split('-')[0]
    #setting.contractName='batdappboomx'

    if 'inject'.upper() in config['flags']:
        isInject = True
        
    if config['round'] is not None:
        _t = int(config['round'])  #_t=300
        if _t != -1:
            setting.maxPeriod = _t   # setting.maxPeriod = 300
    
    if config['timeout'] is not None:
        setting.timeoutSeconds = int(config['timeout'])  #setting.timeoutSeconds = 300

    if config['savefile'] is not None:
        setting.pathHookContract = config['savefile'] + '/'   #'./rt//'
        setting.plogPath = setting.pathHookContract + '/log2.txt'  #'./rt///log2.txt'
#
    # config for the detectors  检测器配置
    if 'DETECT_VULS' in config['flags']:
        setting.detectVul = True
#python -m bin.fuzz <wasmPath> <abiPath> <contractName> <timeout> <fuzzCnt> <saveResult>
# python3 -m bin.fuzz ./examples/batdappboomx/batdappboomx.wasm ./examples/batdappboomx/batdappboomx.abi batdappboomx 300 300  ./rt/ --detect_vuls 020000
        if config['vuls'] is not None:
            # vuls 参数6的数字且最多出现一次2
            assert len(config['vuls']) == 6 and config['vuls'].count('2') <= 1, '[-] Invalid parameter for `vuls`'
            ##如果len(config['vuls']) == 6 and config['vuls'].count('2') <= 1不成立，程序会抛出AssertionError错误，报错为参数内容“[-] Invalid parameter for `vuls”
            '''
            0 : disable
            1 : enable
            2 : fast mode: stop analysis as soon as found a bug  一旦发现错误，立即停止分析
            '''
            setting.isChkOOB       = config['vuls'][0]      #0
            setting.isFakeEos      = config['vuls'][1]         #2
            setting.isFakeNot      = config['vuls'][2]         #0
            setting.isChkPems      = config['vuls'][3]        #0
            setting.isRollback     = config['vuls'][4]          #0
            setting.isBlockinfoDep = config['vuls'][5]      #0
    else:
        setting.detectVul = False     

    print("[+] Test:", setting.contractName)
    # final report for this contract
    caseReport = {
        'name': setting.contractName,
        'round':-1 ,
        'time':-1,
        'bugs':[],
        'lava_eos':(),
        'lava_notif':()
    }

    _beforeFuzzTime = time.time()   #time()返回当前时间的时间戳。

    #
    abiObj, feedbackObj = init_static(setting.contractName, config['code'], config['abi'])  #参数：batdappboomx，'/home/wx/wasif/examples/batdappboomx/batdappboomx.wasm'，'/home/wx/wasif/examples/batdappboomx/batdappboomx.abi'
    fs = {'send_inline', 'send_deferred', 'send_context_free_inline', 'cancel_deferred', 
                'db_find_i64', 'db_lowerbound_i64', 'db_get_i64',
                'db_update_i64', 'db_store_i64', 'db_remove_i64', 'db_idx64_store', 'db_idx64_update', 'db_idx64_remove', 'db_idx128_update',
                'db_idx128_store', 'db_idx128_remove', 'db_idx256_remove', 'db_idx256_store'}
    
    # for filter pm
    # if len(set(feedbackObj.importsFunc ) & fs) == 0:
    #     print("???[-] remove, ", setting.contractName)
    #     os.system(f"echo {setting.contractName} >> /tmp/pmrms")
    #     # os.system(f"rm -r {setting.contractName}")
    # else:
    #     print("???[+] use it, ", setting.contractName)
    #     print(set(feedbackObj.importsFunc ) & fs)

    fuzzTimeLimiter(config['code'],contractABI=abiObj, feedbackFactory=feedbackObj)

    
    caseReport['time'] = '%.2fs' % (time.time() - _beforeFuzzTime)   #执行时间（单位：秒）精确到小数点后两位
    caseReport['logLifes'] = [(pidx, _k - _beforeFuzzTime) for pidx, _k in setting.timePoints]
    caseReport['bugs'] = setting.bugSet
    caseReport['round'] = fuzzActions.ROUND

    if isInject:
        # fixed fakeNotif
        if 1 not in caseReport['bugs']:
            try:
                caseReport['lava_notif'] = find_fakeNotif_atk(setting.contractName, feedbackObj)
            except:
                pass

        # fixed fakeos
        if 2 not in caseReport:
            try:
                caseReport['lava_eos'] = find_fakeos_atk(setting.contractName, feedbackObj)
            except:
                pass
    
    with open(f'{setting.pathHookContract}/report.json', 'w') as f:
        json.dump(caseReport, f)
    os.system(f'rm {setting.plogPath}')
    os.system(f'mv {setting.pathHookContract}/*.wasm {setting.pathHookContract}/raw.wasm')

    if 'nostdout'.upper() not in config['flags']:
        # stdout
        if setting.isChkOOB != '0':
            print("- Checking OOB")
        if setting.isFakeEos != '0':
            print('- Checking Fakeos')
        if setting.isFakeNot != '0':
            print('- Checking FakeNotif')
        if setting.isChkPems != '0':
            print("- Checking AuthMissing")
        if setting.isBlockinfoDep != '0':
            print("- Checking BlockinfoDep")
        if setting.isRollback != '0':
            print("- Checking Rollback")

        caseReport['logLifes'] = []
        print('[+] final report:', json.dumps(caseReport, indent=4))

        filepath_result="/home/wx/wasif/result.txt"
        with open(filepath_result, 'a') as file_object:
            file_object.write(str( json.dumps(caseReport, indent=None))+"\n")

    '''
    bugs:
    1: fake notification
    2. fake eos
    3. OOB
    6. AuthMissing
    7. BlockinfoDep
    8. Rollback
    '''



if __name__ == "__main__":
    main()