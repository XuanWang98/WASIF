import os
import sys
import json
import time
import shutil


'''
测试公网数据 /devdata/cwmdata/symzzerDataset/cleanet
'''
def run():
    file_result='/home/wx/wasif/result.txt'
    with open(file_result, 'w') as file:
        pass 
    shutil.rmtree('/home/wx/wasif/wasm2wat')
    os.mkdir('/home/wx/wasif/wasm2wat')

    _begSt = time.time()

    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print('Usage: %s <path_to_benchmark> <savefile> [count]' % \
               sys.argv[0], file=sys.stderr)
        exit(-1)

    base = sys.argv[1]
    targetDir = sys.argv[2]

    # if os.path.exists(targetDir) and len(os.listdir(targetDir)) > 0:
    #     _c = input(f"Do your want to remove {targetDir}? Y/n")
    #     if _c != 'Y':
    #         print("Do nothing, leave.")
    #         return

    if len(sys.argv) == 4 and sys.argv[3] != None:
        _cnt = int(sys.argv[3])
        if _cnt == -1:
            contractsList = os.listdir(base)
        else:
             contractsList = os.listdir(base)[:_cnt]
    else:
        contractsList = os.listdir(base)
    
    os.system(f'mkdir -p {targetDir} && rm -r {targetDir}/*')
    

    # print(contractsList)
    # exit(0)
    # tmps = os.listdir("/devdata/cwmdata/symzzerDataset/rq2/res/vul_notif/")
    #threecountry

    lastResultFile="/home/wx/ablation/noblo.txt"
    # 打开文件并读取内容
    with open(lastResultFile, 'r') as file:
        # 逐行读取文件内容
        lines = file.readlines()

    # 存储所有 "name" 字段的值
    names = []
    noti=[]
    # 遍历每一行数据，解析JSON并提取 "name" 字段的值
    for line in lines:
        try:
            data = json.loads(line)
            name = data.get("name")
            if name is not None:
                names.append(name)
        except json.JSONDecodeError:
            # 如果行不是有效的JSON数据，跳过该行
            pass
    noti=['farmeosbank1', 'hotdicegroup', 'bitsplatform', 'pizzaauction', 'eosjackslead', 'eosfantasyio', 'clubpool1111', 'eosbetgogame', 'eoswinonediv', 'eosfantasy12', 'tgememodates', 'topdapprps11', 'fateroulette', 'gigaofcolony', 'farmgamede21', 'ffgamebonus1', 'casinolordio', 'ekdholdem111', 'ekdholdem222', 'eoswagermain', 'xxxsevensxxx', 'eostimecontr', 'vipbetroll13', 'bancorc11123', 'betcityndice', 'pushtestfold', 'eoseoscrash2', 'qiulot4qiuk3', 'vagasgame111', 'wwweosswapio', 'bestppptexas', 'eospindealer', 'eosbluecarib', 'bidchextoken', 'nbasportsaaa', 'decentiumtst', 'kktest112233', 'oneplayerone', 'aaaaaaaa5555', 'magicpokerio', 'eosdaq1nswap', 'bbqbbq4bonus', 'simplemarket', 'eossicbo1111', 'ninebloxtest', 'mmmeosmmmeos', 'clubtest1111', 'pickowngames', 'eosdappdivis', 'monarchdata3', 'eoslotteryes', 'leekdaobanks', 'fastecolucky', 'lynxgametest', 'pokerkingadm', 'lynxeosgame3', 'guacamolenom', 'bancorc11151', 'cryptobento1', 'eoseoseosdev', 'egspeedtrade', 'larkgames555', 'eospokedice1', '11team1dream', 'ninebloxgame', 'mm1234mm1234', 'huobideposit', 'dgpokereosio', 'bancorc11131', 'eosmakeosmak', 'thebetxdivid', 'thedeosgames', 'teamemodream', 'dgame4eos211', 'eosriosignup', 'allbet3cards', 'bancorc11134', 'exshellhotw1', 'tazsalesaver', 'regofdapppub', 'buttonbutton', 'ewgpokergame', 'roulettegame', 'youhappyisok', 'bancorc11223', 'bancorc11213', '51buyeoscoin', 'eosdivssdice', 'aali5fkop2md', 'emmmmmmmmmmm', 'dappminebank', 'gameworldcom', 'mangohold111', 'bancorc11154', 'v5eosaccount', 'mxcexdeposit', 'kittyfishing', 'bancorc11135', 'bancorc11215', 'eospokepay11', 'eospokebulls', 'fomochatdapp', 'cmug2usdcvrt', 'zgeosdeposit', 'baccaratdev1', 'ekdholdem333', 'wdgteameosio', 'magienodepml', 'pvpgamesrock', 'gamebetbonus', 'chaingoods31', 'hezdqmrrgyge', 'bbbaaannn111', 'faireosatpvp', 'eosgoodsmall', 'banmemodream', 'bancorc11155', 'bancorc11152', 'thisisbancor', 'bidreamroute', 'faireosadmin', 'nameosmainsc', 'windiceadmin', 'bancorc11144', 'betosososos2', 'eospayserver', 'qiuguochao11', 'hello', 'mmnewaccount', 'bancorc11143', 'bancorc11145', 'leekdaoadmin', 'eospokedish2', 'liantongct14', 'batdappboomx', 'eosrush11111', 'rockpaprscis', 'zos2eoscnvrt', 'xfzbcfzlocib', 'hotdiceslot1', 'thebetxaward', 'vagasteam111', 'skrxlotteryx', 'crheroessale', 'okbetgroup11', 'bancorc11153', 'biteyebiteye', 'eosfreedgame', 'eosioforau11', 'biggamevip11', 'wineosmaster', 'betsandbacca', 'paigow555555', 'egtradeadmin']
    for contractDir in contractsList:
        try:
            # if contractDir != "frogkingking":
            #     continue

            '''
            efxstakepool
            xxxsevensxxx
            '''
            if contractDir in names:
                continue
            # if contractDir not in noti:
            #     continue
            # errorContract = ["multipante11","eosnowbpower","eosiorpsgame","ydxij","tsamhbc","iaszvvngme","fayzqtc","dxebki","inravrai","vaogs","gtjbcud","ydxi","setcode","zwuczp","erqsni","tvtundga","bryuimlwn","zrzkfvbgpz"]
            errorContract = []
            if contractDir in errorContract :
                continue
            # nopm=['newotciotest', 'duoduoiodapp', 'beltalpha21z', 'frogbestbets', 'wheelof4tune', 'jiamiwangzuo', 'magicpokerio', 'egspeedtrade', 'dbetonesicbo', 'magienodepml']
            # if contractDir not in nopm:
            #     continue
            # noti.append(contractDir)

            abiPath = False
            wasmPath = False
            contractName = contractDir.split('_')[0].split('-')[0]
            _dirBase = os.path.join(base, contractDir)
            for contractFile in os.listdir(_dirBase):
                if contractFile.endswith('.abi'):
                    abiPath = os.path.join(_dirBase, contractFile)
                if contractFile.endswith('.wasm'):
                    wasmPath = os.path.join(_dirBase, contractFile)
            
            if abiPath != False and wasmPath != False:
                fuzzTarget = './rt/'
                '''
                setting.isChkOOB       = config['vuls'][0] 
                setting.isFakeEos      = config['vuls'][1] 
                setting.isFakeNot      = config['vuls'][2] 
                setting.isChkPems      = config['vuls'][3]
                setting.isRollback     = config['vuls'][4]
                setting.isBlockinfoDep = config['vuls'][5]
                '''          
                # vul_num ="020000"    #Fake eos
                vul_num ="000002"    #Blockinfo
                # vul_num ="000200"    #ChkPems
                # vul_num ="002000"    #FakeNot
                # vul_num ="000020"    #Rollback
                # vul_num ="111111"    #All
                
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} NULL 500000 300 {fuzzTarget} --detect_vuls 200000 --nostdout' # OOB
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} {contractName} 20 20 {fuzzTarget} --detect_vuls 002000' #FAKE NOTIF
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} {contractName} 30 30 {fuzzTarget} --detect_vuls 020000'   #FAKE EOS
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} {contractName} -1 120 {fuzzTarget} --detect_vuls 011100 --inject --nostdout'   # 
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} {contractName} 300 300 {fuzzTarget} --detect_vuls 000200'   #PM
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} {contractName} 500000000 300 {fuzzTarget} --detect_vuls 000000 --nostdout'   # coverage
                cmd = f'python3 -m bin.fuzz {wasmPath} {abiPath} {contractName} 300 300 {fuzzTarget} --detect_vuls {vul_num}'   
                # cmd = f'python -m bin.fuzz {wasmPath} {abiPath} {contractName} 300000  300 {fuzzTarget} --detect_vuls 000020'   # rollback

                os.system("rm ./rt/* -r")
                if os.system(cmd) == 0:
                    os.system(f'mv {fuzzTarget} {targetDir}/{contractDir}')
                    print(f"[+] Finish and Save in {targetDir}/{contractDir}")
                else:
                    print(f"[+] An Error Occur for {fuzzTarget}")

                vul_mapping = {
                "1": "OOB: out of bounds",
                "2": "Fake eos",
                "3": "Fake notification",
                "4": "AuthMissing",
                "5": "Rollback",
                "6": "BlockinfoDep"
                }
                
                for i, digit in enumerate(vul_num):
                    if digit != "0":
                        vul = vul_mapping.get(str(i + 1))
                        if vul:
                            # 执行正在检测的漏洞操作
                            print(f"正在检测 {vul}")
                            vul_name=vul
                        else:
                            # 处理未知的数字或无效的漏洞
                            print("Unknown vulnerability")
        except Exception:
        # 如果发生任何异常，都跳过当前迭代
            continue

    

    print(f'[+] files save in {targetDir}')
    print('[+] Finish Analysis with ', "%.2f" % (time.time() - _begSt), 's')
    print('[+] Avg Times ', "%.2f" % ((time.time() - _begSt)/len(contractsList)), 's')
    # print(noti)



def analyze():
    if len(sys.argv) != 2:
        print('Usage: %s <savefile>' % \
               sys.argv[0], file=sys.stderr)
        exit(-1)
    targetDir = sys.argv[1]

    bugMap = {
        1:'fake notification',
        2:'fake eos',
        3:'OOB',
        6:'AuthMissing',
        7:'BlockinfoDep',
        8:'Rollback',
        -11:'guard notification'
    }
    result = dict()
    atk = 0
    print(f"[+] Scanned {len(os.listdir(targetDir))} contracts in total.")
    rbcnt = 0
    for contractDir in os.listdir(targetDir):
        if not os.path.exists(os.path.join(targetDir, contractDir, 'report.json')):
            # print(contractDir, '#')
            continue
        with open(os.path.join(targetDir, contractDir, 'report.json'), 'r') as f:
            _r = json.load(f)

        # if _r['lava_notif'] != []:
        #     atk += 1
        
   
    

        for bid in _r['bugs']:
            if bid == -11:
                if bid not in result:
                    result[bid] = [contractDir]
                else:
                    result[bid].append(contractDir)
            else:
                if bid not in result:
                    result[bid] = [contractDir]
                else:
                    result[bid].append(contractDir)
    if result:
        for key, val in result.items():
            print(f'[+] {bugMap[key]}: {len(val)} :\n', val, "\n")
            # print(f'- {bugMap[key]}: {len(val)} : {set(os.listdir(targetDir)) - set(val)}')
    else:
        print('- ALL Safe.')
    print(atk)


def main():
    if len(sys.argv) == 2:
        analyze()
    else:
        run()

main()
#run() 
#analyze()

