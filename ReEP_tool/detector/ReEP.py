import time
import sys
import os
import csv
from slither import Slither
import json
from print_pragma_version import get_solc
from manti_reen1 import d_execute
import argparse


def detect_tasks(filename,contractname,functionname,task2_payable,task3_modifier):
    slither = Slither(filename)
    contracts = slither.get_contract_from_name(contractname)
    if contracts:
        for function in contracts.functions:
            if function.name == functionname:
                if function.payable:
                    task2_payable = True

    return task2_payable,task3_modifier


def staticDetect(filename,task1_msgsender,task2_payable,task3_modifier):
    f_name1 = ""
    f_name2 = ""
    global needDetect 
    global Contract_name
    global Function_name
    print(filename)
    Result_Name = filename +'.json'
    os.system("rm -f %s" %(Result_Name))
    os.system("slither %s --detect reentrancy-eth,unrestricted-write-state,arbitrary-send,reentrancy-benign,low-level-calls --solc-disable-warnings --json %s" %(filename,Result_Name))
    with open(Result_Name) as f:
        results = json.load(f)
        if results['success']:
            if results['results'] != {}:
                detcet_list = []
                for item in results['results']['detectors']:
                    if item['check'] == "reentrancy-eth" or item['check'] == "arbitrary-send" or item['check'] == "reentrancy-benign":
                        Function_name1 = item['elements'][0]['name']
                        f_name1 = item['elements'][0]['type_specific_fields']['signature']
                        c_name1 = item['elements'][0]['type_specific_fields']['parent']['name']
                    if item['check'] == "unrestricted-write-state" or item['check'] == "low-level-calls":
                        f_name2 = item['elements'][0]['type_specific_fields']['signature']
                        detcet_list.append(f_name2)
                        task3_modifier = True
                if f_name1 != "" :
                    needDetect = True
                    task1_msgsender = True
                    Function_name = f_name1
                    print(Function_name)
                    Contract_name = c_name1
                    task2_payable,task3_modifier = detect_tasks(filename,Contract_name,Function_name1,task2_payable,task3_modifier)
                    if f_name2 != "":
                        task3_modifier = True
                else :
                    needDetect = False
                    Function_name = "NO_1"
                    Contract_name = None 
            else:
                needDetect = False
                Function_name = "NO_static"
                Contract_name = None          
        else:
            needDetect = False
            Function_name = "compile error!"
            Contract_name = None
            
    os.system("rm -f %s" %(Result_Name))
    return needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier


class ReEP:
    def __init__(self):
        
        text = "RRRRRRRRRRRRRRRRR                     EEEEEEEEEEEEEEEEEEEEEEPPPPPPPPPPPPPPPPP   \n" \
       "R::::::::::::::::R                    E::::::::::::::::::::EP::::::::::::::::P  \n" \
       "R::::::RRRRRR:::::R                   E::::::::::::::::::::EP::::::PPPPPP:::::P \n" \
       "RR:::::R     R:::::R                  EE::::::EEEEEEEEE::::EPP:::::P     P:::::P\n" \
       "  R::::R     R:::::R    eeeeeeeeeeee    E:::::E       EEEEEE  P::::P     P:::::P\n" \
       "  R::::R     R:::::R  ee::::::::::::ee  E:::::E               P::::P     P:::::P\n" \
       "  R::::RRRRRR:::::R  e::::::eeeee:::::eeE::::::EEEEEEEEEE     P::::PPPPPP:::::P \n" \
       "  R:::::::::::::RR  e::::::e     e:::::eE:::::::::::::::E     P:::::::::::::PP  \n" \
       "  R::::RRRRRR:::::R e:::::::eeeee::::::eE:::::::::::::::E     P::::PPPPPPPPP    \n" \
       "  R::::R     R:::::Re:::::::::::::::::e E::::::EEEEEEEEEE     P::::P            \n" \
       "  R::::R     R:::::Re::::::eeeeeeeeeee  E:::::E               P::::P            \n" \
       "  R::::R     R:::::Re:::::::e           E:::::E       EEEEEE  P::::P            \n" \
       "RR:::::R     R:::::Re::::::::e        EE::::::EEEEEEEE:::::EPP::::::PP          \n" \
       "R::::::R     R:::::R e::::::::eeeeeeeeE::::::::::::::::::::EP::::::::P          \n" \
       "R::::::R     R:::::R  ee:::::::::::::eE::::::::::::::::::::EP::::::::P          \n" \
       "RRRRRRRR     RRRRRRR    eeeeeeeeeeeeeeEEEEEEEEEEEEEEEEEEEEEEPPPPPPPPPP           "
       
        print(text)
        print()

        
        self.parser = argparse.ArgumentParser()
        group1 = self.parser.add_argument_group('Analysis options')
        group1.add_argument("-a", "--analyze", action="store_true", help="Search for vulnerability information")

        group2 = self.parser.add_argument_group('Vulnerability options')
        group2.add_argument("-r", "--reentrancy", action="store_true", help="Check for reentrancy vulnerabilities")

        
        self.parser.add_argument("-f", "--file", type=str, help="path to the input file")
        self.parser.add_argument("-o", "--output", type=str, default="output.txt", help="path to the output file")
        self.parser.add_argument("-c", "--contract", type=str, help="contract name")
        self.parser.add_argument("-func", "--function", type=str, help="function name")
    
    def run(self, args):
        if args.reentrancy:
            print("Check for reentrancy vulnerabilities...")
            vul_type = 'RE'
        if args.analyze:
            print("Search for vulnerability information...")
            Contract_name=""
            Function_name=""
        else:
            if args.contract and args.function:
                Contract_name = args.contract
                Function_name = args.function
            else:
                print("Error: Please provide vulnerability information (contract name & function name) with -c, -func .")
                sys.exit(1)
            
        if args.file:
            filename = args.file
            print(f"Input file: {args.file}")
        if args.output:
            result_csv = args.output
            print(f"Output file: {args.output}")
            
        start = time.time()
        state_id = 0
        needDetect = False
        is_bug = False


        task1_msgsender = False
        task2_payable = False
        task3_modifier = False
        
        solc_v = get_solc(filename)
        # os.system("solc-select use %s" %(solc_v))
        needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier = staticDetect(filename,task1_msgsender,task2_payable,task3_modifier)
        print(needDetect,Contract_name,Function_name,task1_msgsender,task2_payable,task3_modifier)
        print('Contract Name:',Contract_name)
        print('Function Name:',Function_name)

        if needDetect :
            if vul_type == 'RE':
                if (task1_msgsender == True):
                    start_d = time.time()
                    if (task3_modifier == True):
                        if task2_payable== True :
                            is_bug,state_id,_ = d_execute(filename,Contract_name,Function_name)
                        if task2_payable== False :
                            is_bug,state_id,_ = d_execute(filename,Contract_name,Function_name)
                            # is_bug = True   
                    # else :
                        # if (task3_modifier == True):
                            # is_bug = True   
                        # dir,is_bug,state_id = d_execute(filename,Contract_name,Function_name)
                        
                    end_d = time.time()
                    d_ttime = end_d-start_d
                    end = time.time()
                    ttime = end-start
                    file = open(result_csv,'a+', encoding='utf-8')
                    csv_writer = csv.writer(file)
                    row = [filename,is_bug,ttime,Function_name,Contract_name,'RE']
                    csv_writer.writerow(row)
                    os.system("rm -rf mcore*")
                else:
                    is_bug = False
                    end = time.time()
                    ttime = end-start
                    file = open(result_csv,'a+', encoding='utf-8')
                    csv_writer = csv.writer(file)
                    row = [filename,is_bug,ttime,Function_name,Contract_name,'RE']
                    csv_writer.writerow(row)
                    os.system("rm -rf mcore*")
        else:
            is_bug = False
            end = time.time()
            ttime = end-start
            file = open(result_csv,'a+', encoding='utf-8')
            csv_writer = csv.writer(file)
            row = [filename,is_bug,ttime,Function_name,Contract_name]
            csv_writer.writerow(row)
        os.system("rm -rf mcore*")
            
        
            
if __name__ == "__main__":
    tool = ReEP()
    args = tool.parser.parse_args()
    tool.run(args)




