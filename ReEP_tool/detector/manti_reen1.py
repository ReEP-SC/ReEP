from manticore.core.plugin import Plugin
from manticore.core.smtlib.visitors import simplify
from manticore.core.workspace import *
from contextlib import contextmanager
from manticore.core.smtlib.operators import OR, NOT, AND
from manticore.core.smtlib import ConstraintSet, operators, Constant, simplify
from manticore.core.smtlib.expression import issymbolic, taint_with, get_taints
from manticore.core.plugin import Plugin
from manticore.ethereum import (ManticoreEVM,Detector,ABI)
from manticore.core.smtlib import Operators, to_constant
import pyevmasm as EVMAsm
import sys,subprocess
from func_timeout import func_timeout, FunctionTimedOut
from slither import Slither
import sys
from slither.utils.function import get_function_id

from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
import binascii
from evm_cfg_builder.cfg import CFG


class DetectReentrancySimple(Detector):
    @property
    def _context_key(self):
        return f"{self.name}.call_locations"

    def will_open_transaction_callback(self, state, tx):
        if tx.is_human:
            state.context[self._context_key] = []

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        if instruction.semantics == "CALL":
            gas = arguments[0]
            dest_address = arguments[1]
            msg_sender = state.platform.current_vm.caller
            pc = state.platform.current_vm.pc

            is_enough_gas = Operators.UGT(gas, 2300)
            if not state.can_be_true(is_enough_gas):
                return
            
            if issymbolic(dest_address) or msg_sender == dest_address:
                state.context.get(self._context_key, []).append((pc, is_enough_gas))

    def did_evm_write_storage_callback(self, state, address, offset, value):
        locs = state.context.get(self._context_key, [])

        for callpc, gas_constraint in locs:
            addr = state.platform.current_vm.address
            at_init = state.platform.current_transaction.sort == "CREATE"
            self.add_finding(
                state,
                addr,
                callpc,
                "Potential reentrancy vulnerability",
                at_init,
                constraint=gas_constraint,
            )


class DetectReentrancyAdvanced(Detector):

    def __init__(self, addresses=None, **kwargs):
        super().__init__(**kwargs)
        self._addresses = addresses

    @property
    def _read_storage_name(self):
        return "{:s}.read_storage".format(self.name)

    def will_open_transaction_callback(self, state, tx):
        if tx.is_human:
            state.context[self._read_storage_name] = set()
            state.context["{:s}.locations".format(self.name)] = dict()

    def did_close_transaction_callback(self, state, tx):
        world = state.platform

        if not tx.is_human:
            if tx.result:
                if state.can_be_true(operators.UGE(tx.gas, 2300)):
                    if (
                        self._addresses is None
                        and not world.get_code(tx.address)
                        or self._addresses is not None
                        and tx.address in self._addresses
                    ):
                        self._save_location_and_reads(state)


    def _save_location_and_reads(self, state):
        name = "{:s}.locations".format(self.name)
        locations = state.context.get(name, dict)
        world = state.platform
        address = world.current_vm.address
        pc = world.current_vm.pc
        if isinstance(pc, Constant):
            pc = pc.value
        assert isinstance(pc, int)
        at_init = world.current_transaction.sort == "CREATE"
        location = (address, pc, "Reentrancy multi-million ether bug", at_init)
        locations[location] = set(state.context[self._read_storage_name])
        state.context[name] = locations

    def _get_location_and_reads(self, state):
        name = "{:s}.locations".format(self.name)
        locations = state.context.get(name, dict)
        return locations.items()

    def did_evm_read_storage_callback(self, state, address, offset, value):
        state.context[self._read_storage_name].add((address, offset))

    def did_evm_write_storage_callback(self, state, address, offset, value):
        for location, reads in self._get_location_and_reads(state):
            for address_i, offset_i in reads:
                if address_i == address:
                    if state.can_be_true(offset == offset_i):
                        self.add_finding(state, *location)

class SensitiveStorageCFG(Plugin):
    
    def __init__(self, Jump_map=None, **kwargs):
        super().__init__(**kwargs)
        self._Jump_loc = list(Jump_map.keys())
        self._JumpDest_loc = Jump_map

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":

            if instruction.semantics == "JUMPI" :
                if instruction.pc in self._Jump_loc:
                    world.current_vm.pc = self._JumpDest_loc[instruction.pc]


class StopAtDepth(Detector):

    def will_run_callback(self, *args):
        with self.manticore.locked_context("seen_rep", dict) as reps:
            reps.clear()

    def will_decode_instruction_callback(self, state, pc):
        world = state.platform
        with self.manticore.locked_context("seen_rep", dict) as reps:
            item = (
                world.current_transaction.sort == "CREATE",
                world.current_transaction.address,
                pc,
            )
            if not item in reps:
                reps[item] = 0
            reps[item] += 1
            if reps[item] > 6:
                state.abandon()

class SkipLibCall(Detector):

    def __init__(self, Lib_function=None,Dest_loc=None, **kwargs):
        super().__init__(**kwargs)
        self._Lib_function = Lib_function
        self._Dest_loc = Dest_loc

    def _is_revert_bb(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            if inst.is_terminator:
                return False
    
    def _is_revert_bb1(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            if inst.name == "PUSH2":
                return l_dest

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":
            jupm_l = 0
            if instruction.semantics == "CALL":
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller
                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                d = state.solve_one(d)
                s_value = state.solve_one(sent_value)
                msg = "ether leak" if issymbolic(sent_value) else "external call"
                if issymbolic(dest_address):
                    if state.can_be_true(msg_sender == dest_address):
                        self.add_finding_here(
                            state,
                            f"Reachable {msg} to sender via argument",
                            constraint=msg_sender == dest_address,
                        )
                else:
                    if msg_sender == dest_address:
                        self.add_finding_here(state, f"Reachable {msg} to sender")

            if instruction.semantics == "PUSH" and instruction.operand_size == 4:

                if hex(arguments[0]) in self._Lib_function:
                    for tup in self._Dest_loc:
                        if instruction.pc == tup[0]:
                            jupm_l = tup[1]

                    world.current_vm.pc = jupm_l+3

class SkipLibCall1(Detector):

    def __init__(self, Lib_function=None,Dest_loc=None, **kwargs):
        super().__init__(**kwargs)
        self._Lib_function = Lib_function
        self._Dest_loc = Dest_loc

    def _is_revert_bb(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):

            if inst.is_terminator:
                return False
    
    def _is_revert_bb1(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            if inst.name == "PUSH2":
                l_dest = hex(inst.operand)
                return l_dest


    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        m = ManticoreEVM()

        if state.platform.current_transaction.sort != "CREATE":
            
            if instruction.semantics == "CALL":
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller
                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                d = state.solve_one(d)
                s_value = state.solve_one(sent_value)
                msg = "ether leak" if issymbolic(sent_value) else "external call"
                if issymbolic(dest_address):
                    self.add_finding_here(
                        state,
                        f"Reachable {msg} to sender via argument",
                        constraint=msg_sender == dest_address,
                    )
                    world.current_vm._pop()
                    world.current_vm._pop()
                    world.current_vm._pop()
                    world.current_vm._pop()
                    world.current_vm._pop()
                    world.current_vm._pop()
                    world.current_vm._pop()
                    world.current_vm._push(1)
                    world.current_vm.pc = world.current_vm.pc + 1
                else:
                        self.add_finding_here(state, f"Reachable {msg} to sender")
            
            if instruction.semantics == "CALLDATACOPY":
                msg = "ether leak" 
                self.add_finding_here(state, f"Reachable {msg} to sender")

                
def search_cut_loc(runtimecode):

    instruction_table = instruction_tables['istanbul']
    try:
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))
    except: #binascii.Error: Odd-length string
        runtimecode = runtimecode+'0'
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))
    lib_func_loc = []
    for l in instrs:
        if l.name  == 'STOP' and l_last.name  == 'JUMPDEST' :
            lib_func_loc.append(l_last.pc)
            l_last = l
        else:
            l_last = l
    return lib_func_loc

def search_cut_loc_mid(runtimecode):

    instruction_table = instruction_tables['istanbul']
    try:
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))
    except: #binascii.Error: Odd-length string
        initcode = initcode+'0'
        instrs = list(disassemble_all(binascii.unhexlify(runtimecode)))

    disassemble_txt = 'disassemble.txt'
    Note=open(disassemble_txt,mode='w')
    Note.write(str(instrs)+'\n') 
    for ins in instrs:
        Note.write(str(ins)+'\n') 

    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    for l in instrs:
        if l.semantics == "PUSH" and l.operand_size == 4:
            is_start = True
            func_loc = l.pc
        if l.name  == 'ISZERO' and l_last.name  == 'CALL' and is_start :
            is_front = True
        
        if l.semantics == "PUSH" and l.operand_size == 2 and is_front :
            tup = [func_loc,l.operand]
            lib_func_loc_mid.append(tup)
            l_last = l
            is_start = False
            is_front = False
        else:
            l_last = l

    return lib_func_loc_mid


def search_cut_return_use(runtimecode,function_name,lib_con_func):
    
    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    jump_dest = 0
    fun_return = False
    return_use = False
    
    instruction_table = instruction_tables['istanbul']
    cfg = CFG(runtimecode)

    for function in sorted(cfg.functions, key=lambda x: x.start_addr):
            for basic_block in sorted(function.basic_blocks, key=lambda x:x.start.pc):
                for l in basic_block.instructions:
                    if len(lib_con_func) != 0:
                        if l.semantics == "PUSH" and l.operand_size == 4 and hex(l.operand) in lib_con_func[1][1] :
                            is_start = True
                            func_loc = l.pc
                        if l.name  == 'ISZERO' and l_last.name  == 'CALL' and is_start :
                            is_front = True
                        
                        if l.semantics == "PUSH" and l.operand_size == 2 and is_front :
                            tup = [func_loc,l.operand]
                            lib_func_loc_mid.append(tup)
                            jump_dest = hex(l.operand)
                            l_last = l
                            is_start = False
                            is_front = False
                        else:
                            l_last = l
                if jump_dest != 0:
                    for outgoing_bb in sorted(basic_block.outgoing_basic_blocks(function.key), key=lambda x:x.start.pc):
                        if(hex(outgoing_bb.start.pc) == jump_dest):
                            for ins in outgoing_bb.instructions:
                                if ins.name == "MLOAD":
                                    fun_return = True
                                if ins.name == "SSTORE":
                                    return_use = True                            

    return fun_return,return_use

def run_cmd(cmd_str):
    print("[*] Executing: %s" % cmd_str)
    cmd_args = cmd_str.split()
    try:
        PIPE = subprocess.PIPE
        p = subprocess.Popen(cmd_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        return int.from_bytes(output, byteorder='big')  
    except Exception as e:
        print("run_cmd error")
        print(e)
        exit(1)

def extract_info(isMul,file_name,contract_name,lib_func_list):
    slither = Slither(file_name)
    lib_con_func = []
    lib_func_list = []
    if len(slither.contracts) > 1:
        isMul= True
        for contract in slither.contracts:
            all_functions_name = []
            for function in contract.functions:
                all_functions_name.append(hex(get_function_id(function.solidity_signature)))
            lib_con_func.append([contract.name,all_functions_name])
    lib_con_func1 = lib_con_func

    for item in lib_con_func1:
        if item[0] == contract_name:
            continue
        else:
            for f in item[1]:
                lib_func_list.append(f)



    return isMul,lib_con_func,lib_func_list




def d_execute(filename,contractname,function_Name):


    with open(filename) as f:
        source_code = f.read()

    m = ManticoreEVM()
    # m.verbosity(0)
    isMul= False
    fun_return = True
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    fun_return = False
    return_use = False
    jump_map = {}
    isMul,lib_con_func,lib_func_list = extract_info(isMul,filename,contractname,lib_func_list)
    compile_result  = m._compile(source_code,contractname)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    lib_jump_loc = search_cut_loc_mid(runtimecode)
    fun_return,_ = search_cut_return_use(runtimecode,function_Name,lib_con_func)
    fun_return = True
    if fun_return:
        l = SkipLibCall1()
        m.register_plugin(SkipLibCall1(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
        p = DetectReentrancySimple()
        m.register_detector(p)
    else :
        p = DetectReentrancySimple()
        l = SkipLibCall()
        m.register_detector(p)
        m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))

    m.register_plugin(StopAtDepth())

    
    symbolic_value = m.make_symbolic_value()
    try:
        func_timeout(30, m.multi_tx_analysis1(initcode, contract_name=contractname, args=symbolic_value,tx_limit=1,tx_preconstrain=False,tx_send_ether=True))
    except FunctionTimedOut:
        print("Function timed out after 5 seconds.")


    for state in m.all_states:
        f_value = []
        l_l = 0
        l_p = []
        is_exis = False
        findings = l.get_findings(state)
        findings1 = p.get_findings(state)

        info_l = "Reachable ether leak to sender"
        info_p = "Reentrancy multi-million ether bug"
        info_p1 = "Potential reentrancy vulnerability"
        for item in findings:
            v = item[2]
            if v == info_l:
                l_l = item[1]

        for item in findings1:
            v = item[2]
            if v == info_p or v == info_p1:
                l_p.append(item[1])
        if l_l !=0 or l_p:
            is_exis = True

        if is_exis:
            reentry_string = ABI.function_selector(function_Name)
            d = state.platform.transactions[-1].data
            funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
            funcd = state.solve_one(funcid)
            if m.generate_testcase(state, "maybe reentrancy?"):
                print("Bug found! see {}".format(m.workspace))
                fname = filename +'_'+ contractname
                newName=os.getcwd()+'/'+fname
                cmd = "mv %s %s" % (m.workspace,newName)
                run_cmd(cmd)
                file_name = newName +'/'+ '.state_id'
                with open(file_name,'r') as f1:
                    lines=f1.readlines()
                    state_id = lines[0]

                return newName,True,state_id          
        else:
             continue
    
    return m.workspace,False,0
            
def d_execute1(filename,contractname,function_Name):


    with open(filename) as f:
        source_code = f.read()

    m = ManticoreEVM()
    m.verbosity(0)
    isMul= False
    fun_return = True
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    fun_return = False
    return_use = False
    jump_map = {}

    isMul,lib_con_func,lib_func_list = extract_info(isMul,filename,contractname,lib_func_list)
    compile_result  = m._compile(source_code,contractname)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    lib_jump_loc = search_cut_loc_mid(runtimecode)
    fun_return,_ = search_cut_return_use(runtimecode,function_Name,lib_con_func)
    fun_return = True
    if fun_return:
        l = SkipLibCall1()
        m.register_plugin(SkipLibCall1(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    else :
        l = SkipLibCall()
        m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))

    m.register_plugin(StopAtDepth())

    
    symbolic_value = m.make_symbolic_value()
    m.multi_tx_analysis1(initcode, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)



    for state in m.all_states:
        f_value = []
        l_l = 0
        l_p = []
        is_exis = False
        findings = l.get_findings(state)
        info_l = "Reachable ether leak to sender"
        info_p = "Reentrancy multi-million ether bug"
        info_p1 = "Potential reentrancy vulnerability"
        for item in findings:
            v = item[2]
            if v == info_l:
                l_l = item[1]
                is_exis = True
        if is_exis:
            if len(state.platform.transactions) > 2:
                reentry_string = ABI.function_selector(function_Name)
                d = state.platform.transactions[-1].data
                funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
                funcd = state.solve_one(funcid)
                if m.generate_testcase(state, "maybe reentrancy?"):
                    print("Bug found! see {}".format(m.workspace))
                    fname = filename +'_'+ contractname
                    newName=os.getcwd()+'/'+fname
                    cmd = "mv %s %s" % (m.workspace,newName)
                    run_cmd(cmd)
                    file_name = newName +'/'+ '.state_id'
                    with open(file_name,'r') as f1:
                        lines=f1.readlines()
                        state_id = lines[0] 
                    return newName,True,state_id
            else:
                 continue                        
        else:
             continue
    
    return m.workspace,False,0





