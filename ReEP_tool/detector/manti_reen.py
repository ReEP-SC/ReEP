from manticore.core.plugin import Plugin
from manticore.core.smtlib.visitors import simplify
import hashlib
import logging
from manticore.core.workspace import *
from contextlib import contextmanager
from manticore.core.smtlib.operators import OR, NOT, AND
from manticore.core.smtlib import ConstraintSet, operators, Constant, simplify
from manticore.core.smtlib.expression import issymbolic, taint_with, get_taints
# from manticore.utils.helpers import istainted, issymbolic, taint_with, get_taints
from manticore.core.plugin import Plugin
from manticore.ethereum import (ManticoreEVM,Detector,ABI)
from manticore.core.smtlib import Operators, to_constant
import pyevmasm as EVMAsm
import sys,subprocess
import time
from binascii import unhexlify, hexlify
from func_timeout import func_set_timeout

from contract_count import extract_info
from pyevmasm import instruction_tables, disassemble_hex, disassemble_all, assemble_hex
import binascii

################ Script #######################

class DetectReentrancySimple(Detector):
    """
    Simple detector for reentrancy bugs.
    Alert if contract changes the state of storage (does a write) after a call with >2300 gas to a user controlled/symbolic
    external address or the msg.sender address.
    """

    # ARGUMENT = "reentrancy"
    # HELP = "Reentrancy bug"
    # IMPACT = DetectorClassification.HIGH
    # CONFIDENCE = DetectorClassification.HIGH

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

            # flag any external call that's going to a symbolic/user controlled address, or that's going
            # concretely to the sender's address
            if issymbolic(dest_address) or msg_sender == dest_address:
                state.context.get(self._context_key, []).append((pc, is_enough_gas))

    def did_evm_write_storage_callback(self, state, address, offset, value):
        locs = state.context.get(self._context_key, [])

        # if we're here and locs has stuff in it. by definition this state has
        # encountered a dangerous call and is now at a write.
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
    """
    Detector for reentrancy bugs.
    Given an optional concrete list of attacker addresses, warn on the following conditions.
    1) A _successful_ call to an attacker address (address in attacker list), or any human account address
    (if no list is given). With enough gas (>2300).
    2) A SSTORE after the execution of the CALL.
    3) The storage slot of the SSTORE must be used in some path to control flow
    """

    # ARGUMENT = "reentrancy-adv"
    # HELP = "Reentrancy bug (different method)"
    # IMPACT = DetectorClassification.HIGH
    # CONFIDENCE = DetectorClassification.HIGH

    def __init__(self, addresses=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._addresses = addresses

    @property
    def _read_storage_name(self):
        return "{:s}.read_storage".format(self.name)

    def will_open_transaction_callback(self, state, tx):
        # Reset reading log on new human transactions
        if tx.is_human:
            state.context[self._read_storage_name] = set()
            state.context["{:s}.locations".format(self.name)] = dict()

    def did_close_transaction_callback(self, state, tx):
        world = state.platform
        # Check if it was an internal tx
        if not tx.is_human:
            # Check is the tx was successful
            if tx.result:
                # Check if gas was enough for a reentrancy attack
                if state.can_be_true(operators.UGE(tx.gas, 2300)):
                # if tx.gas > 2300:
                    # Check if target address is attaker controlled
                    if (
                        self._addresses is None
                        and not world.get_code(tx.address)
                        or self._addresses is not None
                        and tx.address in self._addresses
                    ):
                        # that's enough. Save current location and read list
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
        # if in potential DAO check that write to storage values read before
        # the "send"
        for location, reads in self._get_location_and_reads(state):
            for address_i, offset_i in reads:
                if address_i == address:
                    if state.can_be_true(offset == offset_i):
                        self.add_finding(state, *location)

class KeepOnlyIfStorageChanges(Plugin):
    """This plugin discards all transactions that results in states where
    the underlying EVM storage did not change or in other words,
    there were no writes to it.
    This allows to speed-up EVM engine exploration as we don't
    explore states that have the same storage (contract data).
    However, keep in mind that if the (contract) code relies on
    account balance and the balance is not a symbolic value
    it might be that a certain state will not be covered by the
    execution when this plugin is used.
    """

    def did_open_transaction_callback(self, state, tx, *args):
        """We need a stack. Each tx (internal or not) starts with a "False" flag
        denoting that it did not write anything to the storage
        """
        state.context["written"].append(False)

    def did_close_transaction_callback(self, state, tx, *args):
        """When a tx (internal or not) is closed a value is popped out from the
        flag stack. Depending on the result if the storage is not rolled back the
        next flag in the stack is updated. Not that if the a tx is reverted the
        changes it may have done on the storage will not affect the final result.
        """
        flag = state.context["written"].pop()
        if tx.result in {"RETURN", "STOP"}:
            code_written = (tx.result == "RETURN") and (tx.sort == "CREATE")
            flag = flag or code_written
            # As the ether balance of any account can be manipulated beforehand
            # it does not matter if a state can affect the balances or not.
            # The same reachability should be obtained as the account original
            # balances must be symbolic and free-ish
            if not flag:
                ether_sent = state.can_be_true(tx.value != 0)
                flag = flag or ether_sent
            state.context["written"][-1] = state.context["written"][-1] or flag

    def did_evm_write_storage_callback(self, state, *args):
        """Turn on the corresponding flag is the storage has been modified.
        Note: subject to change if the current transaction is reverted"""
        state.context["written"][-1] = True

    def will_run_callback(self, *args):
        """Initialize the flag stack at each human tx/run()"""
        for st in self.manticore.ready_states:
            st.context["written"] = [False]

    def did_run_callback(self):
        """When  human tx/run just ended remove the states that have not changed
        the storage"""
        with self.manticore.locked_context("ethereum.saved_states", list) as saved_states:
            # Normally the ready states are consumed and forked, eth save the
            # states that finished ok in a special context list. This list will
            # compose the ready states for the next human transaction.
            # The actual "ready_states" list at this point contain the states
            # that have not finished the previous TX due to a timeout. Those will
            # be ignored.
            for state_id in list(saved_states):
                st = self.manticore._load(state_id)
                if not st.context["written"][-1]:
                    if st.id in self.manticore._ready_states:
                        self._publish(
                            "will_transition_state",
                            state_id,
                            StateLists.ready,
                            StateLists.terminated,
                        )
                        self.manticore._ready_states.remove(st.id)
                        self.manticore._terminated_states.append(st.id)
                        self._publish(
                            "did_transition_state",
                            state_id,
                            StateLists.ready,
                            StateLists.terminated,
                        )
                    saved_states.remove(st.id)

    def generate_testcase(self, state, testcase, message):
        with testcase.open_stream("summary") as stream:
            if not state.context.get("written", (False,))[-1]:
                stream.write(
                    "State was removed from ready list because the last tx did not write to the storage"
                )

class StopAtDepth(Detector):
    """This just aborts explorations that are too deep"""

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

class SkipRevertBasicBlocks(Plugin):
    def _is_revert_bb(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            if inst.name == "REVERT":
                return True
            if inst.is_terminator:
                return False

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":

            if instruction.semantics == "JUMPI":

                # if the bb after the jumpi ends ina revert do not explore it.
                if self._is_revert_bb(state, world.current_vm.pc + instruction.size):
                    state.constrain(arguments[1] == True)
                    # print("jumpi位置1：",world.current_vm.pc,instruction.size,arguments[0],arguments[1])

                # if the target of the jumpi ends up in a revert avoid it
                if self._is_revert_bb(state, arguments[0]):
                    state.constrain(arguments[1] == False)
                    # print("jumpi位置2：",arguments[0])

                # This may have added an impossible constraint.


class SkipLibCall(Detector):

    def __init__(self, Lib_function=None,Dest_loc=None, **kwargs):
        super().__init__(**kwargs)
        # TODO Check addresses are normal accounts. Heuristics implemented here
        # assume target addresses wont execute code. i.e. won't detect a Reentrancy
        # attack in progess but only a potential attack
        self._Lib_function = Lib_function
        self._Dest_loc = Dest_loc

    def _is_revert_bb(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            # is_REVERT = 0
            while True:
                # print(to_constant(world.current_vm.read_code(_pc)[0]))
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            print("inst.name",inst.name)
            # if inst.name == "REVERT":
            #     return hex(inst.pc)
            
            # else :
            #     return 0
                # return True
            if inst.is_terminator:
                print("基本块边界：",inst.pc,inst.name)
                return False
    
    def _is_revert_bb1(self, state, pc):
        world = state.platform

        def read_code(_pc=None):
            # is_REVERT = 0
            while True:
                yield to_constant(world.current_vm.read_code(_pc)[0])
                _pc += 1

        for inst in EVMAsm.disassemble_all(read_code(pc), pc):
            if inst.name == "PUSH2":
                l_dest = hex(inst.operand)
                print("push2对应的跳转地址：",l_dest)
                return l_dest

    def will_evm_execute_instruction_callback(self, state, instruction, arguments):
        world = state.platform
        if state.platform.current_transaction.sort != "CREATE":
            jupm_l = 0
            if instruction.semantics == "CALL":
                dest_address = arguments[1]
                sent_value = arguments[2]
                msg_sender = state.platform.current_vm.caller

                            # world = state.platform
                curr_tx = world.current_transaction
                d = curr_tx.data[:4]
                d = state.solve_one(d)
                s_value = state.solve_one(sent_value)
                print(s_value,d)
                msg = "ether leak" if state.can_be_true(sent_value != 0) else "external call"

                if issymbolic(dest_address):
                    # We assume dest_address is symbolic because it came from symbolic tx data (user input argument)
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
                # if hex(arguments[0]) == self._Lib_function:
                    print("arguments[0]:",hex(arguments[0]))
                    # print("jumpi位置2：",world.current_vm.pc + instruction.size)
                    # if the bb after the jumpi ends ina JUMPI
                    # pc1 = self._is_revert_bb1(state, world.current_vm.pc + instruction.size)
                    # print("push2的地址：：",int(pc1,16))
                    for tup in self._Dest_loc:
                        if instruction.pc == tup[0]:
                            jupm_l = tup[1]

                    # if pc1 != 0:
                        # world.current_vm.pc = int(pc1,16)
                    print(jupm_l)

                    # 根据字节码的特点，需要将栈内的元素推出
                    world.current_vm.pc = jupm_l+3
                    # world.current_vm.pc = 1072    #141   #0x8d




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
            print(l_last.pc)
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

# ________________________________________________________________________

    disassemble_txt = 'disassemble.txt'
    Note=open(disassemble_txt,mode='w')
    Note.write(str(instrs)+'\n') 
    for ins in instrs:
        Note.write(str(ins)+'\n') 
# _________________________________________________
    lib_func_loc_mid = []
    is_start = False
    is_front = False
    func_loc = 0
    for l in instrs:
        if l.semantics == "PUSH" and l.operand_size == 4 and hex(l.operand) == "0x4c2f04a4" :
            is_start = True
            print("打开开关")
            func_loc = l.pc
        # Instruction(0x14, 'EQ', 0, 2, 1, 3, 'Equality comparision.', None, 0)
        if l.name  == 'ISZERO' and l_last.name  == 'CALL' and is_start :
            # print(hex(i-1))
            is_front = True
        
        if l.semantics == "PUSH" and l.operand_size == 2 and is_front :
            # print(instrs.index(l))
            # instrs.index(l)+3 表示在ISZERO后的第三个指令的PUSH指令，其对应的元素为跳转目标地址
            # print(hex(l_j.operand))
            # print(l.operand)
            tup = [func_loc,l.operand]
            print(tup)
            lib_func_loc_mid.append(tup)
            l_last = l
            is_start = False
            is_front = False
            print("关闭开关")
        else:
            l_last = l

    # print(lib_func_loc_mid)

    return lib_func_loc_mid

def run_cmd(cmd_str):
    print("[*] Executing: %s" % cmd_str)
    cmd_args = cmd_str.split()
    try:
        PIPE = subprocess.PIPE
        p = subprocess.Popen(cmd_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        # //只会检查返回值是否为整数
        return int.from_bytes(output, byteorder='big')  
    except Exception as e:
        print("run_cmd error")
        print(e)
        exit(1)






def d_execute(filename,contractname,function_Name):


    with open(filename) as f:
        source_code = f.read()

    m = ManticoreEVM()

    isMul= False
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    isMul,_,lib_func_list = extract_info(isMul,filename,contractname,lib_func_list)
    compile_result  = m._compile(source_code,contractname)
    #  (name, source_code, bytecode, runtime, srcmap, srcmap_runtime, hashes, abi, warnings)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    print(runtimecode)
    # lib_jump_loc = search_cut_loc(runtimecode)
    lib_jump_loc = search_cut_loc_mid(runtimecode)

    # m.verbosity(0)
    p = DetectReentrancyAdvanced()
    # p= DetectReentrancySimple()
    l = SkipLibCall()
    m.register_detector(p)
    # m.register_detector(l)
    m.register_plugin(StopAtDepth())
    # m.register_plugin(KeepOnlyIfStorageChanges())
    # m.register_plugin(SkipRevertBasicBlocks())
    # m.register_plugin(SkipLibCall(Lib_function=lib_func_list))
    m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    # Dest_loc： 8d d0 f0 107 134 154
    
    # print(initcode.hex())
    # print(hex(int(initcode).encode()))
    # yes
    # initcode = '0x608060405234801561001057600080fd5b5061062b806100206000396000f300608060405260043610610083576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063303b93791461008f5780633fe43822146100d25780635daa87a0146100f2578063640d30171461010957806365f3c31a146101365780637731cd2a14610156578063c2808d1a146101b4575b61008d60006101df565b005b34801561009b57600080fd5b506100d0600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610367565b005b6100f0600480360381019080803590602001909291905050506103c5565b005b3480156100fe57600080fd5b50610107610594565b005b34801561011557600080fd5b50610134600480360381019080803590602001909291905050506105b1565b005b610154600480360381019080803590602001909291905050506101df565b005b34801561016257600080fd5b50610197600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506105d5565b604051808381526020018281526020019250505060405180910390f35b3480156101c057600080fd5b506101c96105f9565b6040518082815260200191505060405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090503481600101600082825401925050819055508060000154824201111561024d5781420181600001819055505b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff165b00634c2f04a433346040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200180602001828103825260038152602001807f50757400000000000000000000000000000000000000000000000000000000008152506020019350505050600060405180830381600087803b15801561034b57600080fd5b505af115801561035f573d6000803e3d6000fd5b505050505050565b600260149054906101000a900460ff161561038157600080fd5b80600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000209050600154816001015410158015610421575081816001015410155b80156104305750806000015442115b15610590573373ffffffffffffffffffffffffffffffffffffffff168260405160006040518083038185875af1925050501561058f57818160010160008282540392505081905550600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff5b001673ffffffffffffffffffffffffffffffffffffffff16634c2f04a433846040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200180602001828103825260078152602001807f436f6c6c656374000000000000000000000000000000000000000000000000008152506020019350505050600060405180830381600087803b15801561057657600080fd5b505af115801561058a573d6000803e3d6000fd5b505050505b5b5050565b6001600260146101000a81548160ff021916908315150217905550565b600260149054906101000a900460ff16156105cb57600080fd5b8060018190555050565b60006020528060005260406000206000915090508060000154908060010154905082565b600154815600a165627a7a723058206cbd5234fc1d50b43c72642c4074e1a0c1e193d4e8f23d8754810bcd54'
    # initcode = initcode.encode()
    symbolic_value = m.make_symbolic_value()
    # m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True,libraries=[("LogFile",0x30000)])
    # m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True)
    m.multi_tx_analysis1(initcode, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)
    # # state = next(m.ready_states)  



    for state in m.all_states:
        f_value = []
        l_l = 0
        l_p = []
        is_exis = False
        findings = l.get_findings(state)
        findings1 = p.get_findings(state)
        print("lllll",findings)
        print("ppppp",findings1)


        info_l = "Reachable ether leak to sender"
        info_p1 = "Reentrancy multi-million ether bug"
        info_p = "Potential reentrancy vulnerability"
        for item in findings:
            v = item[2]
            if v == info_l:
                l_l = item[1]

        for item in findings1:
            v = item[2]
            if v == info_p or v == info_p1:
                l_p.append(item[1])
        if l_l in l_p:
            is_exis = True

    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        # retval_array = state.platform.transactions[-1].return_data
        # retval = operators.CONCAT(256, *retval_array)
        # if m.generate_testcase(state, "return can be 0", only_if=retval == 0):
        #     expected_files = {"user_00000000." + ext for ext in ("summary", "constraints", "pkl", "tx.json", "tx", "trace", "logs")}
        #     expected_files.add("state_00000000.pkl")
        #     print("Bug found! see {}".format(m.workspace))
    
   # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        if is_exis:
            if len(state.platform.transactions) > 2:
                reentry_string = ABI.function_selector(function_Name)
                d = state.platform.transactions[-1].data
                funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
                funcd = state.solve_one(funcid)
                print(funcd,reentry_string,findings)
                if m.generate_testcase(state, "maybe reentrancy?", only_if=funcd == reentry_string):
                    expected_files = {"user_00000000." + ext for ext in ("summary", "tx.json", "tx", "trace","findings")}
                    print(funcd,reentry_string,findings)
                    print("Bug found! see {}".format(m.workspace))
                    fname = filename +'_'+ contractname
                    newName="/home/wangzexu/manticore_pro/manticore-0.3.0/examples/evm_reentrancy/"+fname
                    os.rename(m.workspace,newName)
                    file_name = newName +'/'+ '.state_id'
                    with open(file_name,'r') as f1:
                        lines=f1.readlines()
                        state_id = lines[0]
                        # print(state_id)      
                    return newName,True,state_id
            else:
                 continue                        
        else:
             continue
    
    return m.workspace,False,0
            
@func_set_timeout(300)
def d_execute1(filename,contractname,function_Name):


    with open(filename) as f:
        source_code = f.read()

    m = ManticoreEVM()

    isMul= False
    lib_con_func = []
    lib_func_list = []
    lib_jump_loc = []
    isMul,_,lib_func_list = extract_info(isMul,filename,contractname,lib_func_list)
    compile_result  = m._compile(source_code,contractname)
    #  (name, source_code, bytecode, runtime, srcmap, srcmap_runtime, hashes, abi, warnings)
    initcode = compile_result[2]
    runtimecode = compile_result[3].hex()
    print(runtimecode)
    # lib_jump_loc = search_cut_loc(runtimecode)
    lib_jump_loc = search_cut_loc_mid(runtimecode)

    # m.verbosity(0)
    # p = DetectReentrancyAdvanced()
    # p= DetectReentrancySimple()
    l = SkipLibCall()
    # m.register_detector(p)
    # m.register_detector(l)
    m.register_plugin(StopAtDepth())
    # m.register_plugin(KeepOnlyIfStorageChanges())
    # m.register_plugin(SkipRevertBasicBlocks())
    # m.register_plugin(SkipLibCall(Lib_function=lib_func_list))
    m.register_plugin(SkipLibCall(Lib_function=lib_func_list,Dest_loc=lib_jump_loc))
    # Dest_loc： 8d d0 f0 107 134 154
    
    # print(initcode.hex())
    # print(hex(int(initcode).encode()))
    # yes
    # initcode = '0x608060405234801561001057600080fd5b5061062b806100206000396000f300608060405260043610610083576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063303b93791461008f5780633fe43822146100d25780635daa87a0146100f2578063640d30171461010957806365f3c31a146101365780637731cd2a14610156578063c2808d1a146101b4575b61008d60006101df565b005b34801561009b57600080fd5b506100d0600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610367565b005b6100f0600480360381019080803590602001909291905050506103c5565b005b3480156100fe57600080fd5b50610107610594565b005b34801561011557600080fd5b50610134600480360381019080803590602001909291905050506105b1565b005b610154600480360381019080803590602001909291905050506101df565b005b34801561016257600080fd5b50610197600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506105d5565b604051808381526020018281526020019250505060405180910390f35b3480156101c057600080fd5b506101c96105f9565b6040518082815260200191505060405180910390f35b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090503481600101600082825401925050819055508060000154824201111561024d5781420181600001819055505b600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff165b00634c2f04a433346040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200180602001828103825260038152602001807f50757400000000000000000000000000000000000000000000000000000000008152506020019350505050600060405180830381600087803b15801561034b57600080fd5b505af115801561035f573d6000803e3d6000fd5b505050505050565b600260149054906101000a900460ff161561038157600080fd5b80600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000209050600154816001015410158015610421575081816001015410155b80156104305750806000015442115b15610590573373ffffffffffffffffffffffffffffffffffffffff168260405160006040518083038185875af1925050501561058f57818160010160008282540392505081905550600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff5b001673ffffffffffffffffffffffffffffffffffffffff16634c2f04a433846040518363ffffffff167c0100000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200180602001828103825260078152602001807f436f6c6c656374000000000000000000000000000000000000000000000000008152506020019350505050600060405180830381600087803b15801561057657600080fd5b505af115801561058a573d6000803e3d6000fd5b505050505b5b5050565b6001600260146101000a81548160ff021916908315150217905550565b600260149054906101000a900460ff16156105cb57600080fd5b8060018190555050565b60006020528060005260406000206000915090508060000154908060010154905082565b600154815600a165627a7a723058206cbd5234fc1d50b43c72642c4074e1a0c1e193d4e8f23d8754810bcd54'
    # initcode = initcode.encode()
    symbolic_value = m.make_symbolic_value()
    # m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True,libraries=[("LogFile",0x30000)])
    # m.multi_tx_analysis(filename, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=True,tx_use_coverage=True,tx_send_ether=True)
    m.multi_tx_analysis1(initcode, contract_name=contractname, args=symbolic_value,tx_limit=2,tx_preconstrain=False,tx_use_coverage=True,tx_send_ether=True)
    # # state = next(m.ready_states)  



    for state in m.all_states:
        f_value = []
        l_l = 0
        l_p = []
        is_exis = False
        findings = l.get_findings(state)
        # findings1 = p.get_findings(state)
        print("lllll",findings)
        # print("ppppp",findings1)


        info_l = "Reachable ether leak to sender"
        info_p1 = "Reentrancy multi-million ether bug"
        info_p = "Potential reentrancy vulnerability"
        for item in findings:
            v = item[2]
            if v == info_l:
                l_l = item[1]
                is_exis = True

        # for item in findings1:
        #     v = item[2]
        #     if v == info_p or v == info_p1:
        #         l_p.append(item[1])
        # if l_l in l_p:
        #     is_exis = True

    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        # retval_array = state.platform.transactions[-1].return_data
        # retval = operators.CONCAT(256, *retval_array)
        # if m.generate_testcase(state, "return can be 0", only_if=retval == 0):
        #     expected_files = {"user_00000000." + ext for ext in ("summary", "constraints", "pkl", "tx.json", "tx", "trace", "logs")}
        #     expected_files.add("state_00000000.pkl")
        #     print("Bug found! see {}".format(m.workspace))
    
   # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        if is_exis:
            if len(state.platform.transactions) > 2:
                reentry_string = ABI.function_selector(function_Name)
                d = state.platform.transactions[-1].data
                funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
                funcd = state.solve_one(funcid)
                print(funcd,reentry_string,findings)
                if m.generate_testcase(state, "maybe EL?"):
                    expected_files = {"user_00000000." + ext for ext in ("summary", "tx.json", "tx", "trace","findings")}
                    print(funcd,reentry_string,findings)
                    print("Bug found! see {}".format(m.workspace))
                    fname = filename +'_'+ contractname
                    newName=os.getcwd()+'/'+fname
                    cmd = "mv %s %s" % (m.workspace,newName)
                    run_cmd(cmd)
                    # os.rename(m.workspace,newName)
                    # os.system("rm -rf mcore*")
                    file_name = newName +'/'+ '.state_id'
                    with open(file_name,'r') as f1:
                        lines=f1.readlines()
                        state_id = lines[0]
                        # print(state_id)      
                    return newName,True,state_id
            else:
                 continue                        
        else:
             continue
    
    return m.workspace,False,0
