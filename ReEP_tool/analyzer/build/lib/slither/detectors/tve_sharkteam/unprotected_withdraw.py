from slither.core.declarations import Function
from slither.analyses.data_dependency.data_dependency import is_tainted,is_dependent
from slither.core.declarations.solidity_variables import (SolidityFunction,SolidityVariableComposed,)
from slither.detectors.abstract_detector import AbstractDetector,DetectorClassification
from slither.slithir.operations import (HighLevelCall,Index,LowLevelCall,Send,SolidityCall,Transfer, high_level_call)

def unprotected_withdraw(func):
    if func.is_protected():
        return []
    ret = []
    for node in func.nodes:
        for ir in node.irs:
            if isinstance(ir,SolidityCall):
                if ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)"):
                    return False
            if isinstance(ir,Index):
                if ir.variable_right == SolidityVariableComposed("msg.sender"):
                    return False
                if is_dependent(
                    ir.variable_right,
                    SolidityVariableComposed("msg.sender"),
                    func.contract,
                ):
                     return False
            if isinstance(ir,(HighLevelCall,LowLevelCall,Transfer,Send)):
                if isinstance(ir,(HighLevelCall)):
                    if isinstance(ir.function,Function):
                        if ir.function.full_name == "withdraw(address,uint256)" or "transferFrom(address,address,uint256)":
                            return False
                if ir.call_value is None:
                    continue
                if ir.call_value == SolidityVariableComposed("msg.value"):
                    continue
                if is_dependent(
                    ir.call_value,
                    SolidityVariableComposed("msg.value"),
                    func.contract,
                ):
                     continue

                if is_tainted(ir.destination,func.contract):
                    ret.append(node)

    return ret


def detect_unprotected_withdraw(contract):
    """
        Detect unprotected withdraw
    Args:
        contract(Contract)
    Returns:
        list((Function),(list,(node)))
    """
    ret =[]
    for f in [f for f in contract.functions if f.contract_declarer == contract]:
        nodes = unprotected_withdraw(f)
        if nodes:
            ret.append((f,nodes))
    return ret
    
class UnprotectedWithdraw(AbstractDetector):
    ARGUMENT = "unprotected-withdraw"
    HELP = "Unprotected Ether Withdrawal"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI ="https://swcregistry.io/docs/SWC-105#unprotected-withdraw-function"
    WIKI_TITLE = "Unprotected Ether Withdrawal"
    WIKI_DESCRIPTION = "Due to missing or insufficient access controls, malicious parties can withdraw some or all Ether from the contract account."

    WIKI_EXPLOIT_SCENARIO ="""
    ```solidity
    contract SimpleEtherDrain {

        function withdrawAllAnyone() {
             msg.sender.transfer(this.balance);
        }

        function () public payable {
        }

     }
    ```
    Anybody calls `withdrawAllAnyone` and withdraw all Ether from the contract account.
    """

    WIKI_RECOMMENDATION = "Implement controls so withdrawals can only be triggered by authorized parties or according to the specs of the smart contract system."

    def _detect(self):
        results = []
        for c in self.contracts:
            unprotected_withdraw_result = detect_unprotected_withdraw(c)
            for (func,nodes) in unprotected_withdraw_result:

                info = [func,"anybody can withdraw eth\n"]
                info += ["\tDangerous calls:\n"]

                nodes.sort(key=lambda x:x.node_id)

                for node in nodes:
                    info += ["\t-",node,"\n"]

                res =self.generate_result(info)

                results.append(res)

        return results