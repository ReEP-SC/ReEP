"""
Module detecting DoS with block gas limit
"""


from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Assignment, Length
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.operations.binary import Binary
from slither.analyses.data_dependency.data_dependency import is_tainted


class DoSWithBlockGasLimit(AbstractDetector):
    """
    DoS with block gas limit
    """

    ARGUMENT = "DoS-with-block-gas-limit"
    HELP = "DoS with block gas limit"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#DoS-with-block-gas-limit"

    WIKI_TITLE = "DoS with block gas limit"
    WIKI_DESCRIPTION = "When smart contracts are deployed or functions inside them are called, the execution of these actions always requires a certain amount of gas, based of how much computation is needed to complete them. The Ethereum network specifies a block gas limit and the sum of all transactions included in a block can not exceed the threshold."
    WIKI_EXPLOIT_SCENARIO = ".."

    WIKI_RECOMMENDATION = "Caution is advised when you expect to have large arrays that grow over time. Actions that require looping across the entire data structure should be avoided."

    def _detect_DoS_with_block_gas_limit(self, contract):
        doS_with_block_gas_limit = set()
        for function in contract.functions_and_modifiers_declared:
            for node in function.nodes:
                if node.type == NodeType.EXPRESSION:
                    for s_var in node.state_variables_written:
                        right_condition = "new %s" % (s_var.type)
                        left_condition = "%s" % (s_var.type)
                        expression = "%s" % node.expression
                        if "[]" in left_condition and right_condition in expression:
                            doS_with_block_gas_limit.add(node)
        return doS_with_block_gas_limit

    def _detect(self):
        results = []
        for contract in self.slither.contracts_derived:
            nodes = self._detect_DoS_with_block_gas_limit(contract)
            if nodes:
                info = [contract," DoS With Block Gas Limit\n"]
                for node in nodes:
                    node_info = info + ["\t- ", node, "\n"]
                    res = self.generate_result(node_info)
                    results.append(res)
        return results
