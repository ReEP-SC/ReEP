"""
Module detecting DoS with Failed Call
"""


from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Assignment, Length
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.operations.binary import Binary
from slither.analyses.data_dependency.data_dependency import is_tainted


class DoSWithFailedCall(AbstractDetector):
    """
    DoS with failed call
    """

    ARGUMENT = "DoS-with-failed-call"
    HELP = "DoS with failed call"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#DoS-with-failed-call"

    WIKI_TITLE = "DoS with failed call"
    WIKI_DESCRIPTION = "External calls can fail accidentally or deliberately, which can cause a DoS condition in the contract. To minimize the damage caused by such failures, it is better to isolate each external call into its own transaction that can be initiated by the recipient of the call. This is especially relevant for payments, where it is better to let users withdraw funds rather than push funds to them automatically (this also reduces the chance of problems with the gas limit)."
    WIKI_EXPLOIT_SCENARIO = ".."

    WIKI_RECOMMENDATION = """
    It is recommended to follow call best practices:
        Avoid combining multiple calls in a single transaction, especially when calls are executed as part of a loop
        Always assume that external calls can fail
        Implement the contract logic to handle failed calls"""

    def _detect_doS_with_failed_call(self, contract):
        doS_with_failed_call = set()
        for function in contract.functions_and_modifiers_declared:
            for node in function.nodes:
                if node.type == NodeType.IFLOOP:
                    # print(node.__dict__)
                    # print(node.__str__)
                    for n in node.sons:
                        if n.type == NodeType.EXPRESSION:
                           if n.external_calls_as_expressions is not None:
                                doS_with_failed_call.add(n)
                #     for s_var in node.state_variables_written:
                #         right_condition = "new %s" % (s_var.type)
                #         left_condition = "%s" % (s_var.type)
                #         expression = "%s" % node.expression
                #         if "[]" in left_condition and right_condition in expression:
                #             doS_with_failed_call.add(node)
        return doS_with_failed_call

    def _detect(self):
        results = []
        for contract in self.slither.contracts_derived:
            nodes = self._detect_doS_with_failed_call(contract)
            if nodes:
                info = [contract," DoS with Failed Call\n"]
                for node in nodes:
                    node_info = info + ["\t- ", node, "\n"]
                    res = self.generate_result(node_info)
                    results.append(res)
        return results
