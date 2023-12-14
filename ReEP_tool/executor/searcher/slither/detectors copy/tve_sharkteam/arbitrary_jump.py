"""
Module detecting Arbitrary Jump with Function Type Variable
"""


from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Assignment, Length
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.operations.binary import Binary
from slither.analyses.data_dependency.data_dependency import is_tainted


class ArbitraryJumpWithFunctionTypeVariable(AbstractDetector):
    """
    Arbitrary Jump with Function Type Variable
    """

    ARGUMENT = "Arbitrary-Jump-with-Function-Type-Variable"
    HELP = "Arbitrary Jump with Function Type Variable"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#arbitrary-jump-with-function-type-variable"

    WIKI_TITLE = "Arbitrary Jump with Function Type Variable"
    WIKI_DESCRIPTION = "Solidity supports function types. That is, a variable of function type can be assigned with a reference to a function with a matching signature. The function saved to such variable can be called just like a regular function."
    WIKI_EXPLOIT_SCENARIO = ".."

    WIKI_RECOMMENDATION = "The use of assembly should be minimal. A developer should not allow a user to assign arbitrary values to function type variables."

    def _detect_Arbitrary_Jump_with_Function_Type_Variable(self, contract):
        Arbitrary_Jump = set()
        for function in contract.functions_and_modifiers_declared:
            if function.name =="breakIt":
                for node in function.nodes:
                    if node.type==NodeType.ASSEMBLY:
                        for n in node.sons:
                            for var in n._vars_read:
                                if var._location=="default" and var.type.__str__()=="function()":
                                    Arbitrary_Jump.add(n)
                                # if var._location=="memory":
                                #     for val in var._type._type._elems.values():
                                #         print(val._type)


                                # print(var._type._type.__dict__)
                # if node.type == NodeType.EXPRESSION:
                #     for s_var in node.state_variables_written:
                #         right_condition = "new %s" % (s_var.type)
                #         left_condition = "%s" % (s_var.type)
                #         expression = "%s" % node.expression
                #         if "[]" in left_condition and right_condition in expression:
                #             Arbitrary_Jump.add(node)
        return Arbitrary_Jump

    def _detect(self):
        results = []
        for contract in self.slither.contracts_derived:
            nodes = self._detect_Arbitrary_Jump_with_Function_Type_Variable(contract)
            if nodes:
                info = [contract," Arbitrary Jump with Function Type Variable\n"]
                for node in nodes:
                    node_info = info + ["\t- ", node, "\n"]
                    res = self.generate_result(node_info)
                    results.append(res)
        return results
