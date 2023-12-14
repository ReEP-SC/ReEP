"""
Module detecting integer overflow and underflow.
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.visitors.expression.export_values import ExportValues
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable


class IntegerOverflowAndUnderflow(AbstractDetector):
    """
    Integer Overflow and Underflow.
    """

    ARGUMENT = "integer-overflow-and-underflow"
    HELP = "Integer Overflow and Underflow"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#integer-overflow-and-underflow"

    WIKI_TITLE = "Integer Overflow and Underflow"
    WIKI_DESCRIPTION = "An overflow/underflow happens when an arithmetic operation reaches the maximum or minimum size of a type. For instance if a number is stored in the uint8 type, it means that the number is stored in a 8 bits unsigned number ranging from 0 to 2^8-1. In computer programming, an integer overflow occurs when an arithmetic operation attempts to create a numeric value that is outside of the range that can be represented with a given number of bits – either larger than the maximum or lower than the minimum representable value."
    WIKI_EXPLOIT_SCENARIO = "..."

    WIKI_RECOMMENDATION = "It is recommended to use vetted safe math libraries for arithmetic operations consistently throughout the smart contract system."

    def _integer_overflow_and_underflow(self, contract):
        result = set()
        for function in contract.functions_and_modifiers_declared:
            i = 0
            for node in function.nodes:
                i += 1
                expression = "%s" % node.expression
                opNum = 0
                if "++" in expression \
                        or "--" in expression:
                    result.add(node)
                    continue
                if "+" in expression:
                    opNum += 1
                if "-" in expression:
                    opNum += 1
                if "*" in expression:
                    opNum += 1
                if "/" in expression:
                    opNum += 1
                if opNum > 1:
                    result.add(node)
                    continue
                elif opNum == 0:
                    continue
                if "<" in expression \
                        or ">" in expression \
                        or "==" in expression:
                    result.add(node)
                    continue
                if "+" in expression or "*" in expression:
                    if "=" not in expression:
                        result.add(node)
                        continue
                    ok = False
                    if len(node.variables_written_as_expression)==0 or len(node.variables_read_as_expression)<2:
                        continue
                    resVars = node.variables_written_as_expression[0]
                    rvars, lvars = node.variables_read_as_expression[0], node.variables_read_as_expression[1]
                    if "+" in expression or "*" in expression:
                        # resVar ="%s" % resVars.value
                        # rvar = "%s" % rvars.value
                        # lvar = "%s" % lvars.value
                        for n in function.nodes[i:]:
                            for call in n.calls_as_expression:
                                if "assert" in call.called.__str__() or "require" in call.called.__str__() \
                                        and rvars in n.variables_read_as_expression or lvars in n.variables_read_as_expression \
                                        and resVars in n.variables_read_as_expression:
                                    ok = True
                                    break
                            if ok:
                                break
                elif "-" in expression:
                    pass
                # if node.type == NodeType.EXPRESSION:
                #     for s_var in node.state_variables_written:
                #         right_condition = "new %s" % (s_var.type)
                #         left_condition = "%s" % (s_var.type)
                #         expression = "%s" % node.expression
                #         if "[]" in left_condition and right_condition in expression:
                #             result.add(node)
        return result

    def _detect(self):
        results = []
        for contract in self.contracts:
            nodes = self._integer_overflow_and_underflow(contract)
            if nodes:
                info = [contract, " Integer Overflow and Underflow\n"]
                for node in nodes:
                    node_info = info + ["\t- ", node, "\n"]
                    res = self.generate_result(node_info)
                    results.append(res)

        return results
