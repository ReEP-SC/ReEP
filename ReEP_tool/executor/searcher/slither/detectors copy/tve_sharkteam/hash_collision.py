"""
Module detecting Hash Collisions With Multiple Variable Length Arguments
"""


from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.slithir.operations import Assignment, Length
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.operations.binary import Binary
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.core.compilation_unit import SlitherCompilationUnit


class HashCollisions(AbstractDetector):
    """
    Hash Collisions With Multiple Variable Length Arguments
    """

    ARGUMENT = "hash-collisions-with-multiple-variable-length-arguments"
    HELP = "Hash Collisions With Multiple Variable Length Arguments"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#hash-collisions"

    WIKI_TITLE = "Hash Collisions With Multiple Variable Length Arguments"
    WIKI_DESCRIPTION = "Using abi.encodePacked() with multiple variable length arguments can, in certain situations, lead to a hash collision. Since abi.encodePacked() packs all elements in order regardless of whether they're part of an array, you can move elements between arrays and, so long as all elements are in the same order, it will return the same encoding. In a signature verification situation, an attacker could exploit this by modifying the position of elements in a previous function call to effectively bypass authorization."
    WIKI_EXPLOIT_SCENARIO = ".."

    WIKI_RECOMMENDATION = "When using abi.encodePacked(), it's crucial to ensure that a matching signature cannot be achieved using different parameters. To do so, either do not allow users access to parameters used in abi.encodePacked(), or use fixed length arrays. Alternatively, you can simply use abi.encode() instead."

    def _detect_Hash_collisions_with_multiple_variable_length_arguments(self, contract):
        Hash_collisions = set()
        for function in contract.all_functions_called:
            for expression in function.calls_as_expressions:
                if "abi.encodePacked"==expression.called.__str__():
                    for arg in expression.arguments:
                        for var in function.variables:
                            if arg.__str__() == var.name.__str__() and "[]" in var.type.__str__():
                                for node in function.nodes:
                                    if node.source_mapping["lines"] == expression.source_mapping["lines"]:
                                        Hash_collisions.add(node)
                        for sVar in function.state_variables_read:
                            if arg.__str__() == sVar.name.__str__() and "[]" in sVar.type.__str__():
                                for node in function.nodes:
                                    if node.source_mapping["lines"] == expression.source_mapping["lines"]:
                                        Hash_collisions.add(node)
        return Hash_collisions

    def _detect(self):
        results = []
        for contract in self.slither.contracts_derived:
            nodes = self._detect_Hash_collisions_with_multiple_variable_length_arguments(contract)
            if nodes:
                info = [contract," Hash Collisions With Multiple Variable Length Arguments\n"]
                for node in nodes:
                    node_info = info + ["\t- ", node, "\n"]
                    res = self.generate_result(node_info)
                    results.append(res)
        return results
