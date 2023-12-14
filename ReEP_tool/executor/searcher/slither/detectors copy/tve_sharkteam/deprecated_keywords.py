"""
  Moudle detecting deprecated-keywords

"""
from slither.core.cfg.node import NodeType
from slither.core.declarations.solidity_variables import (
    SolidityVariableComposed,
    SolidityFunction,
)
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import LowLevelCall
from slither.visitors.expression.export_values import ExportValues

class deprecated_keywords(AbstractDetector):

    ARGUMENT = "Use-of-Deprecated-Solidity-Functions"
    HELP = "Use of Obsolete Function"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://swcregistry.io/docs/SWC-111#deprecated-keywords"

    WIKI_TITLE = "Use of Deprecated Solidity Functions"
    WIKI_DESCRIPTION = (
        "Several functions and operators in Solidity are deprecated. Using them leads to reduced code quality. With new major versions of the Solidity compiler, deprecated functions and operators may result in side effects and compile errors."
        )
    WIKI_EXPLOIT_SCENARIO = """"
    pragma solidity ^0.4.24;

    contract DeprecatedSimple {

        // Do everything that's deprecated, then commit suicide.

        function useDeprecated() public constant {

            bytes32 blockhash = block.blockhash(0);
            bytes32 hashofhash = sha3(blockhash);

            uint gas = msg.gas;

            if (gas == 0) {
                throw;
            }

            address(this).callcode();

            var a = [1,2,3];

            var (x, y, z) = (false, "test", 0);

            suicide(address(0));
        }

        function () public {}

    }  
       """
    WIKI_RECOMMENDATION = "Solidity provides alternatives to the deprecated constructions. Most of them are aliases, thus replacing old constructions will not break current behavior. For example, sha3 can be replaced with keccak256."

    DEPRECATED_SOLIDITY_VARIABLE = [
        ("block.blockhash", "block.blockhash()", "blockhash()"),
        ("msg.gas", "msg.gas", "gasleft()"),
    ]
    DEPRECATED_SOLIDITY_FUNCTIONS = [
        ("suicide(address)", "suicide()", "selfdestruct()"),
        ("sha3()", "sha3()", "keccak256()"),
    ]
    DEPRECATED_NODE_TYPES = [(NodeType.THROW, "throw", "revert()")]
    DEPRECATED_LOW_LEVEL_CALLS = [("callcode", "callcode", "delegatecall")]

    def detect_deprecation_in_expression(self, expression):

        export = ExportValues(expression)
        export_values = export.result()


        results = []

        for dep_var in self.DEPRECATED_SOLIDITY_VARIABLE:
            if SolidityVariableComposed(dep_var[0]) in export_values:
                results.append(dep_var)
        for dep_func in self.DEPRECATED_SOLIDITY_FUNCTIONS:
            if SolidityFunction(dep_func[0]) in export_values:
                results.append(dep_func)

        return results

    def detect_deprecated_references_in_node(self, node):

        results = []

        if node.expression:
            results += self.detect_deprecation_in_expression(node.expression)

        for dep_node in self.DEPRECATED_NODE_TYPES:
            if node.type == dep_node[0]:
                results.append(dep_node)

        return results

    def detect_deprecated_references_in_contract(self, contract):
        results = []

        for state_variable in contract.state_variables_declared:
            if state_variable.expression:
                deprecated_results = self.detect_deprecation_in_expression(
                    state_variable.expression
                )
                if deprecated_results:
                    results.append((state_variable, deprecated_results))

        for function in contract.functions_and_modifiers_declared:

            for node in function.nodes:
                deprecated_results = self.detect_deprecated_references_in_node(node)

                for ir in node.irs:
                    if isinstance(ir, LowLevelCall):
                        for dep_llc in self.DEPRECATED_LOW_LEVEL_CALLS:
                            if ir.function_name == dep_llc[0]:
                                deprecated_results.append(dep_llc)

                if deprecated_results:
                    results.append((node, deprecated_results))

        return results

    def _detect(self):

        results = []
        for contract in self.contracts:
            deprecated_references = self.detect_deprecated_references_in_contract(contract)
            if deprecated_references:
                for deprecated_reference in deprecated_references:
                    source_object = deprecated_reference[0]
                    deprecated_entries = deprecated_reference[1]
                    info = ["uses Deprecated Solidity Functions:  ", source_object, ":\n"]

                    for (_dep_id, original_desc, recommended_disc) in deprecated_entries:
                        info += [
                            f'\t- Deprecated keyword "{original_desc}" \n'
                        ]

                    res = self.generate_result(info)
                    results.append(res)

        return results
