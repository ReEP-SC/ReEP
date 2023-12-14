from slither.detectors.abstract_detector import AbstractDetector,DetectorClassification
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations import Contract
from slither.formatters.variables.unused_state_variables import custom_format
from slither.core.compilation_unit import SlitherCompilationUnit

def detect_unrestricted_write_state(contract:Contract):
    dict_function_to_state = {}
    all_function = contract.all_functions_called + contract.modifiers
    for fun in all_function:
        arbitrary_variables = []
        for state_var in fun.state_variables_written:
            if not fun.is_reading_in_require_or_assert(state_var):
                arbitrary_variables.append(state_var.name)

        if arbitrary_variables:
            dict_function_to_state[fun] = arbitrary_variables
    return dict_function_to_state


class UnrestrictedWriteState(AbstractDetector):
    """
       Write to Arbitrary Storage Location without require/assert to check the state variables
       """
    ARGUMENT = "test_unrestricted-write-state"
    HELP = "Write to Arbitrary Storage Location"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#unrestricted-write-state"
    WIKI_TITLE = "Write to Arbitrary Storage Location"
    WIKI_DESCRIPTION = "Detects write to Arbitrary Storage Location without appropriate require/assert to check the state variables"
    WIKI_EXPLOIT_SCENARIO = """
    ```solidity
    // Scenario Replay: SWC-124  
    // https://swcregistry.io/docs/SWC-124#arbitrary-location-write-simplesol
    /**
        Test match: TVE-80: unrestricted_write
     */
    """

    WIKI_RECOMMENDATION = "As a general advice, given that all data structures share the same storage (address) space, one should make sure that writes to one data structure cannot inadvertently overwrite entries of another data structure."

    def _detect(self):
        results =[]
        for contract in self.contracts:
            all_dicts = detect_unrestricted_write_state(contract)
            if all_dicts:
                for function in all_dicts:
                    res = "state variables:["
                    for variables in all_dicts[function]:
                        res = res + " " + variables +" "
                    res += "]"
                    info = [
                        res,
                        "are written to arbitary storage location in function:",
                        function,
                        "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)

        return results
    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result):
        custom_format(compilation_unit,result)