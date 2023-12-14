"""
Module detecting unrestricted state variables write(Write to Arbitrary Storage Location)
ISSUE: SWC-124
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations import Contract
from slither.formatters.variables.unused_state_variables import custom_format
from slither.core.compilation_unit import SlitherCompilationUnit

def detect_unrestricted_write_state(contract: Contract):
    """
    check if exists require statements before state variables write
    
    TODO : 1. based on the solc version to judge further logic audit
                1.1 check if version is under v0.6.0
                1.2 check: if access state variable without judge length 
                1.3 check: if logic of array length  affect other variables/function calls  e.g.(0 <= x.length)
    """
    # result to return 
    # dict function -> arbitrary_variables
    dict_function_to_state = {}

    # all functions
    all_function = contract.all_functions_called + contract.modifiers

    # loop all the functions to check the if the state write with require/assert check
    for fun in all_function:
        # check write state variable with requeire/assert in each funciton
        arbitrary_variables = []
        for state_var in fun.state_variables_written:
            if not fun.is_reading_in_require_or_assert(state_var):
                arbitrary_variables.append(state_var.name)
        
        # if there exists arbitrary_variables, take this funciton and variables to the result
        if arbitrary_variables:
            dict_function_to_state[fun] = arbitrary_variables

    return dict_function_to_state


class UnrestrictedWriteState(AbstractDetector):
    """
    Write to Arbitrary Storage Location without require/assert to check the state variables
    """
    ARGUMENT = "unrestricted-write-state"
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
        "Detect unrestricted-write-state"
        results = []

        for contract in self.contracts:
            # get the all unsafe functions and variables dicts
            all_dicts = detect_unrestricted_write_state(contract)
            if all_dicts:
                for function in all_dicts:
                    res = "State Variables: ["
                    for variables in all_dicts[function]:
                        res = res + " " + variables + " "
                    res += "] "
                    info = [
                        res,
                        " are written to arbitrary storage location in function: ",  
                        function,
                        "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)

        return results

    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result):
        custom_format(compilation_unit, result)