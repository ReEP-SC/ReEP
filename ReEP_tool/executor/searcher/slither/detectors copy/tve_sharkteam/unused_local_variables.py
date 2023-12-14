"""
Module detecting unused local variables
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.formatters.variables.unused_state_variables import custom_format
from slither.core.compilation_unit import SlitherCompilationUnit

def detect_unused_local(contract):
    if contract.is_signature_only():
        return None
    # Get all the variables read in all the functions and modifiers
    all_functions = contract.all_functions_called + contract.modifiers
    local_variables_unused = []
    for function in all_functions:
        for var in function.local_variables:
            if var not in function.variables_read_or_written:
                local_variables_unused += [
                    (var, function),
                ]

    return local_variables_unused


class UnusedLocalVars(AbstractDetector):
    """
    Unused local variables detector
    """

    ARGUMENT = "unused-local"
    HELP = "Unused local variables"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#unused-local-variables"

    WIKI_TITLE = "Unused local variable"
    WIKI_DESCRIPTION = "Unused local variable."
    WIKI_EXPLOIT_SCENARIO = ""
    WIKI_RECOMMENDATION = "Remove unused local variables."

    def _detect(self):
        """Detect unused local variables"""
        results = []
        compilation_unit = self.compilation_unit
        for c in compilation_unit.contracts_derived:
            unusedLocalVars = detect_unused_local(c)
            if unusedLocalVars:
                for localVar in unusedLocalVars:
                    info = [localVar[0], " is never used in ", localVar[1], "\n"]
                    json = self.generate_result(info)
                    results.append(json)

        return results

    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result):
        custom_format(compilation_unit, result)
