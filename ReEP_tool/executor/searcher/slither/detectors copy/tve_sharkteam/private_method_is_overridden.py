"""
Moudle detecting private-method-is-overridden

"""
from slither.detectors.abstract_detector import AbstractDetector,DetectorClassification
from slither.formatters.attributes.const_functions import custom_format

def detect_private_method_overriden(contract):
    ret = []
    functions_fathers = []
    for father in contract.inheritance:
        for f in father.functions:
            if f.contract_declarer != father:
                continue
            if f.visibility == "private":
                functions_fathers += [f]
    for var in contract.functions:
        shadow = [v for v in functions_fathers if v.name == var.name]
        if shadow:
            ret.append([var] + shadow)
    return ret




class PrivateMethodOverriden(AbstractDetector):
    """
    Private Method Overriden detection
    """
    ARGUMENT = "private-method-is-overridden"
    HELP = "Private methods can be overridden by inheriting contracts."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://docs.soliditylang.org/en/v0.8.1/bugs.html#private-method-is-overridden"

    WIKI_TITLE = "privateCanBeOverridden"
    WIKI_DESCRIPTION = """
    While private methods of base contracts are not visible and cannot be called directly from the derived contract, it is still possible to declare a function of the same name and type and thus change the behaviour of the base contract's function.
    """

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """ """
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Use the repaired solc version or use the latest stable version directly"

    def _detect(self):
        results = []
        if self.compilation_unit.solc_version and self.compilation_unit.solc_version >= "0.5.17":
            return results
        for contract in self.contracts:
            shadowing = detect_private_method_overriden(contract)
            if shadowing:
                for private_functions in shadowing:
                    shadow = private_functions[0]
                    variables = private_functions[1:]
                    info = [shadow,"private method overridden:\n"]
                    for var in variables:
                        info += ["\t-",var,"\n"]

                    res = self.generate_result(info)

                    results.append(res)

        return results
