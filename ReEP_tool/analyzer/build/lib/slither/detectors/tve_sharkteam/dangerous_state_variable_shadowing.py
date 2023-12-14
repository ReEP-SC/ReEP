"""
Moudle detecting dangerous-state-variable-shadowing
"""
from slither.detectors.abstract_detector import AbstractDetector,DetectorClassification


def detect_dangerous_shadowing(contract):
    ret = []
    variables_fathers = []
    for father in contract.inheritance:
        if all(not f.is_implemented for f in father.functions + father.modifiers):
            variables_fathers += father.state_variables_declared
    for var in contract.state_variables_declared:
        shadow = [v for v in variables_fathers if v.name == var.name and var.name == "owner" ]
        if shadow:
            ret.append([var] + shadow)
    return ret


class DangerousStateVariable(AbstractDetector):
    """
    Dangerous Shadowing detection
    """

    ARGUMENT = "dangerous-state-variable-shadowing"
    HELP = "Shadowing of inherited state variables should be an error"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-119#dangerous-state-variable-shadowing"

    WIKI_TITLE = "Shadowing State Variables"
    WIKI_DESCRIPTION = """
    Solidity allows for ambiguous naming of state variables when inheritance is used. Contract A with a variable x could inherit contract B that also has a state variable x defined. This would result in two separate versions of x, one of them being accessed from contract A and the other one from contract B. In more complex contract systems this condition could go unnoticed and subsequently lead to security issues.

Shadowing state variables can also occur within a single contract when there are multiple definitions on the contract and function level.
    """

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract BaseContract{
    address owner;
}

contract DerivedContract is BaseContract{
    address owner;
}
```
`owner` of `BaseContract` is shadowed in `DerivedContract`."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Review storage variable layouts for your contract systems carefully and remove any ambiguities. Always check for compiler warnings as they can flag the issue within a single contract."

    def _detect(self):
        results = []
        for contract in self.contracts:
            shadowing = detect_dangerous_shadowing(contract)
            if shadowing:
                for all_variables in shadowing:
                    shadow = all_variables[0]
                    variables = all_variables[1:]
                    info = [shadow,"dangerous state variable shadowing:\n"]
                    for var in variables:
                        info += ["\t-",var,"\n"]

                    res = self.generate_result(info)

                    results.append(res)
                    
        return results