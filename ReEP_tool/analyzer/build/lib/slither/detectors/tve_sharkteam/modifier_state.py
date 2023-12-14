"""
Module detecting modifiers in which state variables are changed. That mains the state variables
in modifiers are written but only read.
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import NodeType
from slither.core.compilation_unit import SlitherCompilationUnit

def is_revert(node):
    return node.type == NodeType.THROW or any(
        c.name in ["revert()", "revert(string"] for c in node.internal_calls
    )


def _get_false_son(node):
    """Select the son node corresponding to a false branch
    Following this node stays on the outer scope of the function
    """
    if node.type == NodeType.IF:
        return node.sons[1]

    if node.type == NodeType.IFLOOP:
        return next(s for s in node.sons if s.type == NodeType.ENDLOOP)

    return None


class ModifierState(AbstractDetector):
    """
    Detector for modifiers in which state variables are changed
    """

    ARGUMENT = "modifier-state"
    HELP = "Modifiers that change state variables"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#modifiers-change-state-varibales"

    WIKI_TITLE = "Modifiers change state variables"
    WIKI_DESCRIPTION = "The code inside a modifier is usually executed before the function body, so any state changes will violate the Checks-Effects-Interactions pattern."
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract A {
    address public owner;
    address public super;
    modifier onlyOwner(address _addr) {
        super = owner;
        require(...);
        _;
    }
}
```
The state variable `super` is changed in the modifier `onlyOwner(address)`, which violates the Checks-Effects-Interactions pattern."""

    WIKI_RECOMMENDATION = "Use modifiers only for checks and any state variable should never be changed in the modifier."

    def _detect(self):
        results = []
        compilation_unit = self.compilation_unit
        for c in compilation_unit.contracts:
            for mod in c.modifiers:
                for state_variable_written in mod.state_variables_written:
                    info = [
                        state_variable_written,
                        " is a state variable and has been changed in the modifier ",
                        mod,
                        "\n",
                    ]
                    results.append(self.generate_result(info))

        return results
