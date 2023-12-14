"""
Module detecting modifiers in which external calls are used.
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.compilation_unit import SlitherCompilationUnit


class ModifierExternalCall(AbstractDetector):
    """
    Detector for modifiers in which external calls are used
    """

    ARGUMENT = "modifier-external-call"
    HELP = "The code inside a modifier is usually executed before the function body, so any external calls will violate the Checks-Effects-Interactions pattern. "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = (
        "https://github.com/crytic/slither/wiki/Detector-Documentation#external-call-in-modifiers"
    )

    WIKI_TITLE = "External call in modifiers"
    WIKI_DESCRIPTION = "The code inside a modifier is usually executed before the function body, so any external calls will violate the Checks-Effects-Interactions pattern. And an external call in modifier can even lead to the reentrancy attack"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Registry {
    function isVoter(address _addr) view external returns(bool) {
        // Code
    }
}

contract Election {
    Registry registry;

    modifier isEligible(address _addr) {
        require(registry.isVoter(_addr));
        _;
    }

    function vote() isEligible(msg.sender) public {
        //code
    }
}
```
the Registry contract can make a reentracy attack by calling Election.vote() inside isVoter()."""

    WIKI_RECOMMENDATION = (
        "Use modifiers only for checks and external calls should never be used in the modifier."
    )

    def _detect(self):
        results = []
        compilation_unit = self.compilation_unit
        for c in compilation_unit.contracts:
            for mod in c.modifiers:
                # if mod.contract_declarer != c:
                #     continue
                # Walk down the tree, only looking at nodes in the outer scope
                for external_call in mod.external_calls_as_expressions:
                    external_call_txt = external_call.__str__() + " is the external call in the modifier "
                    info = [
                        external_call_txt,
                        mod,
                        "\n",
                    ]

                    # json = self.generate_result(info)
                    # info = [localVar[0], " is never used in ", localVar[1], "\n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results
