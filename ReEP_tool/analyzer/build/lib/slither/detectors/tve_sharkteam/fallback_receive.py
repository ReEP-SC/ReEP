"""
Moudle detecting fallback/receive function

Lack of preventive measures for `fallback`/`receive` functions
"""
from slither.detectors.abstract_detector import AbstractDetector,DetectorClassification

class Fallback_Receive(AbstractDetector):
    ARGUMENT ="fallback-receive"
    HELP = "fallback/receive functions have a subtle relationship with visibility, state variability and Ethereum transfers"
    IMPACT =DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://docs.soliditylang.org/en/latest/contracts.html#fallback-and-receive-function"

    WIKI_TITLE = "Fallback vs Receive"
    WIKI_DESCRIPTION ="Lack of preventive measures for `fallback`/`receive` functions."

    WIKI_EXPLOIT_SCENARIO = """
    
    """
    WIKI_RECOMMENDATION = "Check whether all the preventive measures of fallback/receive functions are considered, they have a subtle relationship with visibility, state variability and Ethereum transfers"

    @staticmethod
    def detect_fallback_vs_receive_func(func):
        """Detect if the function is fallback/receive function

        Detect the public functions calling fallback/receive  without protection
        Returns:
            (bool): True if the function is fallback/receive
        """

        if func.is_constructor:
            return False

        if func.visibility not in ["public","external"]:
            return False

        calls = [c.name for c in func.internal_calls]
        if not ("fallback()"in calls or "receive()" in calls):
            return False
           
        return True

    def detect_fallback_vs_receive(self,contract):
        ret = []
        for f in contract.functions_declared:
            if self.detect_fallback_vs_receive_func(f):
                ret.append(f)
        return ret

    def _detect(self):
        """Detect the fallback/receive functions"""
        results = []
        for c in self.contracts:
            functions = self.detect_fallback_vs_receive(c)
            for func in functions:
                info = [func,"Lack of preventive measures for `fallback`/`receive` functions\n"]
                res = self.generate_result(info)
                results.append(res)
        return results
