"""
Module detecting Signature Malleability
ISSUE: SWC-117
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations import Contract
from slither.formatters.variables.unused_state_variables import custom_format 
from slither.core.compilation_unit import SlitherCompilationUnit

def detect_signature_malleability(contract: Contract):
    """
    A signature should never be included into a signed message hash 
    to check if previously messages have been processed by the contract.
    """
    # signature variables contain the characters like :
    # sig
    #SUSPECT_PARAMTERS = ["sig"]
    # Iterate all the function to check if the function names contain words like:
    ## "256/keccak/hash/sig/signature/"
    SUSPECT_FUNCTION_FILEDS = ["keccak256(", "hash256(","sha3("]
    function_to_signature = {}
    call_to_expression = {}

    for function in contract.all_functions_called + contract.modifiers:
        # # 1. check function are signature/hash calls
        # for i in SUSPECT_FUNCTION_FILEDS:
        #     # find the suspected funciton
        #     if i in function.name.lower():
        #         signatures = []
        #         for para in function.parameters:
        #             # find the unsafe parameter
        #             if "sig" in para.name.lower() and "bytes" == str(para.type):
        #                 signatures.append(para.name)       
        #         if signatures:
        #             function_to_signature[function] = signatures
        #         # since find the SUSPECT_FUNCTION_FILEDS
        #         # go over the rest fileds check process
        #         break
        
        # 2. check all the suspect internal calls
        for the_node in function.nodes:
            exps = []
            if the_node.expression:
                for i in SUSPECT_FUNCTION_FILEDS:
                    if i in str(the_node.expression) and "signature" in str(the_node.expression):
                        exps.append(str(the_node.expression))
                        break
                if exps:
                    call_to_expression[function] = exps

    return [function_to_signature, call_to_expression]

class SignatureMalleability(AbstractDetector):
    """
    Signature Malleability
    """
    ARGUMENT = "signature-malleability"
    HELP = "Signature Malleability"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#signature-malleability"
    WIKI_TITLE = "Signature Malleability"
    WIKI_DESCRIPTION = "Detects Signature Malleability"
    WIKI_EXPLOIT_SCENARIO = """
    """

    WIKI_RECOMMENDATION = "A signature should never be included into a signed message hash to check if previously messages have been processed by the contract."

    def _detect(self):
        results = []

        for contract in self.contracts:
            # get the all unsafe functions and parameters 
            all_dicts = detect_signature_malleability(contract)[0]
            all_calls = detect_signature_malleability(contract)[1]
            if all_dicts:
                for function in all_dicts:
                    res = "Function Parameters: ["
                    for params in all_dicts[function]:
                        res = res + " " + params + " "
                    res += "]"
                    info = [
                        res,
                        " are detected a risk of Signature Malleability : ",  
                        function,
                        "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)

            if all_calls:
                for function in all_calls:
                    res = "Call Expression: ["
                    for params in all_calls[function]:
                        res = res + " " + params + " "
                    res += "]"
                    info = [
                        res,
                        " are detected a risk of Signature Malleability : ",  
                        function,
                        "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)

        return results

    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result):
        custom_format(compilation_unit, result)