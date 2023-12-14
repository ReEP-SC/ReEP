"""
Module detecting Module detecting Lack of Proper Signature Verification
ISSUE: SWC-122
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations import Contract
from slither.formatters.variables.unused_state_variables import custom_format 
from slither.core.compilation_unit import SlitherCompilationUnit

def detect_lack_of_proper_signature_verification(contract: Contract):
    """
    Include the address of the contract that processes the message. 
    This ensures that the message can only be used in a single contract.
    """
    # tampering risk on signature
    ABNORMAL = {}
    # tampering risk on signature
    TABPERING = {}

    """
    IF use recover, report the risk of signatrue tampering
    IF not use recover, warn the user use the proper verification scheme
    """
    for function in contract.all_functions_called + contract.modifiers:
        # find all the normal signature verification expression
        address_variables = []

        # not use ecrecover as the normal verification
        abnormal = {}
        # tampering risk on signature
        tampering = {}
        for para in function.parameters:
            if "address" in str(para.type):
                address_variables.append(para.name)
        if address_variables:
            # check if exists signature recover check 
            for expression in function.expressions:
                if "==" in str(expression):
                    for address_v in address_variables:
                        if address_v in str(expression):
                            if "recover" in str(expression) and "signature" in str(expression):
                                tampering[address_v] = expression.source_mapping_str
                            elif "recover" not in str(expression):
                                if "address" in str(expression) or "sender" in str(expression) or "from" in str(expression):
                                    abnormal[address_v] = expression.source_mapping_str
            if abnormal:
                ABNORMAL[function] = abnormal
            if tampering:
                TABPERING[function] = tampering

    return [ABNORMAL, TABPERING]

class LackOfProperSignatureVerification(AbstractDetector):
    """
    Lack of Proper Signature Verification
    """
    ARGUMENT = "lack_of_proper_signature_verification"
    HELP = "Lack of Proper Signature Verification"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#lack-of-proper-signature-verification"
    WIKI_TITLE = "Lack of Proper Signature Verification"
    WIKI_DESCRIPTION = "Detects Lack of Proper Signature Verification"
    WIKI_EXPLOIT_SCENARIO = """
    """

    WIKI_RECOMMENDATION = "Include the address of the contract that processes the message. This ensures that the message can only be used in a single contract."
    def _detect(self):
        results = []

        for contract in self.contracts:
            # get the all unsafe functions and parameters 
            all_abnormal = detect_lack_of_proper_signature_verification(contract)[0]
            all_tampering = detect_lack_of_proper_signature_verification(contract)[1]
            if all_abnormal:
                for function in all_abnormal:
                    info = [function,"make sure Use the proper verification scheme\n"]
                    # res = "Detect"
                    for para in all_abnormal[function]:
                         info += ["\t- ","[" + para + "] in" + all_abnormal[function][para], "\n"]
                    

                    res = self.generate_result(info)
                    results.append(res)

            if all_tampering:
                for function in all_tampering:
                    # res = "Detect"
                    info = [function,"Pay attention on modification on verification signature\n"]
                    for para in all_tampering[function]:
                        info += ["\t- ","[" + para + "] in" + all_tampering[function][para], "\n"]
                    
                    res = self.generate_result(info)
                    results.append(res)

        return results

    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result):
        custom_format(compilation_unit, result)
