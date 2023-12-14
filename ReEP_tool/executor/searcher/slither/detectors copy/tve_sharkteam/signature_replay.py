"""
Module detecting Module detecting Signature Replay Attacks
ISSUE: SWC-121
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations import Contract
from slither.formatters.variables.unused_state_variables import custom_format 

def detect_signature_replay_attacks(contract: Contract):
    """
    Include the address of the contract that processes the message. 
    This ensures that the message can only be used in a single contract.
    """
    result = {}
    for function in contract.all_functions_called + contract.modifiers:
        # find all the ecrecover function to find the message
        message = set()
        for expression in function.expressions:
            # find the hash message variables 
            statement = str(expression)
            if "ecrecover(" in statement:
                stat_slice = statement.split("ecrecover(")
                if len(stat_slice) > 1:
                    variables_statement = stat_slice[1].split(")(")
                    if len(variables_statement) > 1:
                        the_message = variables_statement[1].split(",")[0]
                        message.add(the_message)
        # find the written variable associated wih the "keccak256/sha3"
        for node in function.variables_written:
            if node:
                if node.name in message:
                    statement = str(node.expression).lower()
                    if "keccak256" in statement or "sha3" in statement:
                        # test if nonce in the statement
                        if "nonce" not in statement:
                            result[node.name] = node.expression.source_mapping_str
    return result

# class SignatureReplay(AbstractDetector):
class SignatureReplay(AbstractDetector):
    """
    Signature Replay Attacks
    """
    ARGUMENT = "signature-replay-attacks"
    HELP = "Signature Replay Attacks"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#signature-replay-attacks"
    WIKI_TITLE = "Signature Replay Attacks"
    WIKI_DESCRIPTION = "Detects Signature Replay Attacks"
    WIKI_EXPLOIT_SCENARIO = """
    """

    WIKI_RECOMMENDATION = "Include the address of the contract that processes the message. This ensures that the message can only be used in a single contract."
    def _detect(self):
        results = []

        for contract in self.contracts:
            all_dict_results = detect_signature_replay_attacks(contract)
            if all_dict_results:
                for messages in all_dict_results:
                    info = [
                        "Hash Messge: [",
                        messages,
                        "] are detected a risk of Signature Replay Attacks on (",
                        all_dict_results[messages],
                        " )"
                        "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)

        return results

    @staticmethod
    def _format(slither, result):
        custom_format(slither, result)
