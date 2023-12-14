""""
    Re-entrancy detection

    Based on heuristics, it may lead to FP and FN
    Iterate over all the nodes of the graph until reaching a fixpoint
"""
from collections import namedtuple, defaultdict
from typing import List
from slither.core.declarations.function import Function
from slither.detectors.abstract_detector import DetectorClassification
from .reentrancy import Reentrancy, to_hashable

FindingKey = namedtuple("FindingKey", ["function", "calls", "send_eth"])
FindingValue = namedtuple("FindingValue", ["variable", "node", "nodes"])


class ReentrancyEth(Reentrancy):
    ARGUMENT = "reentrancy-eth"
    HELP = "Reentrancy vulnerabilities (theft of ethers)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = (
        "https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities"
    )

    WIKI_TITLE = "Reentrancy vulnerabilities"

    # region wiki_description
    WIKI_DESCRIPTION = """
Detection of the [reentrancy bug](https://github.com/trailofbits/not-so-smart-contracts/tree/master/reentrancy).
Do not report reentrancies that don't involve Ether (see `reentrancy-no-eth`)"""
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
    function withdrawBalance(){
        // send userBalance[msg.sender] Ether to msg.sender
        // if mgs.sender is a contract, it will call its fallback function
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
            throw;
        }
        userBalance[msg.sender] = 0;
    }
```

Bob uses the re-entrancy bug to call `withdrawBalance` two times, and withdraw more than its initial deposit to the contract."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Apply the [`check-effects-interactions pattern`](http://solidity.readthedocs.io/en/v0.4.21/security-considerations.html#re-entrancy)."

    STANDARD_JSON = False



        # 检测是否有msg.sender依赖
    @staticmethod
    def get_msg_sender_checks(function):
        all_functions = function.all_internal_calls() + [function] + function.modifiers

        all_nodes = [f.nodes for f in all_functions if isinstance(f, Function)]
        all_nodes = [item for sublist in all_nodes for item in sublist]

        all_conditional_nodes = [
            n for n in all_nodes if n.contains_if() or n.contains_require_or_assert()
        ]

        all_conditional_nodes_on_msg_sender = [
            n
            for n in all_conditional_nodes
            if "msg.sender" in [v.name for v in n.solidity_variables_read]
        ]
        return all_conditional_nodes_on_msg_sender

    def find_reentrancies(self):
        result = defaultdict(set)
        for contract in self.contracts:  # pylint: disable=too-many-nested-blocks
            for f in contract.functions_and_modifiers_declared:
                all_conditional_nodes_on_msg_sender = self.get_msg_sender_checks(f)
                # print(all_conditional_nodes_on_msg_sender)

                for node in f.nodes:
                    if node not in all_conditional_nodes_on_msg_sender:
                        # print(node)
                    # for node in condition_nodes:
                        # dead code
                        if not self.KEY in node.context:
                            continue
                        if node.context[self.KEY].calls and node.context[self.KEY].send_eth:
                            if not any(n != node for n in node.context[self.KEY].send_eth):
                                continue
                            read_then_written = set()
                            for c in node.context[self.KEY].calls:
                                if c == node:
                                    continue
                                read_then_written |= {
                                    FindingValue(
                                        v,
                                        node,
                                        tuple(sorted(nodes, key=lambda x: x.node_id)),
                                    )
                                    for (v, nodes) in node.context[self.KEY].written.items()
                                    if v in node.context[self.KEY].reads_prior_calls[c]
                                }

                            if read_then_written:
                                # calls are ordered
                                finding_key = FindingKey(
                                    function=node.function,
                                    calls=to_hashable(node.context[self.KEY].calls),
                                    send_eth=to_hashable(node.context[self.KEY].send_eth),
                                )

                                result[finding_key] |= set(read_then_written)
        return result

    def _detect(self):  # pylint: disable=too-many-branches
        """"""
        super()._detect()

        reentrancies = self.find_reentrancies()

        results = []

        result_sorted = sorted(list(reentrancies.items()), key=lambda x: x[0].function.name)
        varsWritten: List[FindingValue]
        for (func, calls, send_eth), varsWritten in result_sorted:
            calls = sorted(list(set(calls)), key=lambda x: x[0].node_id)
            send_eth = sorted(list(set(send_eth)), key=lambda x: x[0].node_id)
            varsWritten = sorted(varsWritten, key=lambda x: (x.variable.name, x.node.node_id))

            info = ["Reentrancy in ", func, ":\n"]
            info += ["\tExternal calls:\n"]
            for (call_info, calls_list) in calls:
                info += ["\t- ", call_info, "\n"]
                for call_list_info in calls_list:
                    if call_list_info != call_info:
                        info += ["\t\t- ", call_list_info, "\n"]
            if calls != send_eth and send_eth:
                info += ["\tExternal calls sending eth:\n"]
                for (call_info, calls_list) in send_eth:
                    info += ["\t- ", call_info, "\n"]
                    for call_list_info in calls_list:
                        if call_list_info != call_info:
                            info += ["\t\t- ", call_list_info, "\n"]
            info += ["\tState variables written after the call(s):\n"]
            for finding_value in varsWritten:
                info += ["\t- ", finding_value.node, "\n"]
                for other_node in finding_value.nodes:
                    if other_node != finding_value.node:
                        info += ["\t\t- ", other_node, "\n"]

            # Create our JSON result
            res = self.generate_result(info)

            # Add the function with the re-entrancy first
            res.add(func)

            # Add all underlying calls in the function which are potentially problematic.
            for (call_info, calls_list) in calls:
                res.add(call_info, {"underlying_type": "external_calls"})
                for call_list_info in calls_list:
                    if call_list_info != call_info:
                        res.add(
                            call_list_info,
                            {"underlying_type": "external_calls_sending_eth"},
                        )

            # If the calls are not the same ones that send eth, add the eth sending nodes.
            if calls != send_eth:
                for (call_info, calls_list) in send_eth:
                    res.add(call_info, {"underlying_type": "external_calls_sending_eth"})
                    for call_list_info in calls_list:
                        if call_list_info != call_info:
                            res.add(
                                call_list_info,
                                {"underlying_type": "external_calls_sending_eth"},
                            )

            # Add all variables written via nodes which write them.
            for finding_value in varsWritten:
                res.add(
                    finding_value.node,
                    {
                        "underlying_type": "variables_written",
                        "variable_name": finding_value.variable.name,
                    },
                )
                for other_node in finding_value.nodes:
                    if other_node != finding_value.node:
                        res.add(
                            other_node,
                            {
                                "underlying_type": "variables_written",
                                "variable_name": finding_value.variable.name,
                            },
                        )

            # Append our result
            results.append(res)

        return results