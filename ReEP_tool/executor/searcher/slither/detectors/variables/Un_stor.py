"""
    Module detecting Honey Pot(uninitialized-storage-advance)

    Recursively explore the CFG to only report uninitialized storage variables that are
    written before being read
"""

from socket import MsgFlag
from slither.core.declarations.function import Function
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UninitializedStorageVarsAdv(AbstractDetector):

    ARGUMENT = "uninitialized-storage-advance"
    HELP = "Uninitialized storage variables advance"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#uninitialized-storage-variablesXXXXXX"

    WIKI_TITLE = "Uninitialized storage variables advance"
    WIKI_DESCRIPTION = "XXXXXXXXXAn uninitialized storage variable will act as a reference to the first state variable, and can override a critical variable."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Uninitialized{
    address owner = msg.sender;

    struct St{
        uint a;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
   }

    function func() onlyOwner {
        St st;
        st.a = 0x0;
    }
}
```
Bob calls `func`. As a result, `owner` is overridden to `0`XXXXXXXXX.
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Initialize all storage variables XXXXXXXXXX."

    # node.context[self.key] contains the uninitialized storage variables
    key = "UNINITIALIZEDSTORAGE-ADV"

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
            str(n.expression)
            for n in all_conditional_nodes
            if "msg.sender" in [v.name for v in n.solidity_variables_read]
        ]
        return all_conditional_nodes_on_msg_sender

    def _detect_uninitialized(self, function, node, visited):
        if node in visited:
            return

        visited = visited + [node]

        fathers_context = []

        for father in node.fathers:
            if self.key in father.context:
                fathers_context += father.context[self.key]

        # Exclude paths that dont bring further information
        if node in self.visited_all_paths:
            if all(f_c in self.visited_all_paths[node] for f_c in fathers_context):
                return
        else:
            self.visited_all_paths[node] = []

        self.visited_all_paths[node] = list(set(self.visited_all_paths[node] + fathers_context))

        if self.key in node.context:
            fathers_context += node.context[self.key]

        variables_read = node.variables_read
        for uninitialized_storage_variable in fathers_context:
            if uninitialized_storage_variable in variables_read:
                self.results.append((function, uninitialized_storage_variable))

        # Only save the storage variables that are not yet written
        uninitialized_storage_variables = list(set(fathers_context) - set(node.variables_written))
        node.context[self.key] = uninitialized_storage_variables

        for son in node.sons:
            self._detect_uninitialized(function, son, visited)

    def _detect(self):
        """Detect uninitialized storage variables

        Recursively visit the calls
        Returns:
            dict: [contract name] = set(storage variable uninitialized)
        """
        results = []

        # pylint: disable=attribute-defined-outside-init
        self.results = []
        self.visited_all_paths = {}

        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                # 检测是否有msg.sender权限限定
                msg_sender_condition = self.get_msg_sender_checks(function)
                if len(msg_sender_condition) >= 1:
                    # print(msg_sender_condition)
                    # if function.is_implemented:
                    if function.is_implemented and not function.payable:
                        uninitialized_storage_variables = [
                            v for v in function.local_variables if v.is_storage and v.uninitialized
                        ]
                        function.entry_point.context[self.key] = uninitialized_storage_variables
                        self._detect_uninitialized(function, function.entry_point, [])

        for (function, uninitialized_storage_variable) in self.results:
            info = [
                uninitialized_storage_variable,
                " is a storage variable never initializedXXXXX\n",
            ]
            json = self.generate_result(info)
            results.append(json)

        return results