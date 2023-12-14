"""
  Moudle detecting block-values-as-time-proxies

"""
from typing import List,Tuple
from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.cfg.node import Node
from slither.core.declarations import Function,Contract
from slither.core.declarations.solidity_variables import SolidityVariableComposed,SolidityVariable
from slither.detectors.abstract_detector import AbstractDetector,DetectorClassification
from slither.slithir.operations import Binary,BinaryType
from slither.core.compilation_unit import SlitherCompilationUnit

def blockvalue(func:Function) -> List[Node]:
    ret = set()
    for node in func.nodes:
        if node.contains_require_or_assert():
            for var in node.variables_read:
                if is_dependent(var,SolidityVariableComposed("block.timestamp"),func.contract):
                    ret.add(node)
                if is_dependent(var,SolidityVariable("now"),func.contract):
                    ret.add(node)
                if is_dependent(var,SolidityVariableComposed("block.number"),func.contract):
                    ret.add(node)
        for ir in node.irs:
            if isinstance(ir,Binary) and BinaryType.return_bool(ir.type):
                for var in ir.read:
                    if is_dependent(var,SolidityVariableComposed("block.timestamp"),func.contract):
                        ret.add(node)
                    if is_dependent(var,SolidityVariable("now"),func.contract):
                        ret.add(node)
                    if is_dependent(var,SolidityVariableComposed("block.number"),func.contract):
                        ret.add(node)
    return sorted(list(ret),key=lambda x: x.node_id)

def _detect_blockvalue( contract:Contract, ) -> List[Tuple[Function,List[Node]]]:
    """
    Args:
        contract (Contract)
    Returns:
        list((Function), (list (Node)))
    """
    ret = []
    for f in [f for f in contract.functions if f.contract_declarer == contract]:
        nodes = blockvalue(f)
        if nodes:
            ret.append((f, nodes))
    return ret

class block_values_as_time_proxies(AbstractDetector):

    ARGUMENT = "Block-values-as-a-proxy-for-time"
    HELP = "Incorrect use of time proxy`"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-116#block-values-as-time-proxies"

    WIKI_TITLE = "Block values as a proxy for time"
    WIKI_DESCRIPTION = (
        "Contracts often need access to time values to perform certain types of functionality.Values such as block.timestamp, and block.number can give you a sense of the current time or a time delta, however, they are not safe to use for most purposes.In the case of block.timestamp, developers often attempt to use it to trigger time-dependent events. As Ethereum is decentralized, nodes can synchronize time only to some degree. Moreover, malicious miners can alter the timestamp of their blocks, especially if they can gain advantages by doing so. However, miners can't set a timestamp smaller than the previous one (otherwise the block will be rejected), nor can they set the timestamp too far ahead in the future. Taking all of the above into consideration, developers can't rely on the preciseness of the provided timestamp.As for block.number, considering the block time on Ethereum is generally about 14 seconds, it's possible to predict the time delta between blocks. However, block times are not constant and are subject to change for a variety of reasons, e.g. fork reorganisations and the difficulty bomb. Due to variable block times, block.number should also not be relied on for precise calculations of time."
    )
    WIKI_EXPLOIT_SCENARIO = """"
    pragma solidity ^0.5.0;

    contract TimedCrowdsale {

      event Finished();
      event notFinished();

      // Sale should finish exactly at January 1, 2019
      function isSaleFinished() private returns (bool) {
        return block.timestamp >= 1546300800;
      }

      function run() public {
        if (isSaleFinished()) {
            emit Finished();
        } else {
            emit notFinished();
        }
      }

    }   
       """
    WIKI_RECOMMENDATION = "Developers should write smart contracts with the notion that block values are not precise, and the use of them can lead to unexpected effects. Alternatively, they may make use oracles."


    def _detect(self):

        results = []

        for c in self.compilation_unit.contracts_derived:
            detect_blockvalue = _detect_blockvalue(c)
            for (func,nodes) in detect_blockvalue:
                info = [func," use block-value as time proxy\n"]
                info += ["\t Wrong time proxy:\n"]
                nodes.sort(key=lambda x: x.node_id)

                for node in nodes:
                    info += ["\t- ",node,"\n"]
                res = self.generate_result(info)

                results.append(res)

        return results
