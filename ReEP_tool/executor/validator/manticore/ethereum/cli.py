from .detectors import (
    DetectInvalid,
    DetectIntegerOverflow,
    DetectUninitializedStorage,
    DetectUninitializedMemory,
    DetectReentrancySimple,
    DetectReentrancyAdvanced,
    DetectUnusedRetVal,
    DetectSuicidal,
    DetectDelegatecall,
    DetectExternalCallAndLeak,
    DetectEnvInstruction,
    DetectRaceCondition,
    DetectorClassification,
    DetectManipulableBalance,
)
from ..core.plugin import Profiler
from .manticore import ManticoreEVM
from .plugins import (
    FilterFunctions,
    LoopDepthLimiter,
    VerboseTrace,
    KeepOnlyIfStorageChanges,
    SkipRevertBasicBlocks,
)
from ..utils.nointerrupt import WithKeyboardInterruptAs
from ..utils import config
from .abi import ABI
import sys
import time
from ..core.smtlib import (
    Operators,
    Constant,
    simplify,
    istainted,
    issymbolic,
    get_taints,
    taint_with,
)

consts = config.get_group("cli")
consts.add("profile", default=False, description="Enable worker profiling mode")
consts.add(
    "explore_balance",
    default=False,
    description="Explore states in which only the balance was changed",
)

consts.add(
    "skip_reverts",
    default=False,
    description="Simply avoid exploring basic blocks that end in a REVERT",
)


def get_detectors_classes():
    return [
        DetectInvalid,
        DetectIntegerOverflow,
        DetectUninitializedStorage,
        DetectUninitializedMemory,
        DetectReentrancySimple,
        DetectReentrancyAdvanced,
        DetectUnusedRetVal,
        DetectSuicidal,
        DetectDelegatecall,
        DetectExternalCallAndLeak,
        DetectEnvInstruction,
        DetectManipulableBalance,
        # The RaceCondition detector has been disabled for now as it seems to collide with IntegerOverflow detector
        # DetectRaceCondition
    ]


def choose_detectors(args):
    all_detector_classes = get_detectors_classes()
    detectors = {d.ARGUMENT: d for d in all_detector_classes}
    arguments = list(detectors.keys())

    detectors_to_run = []

    if not args.exclude_all:
        exclude = []

        if args.detectors_to_exclude:
            exclude = args.detectors_to_exclude.split(",")

            for e in exclude:
                if e not in arguments:
                    raise Exception(
                        f"{e} is not a detector name, must be one of {arguments}. See also `--list-detectors`."
                    )

        for arg, detector_cls in detectors.items():
            if arg not in exclude:
                detectors_to_run.append(detector_cls)

    return detectors_to_run


# def ethereum_main(args, logger):
#     m = ManticoreEVM(workspace_url=args.workspace)

#     if args.quick_mode:
#         args.avoid_constant = True
#         args.exclude_all = True
#         args.only_alive_testcases = True
#         consts_evm = config.get_group("evm")
#         consts_evm.oog = "ignore"
#         consts.skip_reverts = True

#     with WithKeyboardInterruptAs(m.kill):
#         if consts.skip_reverts:
#             m.register_plugin(SkipRevertBasicBlocks())

#         if consts.explore_balance:
#             m.register_plugin(KeepOnlyIfStorageChanges())

#         if args.verbose_trace:
#             m.register_plugin(VerboseTrace())

#         if args.limit_loops:
#             m.register_plugin(LoopDepthLimiter())

#         for detector in choose_detectors(args):
#             m.register_detector(detector())

#         if consts.profile:
#             profiler = Profiler()
#             m.register_plugin(profiler)

#         if args.avoid_constant:
#             # avoid all human level tx that has no effect on the storage
#             filter_nohuman_constants = FilterFunctions(
#                 regexp=r".*", depth="human", mutability="constant", include=False
#             )
#             m.register_plugin(filter_nohuman_constants)

#         if m.plugins:
#             logger.info(f'Registered plugins: {", ".join(d.name for d in m.plugins)}')

#         logger.info("-------origin Beginning analysis--------")
#         start = time.time()
#         with m.kill_timeout():
#             m.multi_tx_analysis(
#                 args.argv[0],
#                 contract_name=args.contract,
#                 # tx_limit=args.txlimit,
#                 tx_limit=3,
#                 tx_use_coverage=not args.txnocoverage,
#                 # tx_send_ether=not args.txnoether,
#                 tx_send_ether= True,
#                 # tx_account=args.txaccount,
#                 tx_account="combo1",
#                 tx_preconstrain=args.txpreconstrain,
#                 compile_args=vars(args),  # FIXME
#             )
        
#         for state in m.all_states:
#             f_value = []
#             l_l = 0
#             l_p = []
#             is_exis = False
#             p = DetectReentrancyAdvanced()
#             l = DetectExternalCallAndLeak()
#             findings = l.get_findings(state)
#             findings1 = p.get_findings(state)
#             print("lllll",findings)
#             print("ppppp",findings1)

#             info_l = "Reachable ether leak1 to sender"
#             info_p = "Reentrancy multi-million ether bug"
#             for item in findings:
#                 v = item[2]
#                 if v == info_l:
#                     l_l = item[1]

#             for item in findings1:
#                 v = item[2]
#                 if v == info_p:
#                     l_p.append(item[1])
#             if l_l in l_p:
#                 is_exis = True

#             if is_exis:
#                 if len(state.platform.transactions) > 2:
#                     function_Name = "withdrawBalance()"
#                     # function_Name = "Collect(uint256)"
#                     # function_Name =func_name
#                     reentry_string = ABI.function_selector(function_Name)
#                     caller = state.platform.transactions[-1].caller
#                     balance2 = state.platform.get_balance(caller)
#                     d = state.platform.transactions[-1].data
#                     d1 = state.platform.transactions[-2].data[:4]
#                     value = state.platform.transactions[-2].value
#                     funcid, dynargs = ABI.deserialize(type_spec=function_Name, data=d)
#                     funcd = state.solve_one(funcid)
#                     funcd1 = state.solve_one(d1)
#                     tvaule = state.solve_one(value)
#                     balance2 = state.solve_one(balance2)
                
#                     print(funcd,reentry_string,funcd1,tvaule,balance2,findings)
#                     # Operators.AND(funcd == reentry_string, tvaule != 0)
#                     if m.generate_testcase(state, "maybe reentrancy?", only_if=funcd == reentry_string):
#                         expected_files = {"user_00000000." + ext for ext in ("summary", "constraints", "pkl", "tx.json", "tx", "trace", "logs","findings")}
#                         expected_files.add("state_00000000.pkl")
#                         print(funcd,reentry_string,funcd1,tvaule,balance2,findings)
#                         print("Bug found! see {}".format(m.workspace))
#                         # fname = filename +'_'+ contract_Name
#                         # fname = function_Name +'_'
#                         # newName="/data/home/wangzexu/manticore_pro/manticore-0.3.0/examples/evm/"+fname
#                         # os.rename(m.workspace,newName)

#                         end = time.time()
#                         ttime = end-start
#                         print(ttime)
#                         return ttime
#                 else:
#                     continue                        
#             else:
#                 continue

#         # if not args.no_testcases:
#         #     m.finalize(only_alive_states=args.only_alive_testcases)
#         # else:
#         #     m.kill()

#         for detector in list(m.detectors):
#             m.unregister_detector(detector)

#         for plugin in list(m.plugins):
#             m.unregister_plugin(plugin)





            # 
def ethereum_main(args, logger):
    m = ManticoreEVM(workspace_url=args.workspace)

    if args.quick_mode:
        args.avoid_constant = True
        args.exclude_all = True
        args.only_alive_testcases = True
        consts_evm = config.get_group("evm")
        consts_evm.oog = "ignore"
        consts.skip_reverts = True

    with WithKeyboardInterruptAs(m.kill):
        if consts.skip_reverts:
            m.register_plugin(SkipRevertBasicBlocks())

        if consts.explore_balance:
            m.register_plugin(KeepOnlyIfStorageChanges())

        if args.verbose_trace:
            m.register_plugin(VerboseTrace())

        if args.limit_loops:
            m.register_plugin(LoopDepthLimiter())

        for detector in choose_detectors(args):
            m.register_detector(detector())

        if consts.profile:
            profiler = Profiler()
            m.register_plugin(profiler)

        if args.avoid_constant:
            # avoid all human level tx that has no effect on the storage
            filter_nohuman_constants = FilterFunctions(
                regexp=r".*", depth="human", mutability="constant", include=False
            )
            m.register_plugin(filter_nohuman_constants)

        if m.plugins:
            logger.info(f'Registered plugins: {", ".join(d.name for d in m.plugins)}')

        logger.info("Beginning analysis")

        with m.kill_timeout():
            m.multi_tx_analysis(
                args.argv[0],
                contract_name=args.contract,
                tx_limit=args.txlimit,
                tx_use_coverage=not args.txnocoverage,
                tx_send_ether=not args.txnoether,
                tx_account=args.txaccount,
                tx_preconstrain=args.txpreconstrain,
                compile_args=vars(args),  # FIXME
            )

        if not args.no_testcases:
            m.finalize(only_alive_states=args.only_alive_testcases)
        else:
            m.kill()

        for detector in list(m.detectors):
            m.unregister_detector(detector)

        for plugin in list(m.plugins):
            m.unregister_plugin(plugin)