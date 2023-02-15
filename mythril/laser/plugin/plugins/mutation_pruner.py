from mythril.laser.plugin.signals import PluginSkipWorldState
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.plugin.plugins.plugin_annotations import MutationAnnotation
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.smt import UGT, symbol_factory
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)
from mythril.analysis import solver
from mythril.exceptions import UnsatError


class MutationPrunerBuilder(PluginBuilder):
    name = "mutation-pruner"

    def __call__(self, *args, **kwargs):
        return MutationPruner()


class MutationPruner(LaserPlugin):
    """Mutation pruner plugin

    Let S be a world state from which T is a symbolic transaction, and S' is the resulting world state.
    In a situation where T does not execute any mutating instructions we can safely abandon further analysis on top of
    state S'. This is for the reason that we already performed analysis on S, which is equivalent.

    This optimization inhibits path explosion caused by "clean" behaviour

    The basic operation of this plugin is as follows:
     - Hook all mutating operations and introduce a MutationAnnotation to the global state on execution of the hook
     - Hook the svm EndTransaction on execution filter the states that do not have a mutation annotation
    

    S를 world state로 하고, 여기서 T는 symbolic transaction이고, S'는 결과적인 world state라고 하자.
    T가 어떠한 돌연변이 명령도 실행하지 않는 상황에서 우리는 S' 상태 위의 추가 분석을 안전하게 포기할 수 있다. 
    이것은 우리가 이미 동등한 S에 대한 분석을 수행한 이유입니다.

    이 최적화는 "깨끗한" 동작으로 인한 경로 폭발을 방지합니다

    이 플러그인의 기본 작동은 다음과 같습니다:
     - 모든 변환 작업을 후크하고 후크 실행 시 전역 상태에 MutationAnnotation을 추가합니다
     - 실행 시 svm EndTransaction을 후크하여 변환 주석이 없는 상태를 필터링합니다
    """

    def initialize(self, symbolic_vm: LaserEVM):
        """Initializes the mutation pruner

        Introduces hooks for SSTORE operations
        :param symbolic_vm:
        :return:
        """

        @symbolic_vm.pre_hook("SSTORE")
        def sstore_mutator_hook(global_state: GlobalState):
            global_state.annotate(MutationAnnotation())

        """FIXME: Check for changes in world_state.balances instead of adding MutationAnnotation for all calls.
           Requires world_state.starting_balances to be initalized at every tx start *after* call value has been added.
           
           모든 호출에 대해 MutationAnnotation을 추가하는 대신 world_state.balances의 변경 사항을 확인합니다. 
           *이후* 호출 값이 추가될 때마다 world_state.starting_balance를 초기화해야 합니다.
        """

        @symbolic_vm.pre_hook("CALL")
        def call_mutator_hook(global_state: GlobalState):
            global_state.annotate(MutationAnnotation())

        @symbolic_vm.pre_hook("STATICCALL")
        def staticcall_mutator_hook(global_state: GlobalState):
            global_state.annotate(MutationAnnotation())

        @symbolic_vm.laser_hook("add_world_state")
        def world_state_filter_hook(global_state: GlobalState):

            if isinstance(
                global_state.current_transaction, ContractCreationTransaction
            ):
                return

            if isinstance(global_state.environment.callvalue, int):
                callvalue = symbol_factory.BitVecVal(
                    global_state.environment.callvalue, 256
                )
            else:
                callvalue = global_state.environment.callvalue

            try:
                # 새로운 world state를 만들기 위해서는 call value가 0보다 커야 할거같다.
                constraints = global_state.world_state.constraints + [
                    UGT(callvalue, symbol_factory.BitVecVal(0, 256))
                ]

                solver.get_model(constraints)
                return
            except UnsatError:
                # callvalue is constrained to 0, therefore there is no balance based world state mutation
                pass

            if len(list(global_state.get_annotations(MutationAnnotation))) == 0:
                raise PluginSkipWorldState
