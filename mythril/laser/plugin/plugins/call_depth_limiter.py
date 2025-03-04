from mythril.laser.plugin.signals import PluginSkipState
from mythril.laser.plugin.interface import LaserPlugin
from mythril.laser.plugin.builder import PluginBuilder
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.svm import LaserEVM


class CallDepthLimitBuilder(PluginBuilder):
    name = "call-depth-limit"

    def __call__(self, *args, **kwargs):
        return CallDepthLimit(kwargs["call_depth_limit"])


class CallDepthLimit(LaserPlugin):
    def __init__(self, call_depth_limit: int):
        self.call_depth_limit = call_depth_limit

    def initialize(self, symbolic_vm: LaserEVM):
        """Initializes the mutation pruner

        Introduces hooks for SSTORE operations
        STORE 작업을 위한 후크 도입
        :param symbolic_vm:
        :return:
        """

        @symbolic_vm.pre_hook("CALL")
        def sstore_mutator_hook(global_state: GlobalState):
            # transaction 수가 call 하나와 같으므로
            if len(global_state.transaction_stack) - 1 == self.call_depth_limit:
                raise PluginSkipState
