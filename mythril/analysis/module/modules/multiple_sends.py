"""This module contains the detection code to find multiple sends occurring in
a single transaction."""
from copy import copy
from typing import cast, List
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.analysis.report import Issue
from mythril.analysis.solver import get_transaction_sequence, UnsatError
from mythril.analysis.swc_data import MULTIPLE_SENDS
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.ethereum.state.annotation import StateAnnotation
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import And
import logging

log = logging.getLogger(__name__)


class MultipleSendsAnnotation(StateAnnotation):
    def __init__(self) -> None:
        self.call_offsets = []  # type: List[int]

    def __copy__(self):
        result = MultipleSendsAnnotation()
        result.call_offsets = copy(self.call_offsets)
        return result


class MultipleSends(DetectionModule):
    """This module checks for multiple sends in a single transaction."""

    name = "Multiple external calls in the same transaction"
    swc_id = MULTIPLE_SENDS
    description = "Check for multiple sends in a single transaction"
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["CALL", "DELEGATECALL", "STATICCALL", "CALLCODE", "RETURN", "STOP"]

    def _execute(self, state: GlobalState) -> None:
        return self._analyze_state(state)

    def _analyze_state(self, state: GlobalState):
        """
        :param state: the current state
        :return: returns the issues for that corresponding state
        """
        instruction = state.get_current_instruction()

        # Global State에서 MultipleSendsAnnotation 가져와서 list[]형태로 만들어주기
        annotations = cast(
            List[MultipleSendsAnnotation],
            list(state.get_annotations(MultipleSendsAnnotation)),
        )

        # 빈 리스트이면 객체 생성
        if len(annotations) == 0:
            state.annotate(MultipleSendsAnnotation())
            annotations = cast(
                List[MultipleSendsAnnotation],
                list(state.get_annotations(MultipleSendsAnnotation)),
            )

        call_offsets = annotations[0].call_offsets

        if instruction["opcode"] in ["CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"]:
            call_offsets.append(state.get_current_instruction()["address"])

        else:  # RETURN or STOP
            # 최초 호출은 상관이 없으니 이후에 발생하는 것에 대해서 에러
            for offset in call_offsets[1:]:
                try:
                    transaction_sequence = get_transaction_sequence(
                        state, state.world_state.constraints
                    )
                except UnsatError:
                    continue
                description_tail = (
                    "This call is executed following another call within the same transaction. It is possible "
                    "that the call never gets executed if a prior call fails permanently. This might be caused "
                    "intentionally by a malicious callee. If possible, refactor the code such that each transaction "
                    "only executes one external call or "
                    "make sure that all callees can be trusted (i.e. they’re part of your own codebase)."
                )
                '''
                "이 통화는 동일한 트랜잭션 내의 다른 통화에 이어 실행됩니다. 
                이전 호출이 영구적으로 실패하면 호출이 실행되지 않을 수 있습니다.
                 이 문제는 악의적인 호출자에 의해 의도적으로 발생할 수 있습니다. 
                 가능하면 각 트랜잭션이 하나의 외부 통화만 실행하도록 코드를 리팩터링하거나 
                 모든 통화자를 신뢰할 수 있는지 확인하십시오(즉, 사용자 자신의 코드베이스의 일부임)."
                '''

                issue = Issue(
                    contract=state.environment.active_account.contract_name,
                    function_name=state.environment.active_function_name,
                    address=offset,
                    swc_id=MULTIPLE_SENDS,
                    bytecode=state.environment.code.bytecode,
                    title="Multiple Calls in a Single Transaction",
                    severity="Low",
                    description_head="Multiple calls are executed in the same transaction.",
                    description_tail=description_tail,
                    gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                    transaction_sequence=transaction_sequence,
                )
                state.annotate(
                    IssueAnnotation(
                        conditions=[And(*state.world_state.constraints)],
                        issue=issue,
                        detector=self,
                    )
                )
                return [issue]

        return []


detector = MultipleSends()
