"""This module contains the detection code for predictable variable
dependence."""
import logging
from copy import copy
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.analysis import solver
from mythril.analysis.swc_data import TX_ORIGIN_USAGE
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import And
from typing import List

log = logging.getLogger(__name__)


class TxOriginAnnotation:
    """Symbol annotation added to a variable that is initialized with a call to the ORIGIN instruction."""

    def __init__(self) -> None:
        pass


class TxOrigin(DetectionModule):
    """This module detects whether control flow decisions are made based on the transaction origin.
    이 모듈은 트랜잭션 ORIGIN 기반으로 제어 흐름 결정이 이루어지는지 여부를 감지합니다.
    """

    name = "Control flow depends on tx.origin"
    swc_id = TX_ORIGIN_USAGE
    description = "Check whether control flow decisions are influenced by tx.origin"
    entry_point = EntryPoint.CALLBACK

    pre_hooks = ["JUMPI"]
    post_hooks = ["ORIGIN"]

    def _execute(self, state: GlobalState) -> List[Issue]:
        """

        :param state:
        :return:
        """
        return self._analyze_state(state)

    def _analyze_state(self, state: GlobalState) -> List[Issue]:
        """

        :param state:
        :return:
        """

        issues = []

        if state.get_current_instruction()["opcode"] == "JUMPI":
            # We're in JUMPI prehook

            
            for annotation in state.mstate.stack[-2].annotations:

                if isinstance(annotation, TxOriginAnnotation):
                    constraints = copy(state.world_state.constraints)

                    try:
                        transaction_sequence = solver.get_transaction_sequence(
                            state, constraints
                        )
                    except UnsatError:
                        continue

                    description = (
                        "The tx.origin environment variable has been found to influence a control flow decision. "
                        "Note that using tx.origin as a security control might cause a situation where a user "
                        "inadvertently authorizes a smart contract to perform an action on their behalf. It is "
                        "recommended to use msg.sender instead."
                    )
                    '''
                    "tx.origin 환경 변수가 제어 흐름 결정에 영향을 미치는 것으로 확인되었습니다. 
                    tx.origin을 보안 제어로 사용하면 사용자가 실수로 
                    스마트 계약에서 작업을 대신 수행하도록 권한을 부여하는 상황이 발생할 수 있습니다. 
                    대신 msg.sender를 사용하는 것이 좋습니다."
                    '''

                    severity = "Low"

                    """
                    Note: We report the location of the JUMPI instruction. Usually this maps to an if or
                    require statement.
                    """

                    issue = Issue(
                        contract=state.environment.active_account.contract_name,
                        function_name=state.environment.active_function_name,
                        address=state.get_current_instruction()["address"],
                        swc_id=TX_ORIGIN_USAGE,
                        bytecode=state.environment.code.bytecode,
                        title="Dependence on tx.origin",
                        severity=severity,
                        description_head="Use of tx.origin as a part of authorization control.",
                        description_tail=description,
                        gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                        transaction_sequence=transaction_sequence,
                    )
                    state.annotate(
                        IssueAnnotation(
                            conditions=[And(*constraints)], issue=issue, detector=self
                        )
                    )

                    issues.append(issue)

        else:

            # In ORIGIN posthook

            state.mstate.stack[-1].annotate(TxOriginAnnotation())

        return issues


detector = TxOrigin()
