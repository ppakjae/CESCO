
import logging
from copy import copy
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.analysis import solver
from mythril.analysis.swc_data import REQUIREMENT_VIOLATION
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import And
from typing import List

log = logging.getLogger(__name__)


class RequirementAnnotation:
    
    def __init__(self) -> None:
        pass


class ReViolation(DetectionModule):
    

    name = "Requirement violation"
    swc_id = REQUIREMENT_VIOLATION
    description = "Check requirement"
    entry_point = EntryPoint.CALLBACK

    post_hooks = ["PUSH1", "SLT", "SGT"]

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

        if state.environment.code.instruction_list[state.mstate.pc - 1]["opcode"] == "PUSH1":

            state.mstate.stack[-1].annotate(RequirementAnnotation())

        else:

            for annotation in state.mstate.stack[-1].annotations:

                if isinstance(annotation, RequirementAnnotation):
                    constraints = copy(state.world_state.constraints)

                    try:
                        transaction_sequence = solver.get_transaction_sequence(
                            state, constraints
                        )
                    except UnsatError:
                        continue
                    
                    if state.mstate.stack[-1] != 1:

                        description = (
                            "ERROR"
                        )

                        severity = "Low"

                        """
                        Note: We report the location of the JUMPI instruction. Usually this maps to an if or
                        require statement.
                        """
                        
                        issue = Issue(
                            contract=state.environment.active_account.contract_name,
                            function_name=state.environment.active_function_name,
                            address=state.get_current_instruction()["address"],
                            swc_id=REQUIREMENT_VIOLATION,
                            bytecode=state.environment.code.bytecode,
                            title="Requirement Violation",
                            severity=severity,
                            description_head="requirement violation",
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

            for annotation in state.mstate.stack[-2].annotations:

                if isinstance(annotation, RequirementAnnotation):
                    constraints = copy(state.world_state.constraints)

                    try:
                        transaction_sequence = solver.get_transaction_sequence(
                            state, constraints
                        )
                    except UnsatError:
                        continue
                    
                    if state.mstate.stack[-1] != 1:

                        description = (
                            "ERROR"
                        )

                        severity = "Low"

                        """
                        Note: We report the location of the JUMPI instruction. Usually this maps to an if or
                        require statement.
                        """

                        issue = Issue(
                            contract=state.environment.active_account.contract_name,
                            function_name=state.environment.active_function_name,
                            address=state.get_current_instruction()["address"],
                            swc_id=REQUIREMENT_VIOLATION,
                            bytecode=state.environment.code.bytecode,
                            title="Requirement Violation",
                            severity=severity,
                            description_head="requirement violation",
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


        return issues


detector = ReViolation()
