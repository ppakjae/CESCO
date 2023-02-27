"""This module contains the detection code for potentially insecure low-level
calls."""

from mythril.analysis import solver
from mythril.analysis.potential_issues import (
    PotentialIssue,
    get_potential_issues_annotation,
)
from mythril.laser.ethereum.state.constraints import Constraints
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.smt import UGT, symbol_factory, Or, BitVec
from mythril.laser.ethereum.natives import PRECOMPILE_COUNT
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.exceptions import UnsatError
import logging

from mythril.laser.smt import simplify
from copy import deepcopy
from mythril.analysis.report import Issue
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.laser.ethereum.util import get_concrete_int
from mythril.laser.smt.bool import And
import re

TRANSACTION_ORDER_DEPENDENCY = 144

log = logging.getLogger(__name__)

DESCRIPTION = '''
MODULE DESCRIPTION:
This module finds the existance of transaction order dependence vulnerabilities.
The following webpage contains an extensive description of the vulnerability: 
https://consensys.github.io/smart-contract-best-practices/known_attacks/#transaction-ordering-dependence-tod-front-running
'''


class TransactionOrderDependency(DetectionModule):
    """This module searches for low level calls (e.g. call.value()) that
    forward all gas to the callee."""

    name = "Transaction Order Dependency"
    swc_id = TRANSACTION_ORDER_DEPENDENCY
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["CALL"]

    def _execute(self, state: GlobalState) -> None:
        """

        :param state:
        :return:
        """

        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state: GlobalState):
        """

        :param state:
        :return:
        """
        try:

            interesting_storages = list(_get_influencing_storages(state))
            changing_sstores = list(_get_influencing_sstores(state, interesting_storages))

            if len(changing_sstores) > 0:
                
                to = state.mstate.stack[-2]

                constraints = (
                    state.world_state.constraints
                    + [to == ACTORS.attacker]
                )

                transaction_sequence = solver.get_transaction_sequence(
                    state, constraints
                )

                instruction = state.get_current_instruction()
                issue = Issue(
                    contract=state.environment.active_account.contract_name,
                    function_name=state.environment.active_function_name,
                    address=instruction["address"],
                    swc_id=TRANSACTION_ORDER_DEPENDENCY,
                    bytecode=state.environment.code.bytecode,
                    title="Unprotected Transaction Order",
                    severity="High",
                    description_head="description_head",
                    description_tail="description_tail",
                    transaction_sequence=transaction_sequence,
                    gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                )

                state.annotate(
                    IssueAnnotation(
                        conditions=[And(*constraints)], issue=issue, detector=self
                    )
                )

                return [issue]
        except:
            log.debug("No model found")
        return []
    
def _get_influencing_storages(state: GlobalState):
    gas = state.mstate.stack[-1]
    to = state.mstate.stack[-2]
    value = state.mstate.stack[-3]
    storages = []

    if to.symbolic is False:
        storages += _dependent_on_storage(to.value)
    if value.symbolic is False:
        storages += _dependent_on_storage(value.value)

    for storage in storages:
        variable = _get_storage_variable(storage, state)
        can_change = _can_change(state.world_state.constraints, variable, gas)
        if can_change:
            yield storage

def _dependent_on_storage(expression):
        
    pattern = re.compile(r"storage_[a-z0-9_&^]+")
    return pattern.findall(str(simplify(expression)))
    
def _get_storage_variable(storage, state):

    index = int(re.search('[0-9]+', storage).group())

    try:
        return state.environment.active_account.storage(index)
    except:
        return None

def _can_change(constraints, variable, gas):
    _constraints = deepcopy(constraints)

    try:
        model = solver.get_model(_constraints + [UGT(gas, symbol_factory.BitVecVal(2300, 256))])
        
        try:
            initial_value = int(str(model.eval(variable, model_completion=True)))
            _constraints.append(variable != initial_value)
            solver.get_model(_constraints)
            return True

        except UnsatError:
            return False

    except UnsatError:
        return False


def _get_influencing_sstores(state, interesting_storages):
    for sstore_state, node in _get_states_with_opcode(state, "SSTORE"):
        index, value = sstore_state.mstate.stack[-1], sstore_state.mstate.stack[-2]
        try:
            index = get_concrete_int(index)
        except AttributeError:
            index = str(index)
        if "storage_{}".format(index) not in interesting_storages:
            continue
        yield sstore_state, node

# sstore가 들어가 잇는 state가져오기
# 예전과 방식이 바뀐 느낌.. 가져오느게 다름.
def _get_states_with_opcode(state, opcode):
    for k in state.node:
        node = state.nodes[k]
        for _state in node.states:
            if state.get_current_instruction()["opcode"] == opcode:
                yield state, node

    
    
    





detector = TransactionOrderDependency()
