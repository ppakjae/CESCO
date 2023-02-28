from mythril.analysis import solver
from mythril.analysis.report import Issue
from mythril.analysis.swc_data import DEPRECATED_FUNCTIONS_USAGE
from mythril.exceptions import UnsatError
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt.bool import And
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)
import logging
from mythril.laser.ethereum.function_managers import keccak_function_manager


log = logging.getLogger(__name__)

DESCRIPTION = """
Check if the contract uses deprecated Solidity functions
"""


class DeprecatedFunctionsUsage(DetectionModule):
    """This module checks if the contract uses deprecated Solidity functions."""

    name = "Contract uses deprecated Solidity functions"
    swc_id = DEPRECATED_FUNCTIONS_USAGE
    description = DESCRIPTION
    entry_point = EntryPoint.COMPILE

    def __init__(self):
        super().__init__()

    def reset_module(self):
        """
        Resets the module
        :return:
        """
        super().reset_module()

    def _execute(self, path) -> None:

        log.info("Depreacted functions usage module: Analyzing solidity file lines")
        
        all_issues=[]
        
        description_head = ("Several functions and operators in Solidity are deprecated."
                            "Using them leads to reduced code quality."
                            "With new major versions of the Solidity compiler, deprecated functions and operators may result in side effects and compile errors."
        )  

        with open(path) as f:
            lineno = 0
            contract= ""
            function_name = ""
            for line in f.read().split("\n"):
                lineno += 1
                deprecated_functions = ["suicide(", "block.blockhash(", "sha3(", "callcode(", "throw", "msg.gas", "constant", "var"]
                if "contract" in line:
                    contract = line.split(" ")[1]
                elif "function" in line:
                    function_name = line.strip().split(" ", 1)[1][:-9]
                for func in deprecated_functions:
                    if func in line:
                        issue = Issue(
                            contract=contract,
                            function_name=function_name,
                            # address="line number is " + str(lineno),
                            address=lineno,
                            swc_id=DEPRECATED_FUNCTIONS_USAGE,
                            bytecode="",
                            title="DEPRECATED_FUNCTIONS_USAGE",
                            severity="severity",
                            description_head=description_head,
                            description_tail="line " + str(lineno) + ": " +  str(line.strip()) + " this function is deprecated"                        )
                        all_issues.append(issue)
        
        return all_issues

        # return self._analyze_state(state, path)

    def _analyze_state(self, state):
        log.info("Suicide module: Analyzing suicide instruction")
        instruction = state.get_current_instruction()

        log.debug("SELFDESTRUCT in function %s", state.environment.active_function_name)

        description_head = ""
            
        try:
            
            constraints = state.world_state.constraints
                
            transaction_sequence = solver.get_transaction_sequence(
                state, constraints
            )

            description_tail = (
                ""
            )

            

            issue = Issue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=instruction["address"],
                swc_id=DEPRECATED_FUNCTIONS_USAGE,
                bytecode=state.environment.code.bytecode,
                title="Deprecated Solidity Functions Usage",
                severity="Low",
                description_head=description_head,
                description_tail=description_tail,
                transaction_sequence=transaction_sequence,
                gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            )
            state.annotate(
                IssueAnnotation(
                    conditions=[And(*constraints)], issue=issue, detector=self
                )
            )

            return [issue]
        except UnsatError:
            log.debug("No model found")

        return []


detector = DeprecatedFunctionsUsage()
