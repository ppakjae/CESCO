import pytest
from mythril.disassembler.disassembly import Disassembly
from mythril.laser.ethereum.state.environment import Environment
from mythril.laser.ethereum.state.machine_state import MachineState
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.laser.ethereum.instructions import Instruction
from mythril.laser.ethereum.transaction.transaction_models import (
    MessageCallTransaction,
    TransactionStartSignal,
)
from mythril.laser.ethereum.state.calldata import ConcreteCalldata
from mythril.support.support_utils import get_code_hash

last_state = None
created_contract_account = None


def generate_salted_address(code_str, salt, caller):
    addr = hex(caller.value)[2:]
    addr = "0" * (40 - len(addr)) + addr

    salt = hex(salt)[2:]
    salt = "0" * (64 - len(salt)) + salt

    contract_address = int(
        get_code_hash("0xff" + addr + salt + get_code_hash(code_str)[2:])[26:], 16
    )
    return contract_address


def test_create2():
    world_state = WorldState()
    account = world_state.create_account(balance=10, address=101)
    account.code = Disassembly("60606040")
    environment = Environment(account, None, None, None, None, None)
    og_state = GlobalState(
        world_state, environment, None, MachineState(gas_limit=8000000)
    )
    code_raw = []
    code = "606060406060"
    for i in range(len(code) // 2):
        code_raw.append(int(code[2 * i : 2 * (i + 1)], 16))
    calldata = ConcreteCalldata("1", code_raw)
    environment.calldata = calldata
    og_state.transaction_stack.append(
        (MessageCallTransaction(world_state=WorldState(), gas_limit=8000000), None)
    )
    value = 3
    salt = 10
    og_state.mstate.stack = [salt, 6, 0, value]
    instruction = Instruction("create2", dynamic_loader=None)

    # Act + Assert
    with pytest.raises(TransactionStartSignal) as t:
        _ = instruction.evaluate(og_state)[0]
    assert t.value.transaction.call_value == value
    assert t.value.transaction.code.bytecode == code
    assert t.value.transaction.callee_account.address == generate_salted_address(
        code, salt, account.address
    )
