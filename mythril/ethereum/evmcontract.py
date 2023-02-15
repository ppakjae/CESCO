"""This module contains the class representing EVM contracts, aka Smart
Contracts."""
import re
import logging
import persistent

from mythril.support.support_utils import sha3
from mythril.disassembler.disassembly import Disassembly
from mythril.support.support_utils import get_code_hash

########
from mythril.interfaces import show_class_structure

log = logging.getLogger(__name__)


class EVMContract(persistent.Persistent):
    """This class represents an address with associated code (Smart
    Contract)."""

    def __init__(
        self, code="", creation_code="", name="Unknown", enable_online_lookup=False
    ):
        """Create a new contract.

        Workaround: We currently do not support compile-time linking.
        Dynamic contract addresses of the format __[contract-name]_____________ are replaced with a generic address
        Apply this for creation_code & code

        :param code:
        :param creation_code:
        :param name:
        :param enable_online_lookup:
        """
        creation_code = re.sub(r"(_{2}.{38})", "aa" * 20, creation_code)
        code = re.sub(r"(_{2}.{38})", "aa" * 20, code)
        self.creation_code = creation_code
        self.name = name
        self.code = code
        self.disassembly = Disassembly(code, enable_online_lookup=enable_online_lookup)
	#runtime disassembly
	#disassemly
        self.creation_disassembly = Disassembly(
            creation_code, enable_online_lookup=enable_online_lookup
        )

        
        
        '''
        print("====================Disassembly====================")
        self.printDetail("bytecode")
        self.printDetail("instruction_list")
        self.printDetail("func_hashes")
        self.printDetail("function_name_to_address")
        self.printDetail("address_to_function_name")
        self.printDetail("enable_online_lookup")
        self.printDetail("assign_bytecode")
        
        print(self.disassembly)
        print("===================================================")
        print()
        
        print("====================CreationDisassembly====================")
        
        self.printDetail("bytecode")
        self.printDetail("instruction_list")
        self.printDetail("func_hashes")
        self.printDetail("function_name_to_address")
        self.printDetail("address_to_function_name")
        self.printDetail("enable_online_lookup")
        self.printDetail("assign_bytecode")
        
        print(self.creation_disassembly)
        print("===================================================")
        print()
        
        print("====================EVMContract====================")
        self.printDetail("creation_code")
        self.printDetail("code")
        self.printDetail("name")
        self.printDetail("disassembly")
        self.printDetail("creation_disassembly")
        print("===================================================")
        print()
        '''

    @property
    def bytecode_hash(self):
        """

        :return: runtime bytecode hash
        """
        return get_code_hash(self.code)

    @property
    def creation_bytecode_hash(self):
        """

        :return: Creation bytecode hash
        """
        return get_code_hash(self.creation_code)

    def as_dict(self):
        """

        :return:
        """
        return {
            "name": self.name,
            "code": self.code,
            "creation_code": self.creation_code,
            "disassembly": self.disassembly,
        }

    def get_easm(self):
        """

        :return:
        """
        return self.disassembly.get_easm()

    def get_creation_easm(self):
        """

        :return:
        """
        return self.creation_disassembly.get_easm()

    def matches_expression(self, expression):
        """

        :param expression:
        :return:
        """
        str_eval = ""
        easm_code = None

        tokens = re.split("\s+(and|or|not)\s+", expression, re.IGNORECASE)

        for token in tokens:

            if token in ("and", "or", "not"):
                str_eval += " " + token + " "
                continue

            m = re.match(r"^code#([a-zA-Z0-9\s,\[\]]+)#", token)

            if m:
                if easm_code is None:
                    easm_code = self.get_easm()

                code = m.group(1).replace(",", "\\n")
                str_eval += '"' + code + '" in easm_code'
                continue

            m = re.match(r"^func#([a-zA-Z0-9\s_,(\\)\[\]]+)#$", token)

            if m:

                sign_hash = "0x" + sha3(m.group(1))[:4].hex()
                str_eval += '"' + sign_hash + '" in self.disassembly.func_hashes'

        return eval(str_eval.strip())
        
    def printDetail(self, value):
        print()
        print("self." + value)
        
        #value = self.value
        if value == "code":
            value = self.code
        elif value == "creation_code":
            value = self.creation_code
        elif value == "name":
            value = self.name
        elif value == "disassembly":
            value = self.disassembly        
        elif value == "creation_disassembly":
            value = self.creation_disassembly
        '''
        elif value == "bytecode":
            value = self.bytecode
        elif value == "instruction_list":
            value = self.instruction_list
        elif value == "func_hashes":
            value = self.func_hashes
        elif value == "function_name_to_address":
            value = self.function_name_to_address        
        elif value == "address_to_function_name":
            value = self.address_to_function_name
        elif value == "enable_online_lookup":
            value = self.enable_online_lookup     
        elif value == "assign_bytecode":
            value = self.assign_bytecode     
        '''
        
        print(type(value))
        print(value)
        print()

