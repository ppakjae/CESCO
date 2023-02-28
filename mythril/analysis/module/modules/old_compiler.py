from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.ethereum.util import extract_binary, extract_version
from mythril.analysis.swc_data import FLOATING_PRAGMA, OUTDATED_COMPILER_VERSION
from semantic_version import Version, NpmSpec
from mythril.analysis.report import Issue
import re
import logging

DESCRIPTION = """
check compiler version.
"""
OUT_DESCRIPTION = """Using an outdated compiler version can be problematic especially 
if there are publicly disclosed bugs and issues that affect the current compiler version"""
FLO_DESCRIPTION = """Contracts should be deployed with the same compiler version and flags that they have been tested with thoroughly.
Locking the pragma helps to ensure that contracts do not accidentally get deployed using, for example, an outdated compiler version
that might introduce bugs that affect the contract system negatively.
"""

log = logging.getLogger(__name__)

class CheckOldCompiler(DetectionModule):
    '''check old compiler'''

    name = "Contract version is outdated"
    swc_id = "{} {}".format(OUTDATED_COMPILER_VERSION, FLOATING_PRAGMA)
    description = DESCRIPTION
    entry_point = EntryPoint.COMPILE 

    def __init__(self):
        super().__init__()
    
    def reset_module(self):
        super().reset_module()
    #0.4.24
    def _execute(self, path: str) ->None:
        #f = open(path, 'r')
        # f = open("../../../../solidity_examples/killbilly.sol", 'r')
        # f = open(path, 'r')
        compiler_version = None
        description_head = "Solidity Compiler related issues"
        description_tail = ""
        message = ""
        # while(True):
        try:
            # compiler_version = f.readline()
            # compiler_version = extract_version(f.read())
            with open(path) as f:
                compiler_version = extract_version(f.read())
            if compiler_version is None:
                message = "Not declare Solidity version in source file"
                # log.error(message)
                return []
            else:
                if re.findall("r'([\d.8.\d]*)/g", compiler_version) != None:
                    return []
                elif re.findall("r'([\d.7.\d]*)/g", compiler_version) != None:
                    message = "0.7.0 version 취약점 쓰기"
                elif re.findall("r'([\d.6.\d]*)/g", compiler_version) != None:
                    message = "0.6.0 version 취약점 쓰기"
                elif re.findall("r'([\d.5.\d]*)/g", compiler_version) != None:
                    message = "0.5.0 version 취약점 쓰기"
                elif re.findall("r'([\d.4.\d]*)/g", compiler_version) != None:
                    message = "0.4.0 version 취약점 쓰기"

                if re.findall("/([><=^]*)/g", compiler_version) != None:
                    description_tail = FLO_DESCRIPTION
                    swc_id = FLOATING_PRAGMA
                else: # < > =
                    description_tail = OUT_DESCRIPTION + message
                    swc_id = OUTDATED_COMPILER_VERSION
                
                issue = Issue(
                    contract="",
                    function_name="",
                    address="",
                    swc_id=swc_id,
                    bytecode="",
                    title="Related Compiler version",
                    severity="Low",
                    description_head=description_head,
                    description_tail=description_tail
                )
                return[issue]
                # return [issue]
        except: 
            '''
            End of file
            #if compiler_version == "":
            '''
            pass

        return []

detector = CheckOldCompiler()
        
            
        



            
