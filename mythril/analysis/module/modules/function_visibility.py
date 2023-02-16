from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
import logging
import re
from typing import List, Optional
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.analysis.swc_data import DEFAULT_FUNCTION_VISIBILITY


DESCRIPTION = """
In Solidity, when using a function, a function visibility must be used.
Otherwise, Solidity specifies public as the default visibility.
If the function visibility is specified as public, it can be called externally, 
so if you don't want it, you have to code it using private, external and internal. 
"""

log = logging.getLogger(__name__)

class CheckVisibility(DetectionModule):

    name = "Function Visibility is not declared"
    swc_id = DEFAULT_FUNCTION_VISIBILITY
    description = DESCRIPTION
    entry_point = EntryPoint.COMPILE

    def __init__(self):
        super().__init__()
    
    def reset_module(self):
        return super().reset_module()
    
    def _execute(self, path: str) -> List[Issue]:
        
        all_issues =[]
        description_head = DESCRIPTION
        f = open(path, 'r')
        
        try:
            contract = ""
            address = 0
            function_name = ""
            while(True):
                address += 1
                read_line = f.readline()
                if read_line == "":
                    return all_issues
                
                if "contract" in read_line:
                    contract = read_line.split(" ")[1]

                elif "function" in read_line:

                    # if re.findall("r'(public|private|external|internal)/g", read_line) == None:
                    function_name = read_line.split(" ", 1)[1][:-2]
                    # print(re.findall("r'([private]]*)/g", read_line))
                    if "public" in read_line:
                        pass
                    elif "private" in read_line:
                        pass
                    elif "external" in read_line:
                        pass
                    elif "internal" in read_line:
                        pass
                    else:
                        issue = Issue(
                            contract= contract,
                            function_name = function_name,
                            # address = "line number is " + str(address),
                            address = -1,
                            swc_id = DEFAULT_FUNCTION_VISIBILITY,
                            bytecode="",
                            title="Not Declare function visibility",
                            severity = "MID",
                            description_head=description_head,
                            description_tail="",
                        )
                        all_issues.append(issue)

        except:
            pass

        return all_issues

detector = CheckVisibility()