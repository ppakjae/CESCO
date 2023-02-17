import logging
from typing import  Optional

logging.basicConfig(filename="logfile.log", filemode="w", level=logging.WARNING)

def show_class_structure(target, option: Optional[str] = ""):

    print("==========run helper==========")

    object_type = type(target)
    print("type:", object_type)
    print()

    if target == None:
        print("NoneType")
    # if object_type == int or object_type == str:

    elif isinstance(target, int) or isinstance(target, str):
        print(target)
    
    elif(object_type == list):
        print(*target)
    
    elif(object_type == dict):
        fields = [field for field in target.keys()]

        if option == "" or option == "all":
            for key, value in target.items():
                
                print(f"field name: {key}")
                print(f"value type: {type(value)}")
                
                if value == None:
                    print("None")
                elif value == "":
                    print("empty string")
                else:
                    print(value)
                print()
        
        elif option == "help":
            print("you can print these fields")
            print(fields)

        elif option in fields:
            print(option)
            print(getattr(target, option))

        else:
            print(option, "is not in fields")
            print("try these")
            print(fields)
    # if not isinstance(object_type, EVMContract):
    #     print(target)

    else:
        fields = [field for field in target.__dict__.keys()]

        if option == "" or option == "all":
            for key, value in target.__dict__.items():
                
                print(f"field name: {key}")
                print(f"value type: {type(value)}")
                
                if value == None:
                    print("None")
                elif value == "":
                    print("empty string")
                else:
                    print(value)
                print()
        
        elif option == "help":
            print("you can print these fields")
            print(fields)

        elif option in fields:
            print(option)
            print(getattr(target, option))

        else:
            print(option, "is not in fields")
            print("try these")
            print(fields)

    print("==========end helper==========")
    print()
    
def show_class_structure_log(target, option: str):
    
    fields = [field for field in target.__dict__.keys()]

    logging.warning("==========run helper==========")
    logging.warning(f"type: {type(target)}")

    if option == "" or option == "all":
        for key,value in target.__dict__.items():
            logging.warning(f"field name: {key}")
            logging.warning(f"value type: {type(value)}")
            if value == None:
                logging.warning("None")
            elif value == "":
                logging.warning("empty string")
            else:
                logging.warning(value)
    
    elif option == "help":
        logging.warning("you can print these fields")
        logging.warning(fields)

    elif option in fields:
        logging.warning(option)
        logging.warning(getattr(target, option))

    else:
        logging.warning(option, "is not in fields")
        logging.warning("try these")
        logging.warning(fields)

    logging.warning("==========end helper==========")
    