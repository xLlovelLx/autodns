class ConsoleColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    OKRED = '\033[91m'
    OKMAGENTA = '\033[95m'
    OKYELLOW = '\033[93m'
    OKWHITE = '\033[97m'
    OKBLACK = '\033[90m'
    OKBLACKBG = '\033[40m'
    OKWHITEBG = '\033[47m'
    OKGREENBG = '\033[42m'
    OKREDBG = '\033[41m'
    OKCYANBG = '\033[46m'
    OKMAGENTABG = '\033[45m'
    OKYELLOWBG = '\033[43m'
    OKBLUEBG = '\033[44m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    
    


def color_print(message, color):
    """
    Print message in specified color.
    """
    print(f"{color}{message}{ConsoleColors.ENDC}")