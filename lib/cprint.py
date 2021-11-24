"""
Written by Craig B.
https://github.com/Phatkone
           ,,,
          (. .)
-------ooO-(_)-Ooo-------
"""

def cprint(string: str, type: str = "endc", bold: bool = False, underline: bool = False) -> None:
    colours = {
        'PURPLE': '\033[95m',
        'BLUE': '\033[94m',
        'CYAN': '\033[96m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m',
    }
    if type.upper() in ['PURPLE','BLUE','CYAN','GREEN','YELLOW','RED','BOLD','UNDERLINE']:
        s = colours[type.upper()]
        if bold:
            s = s + colours['BOLD']
        if underline:
            s = s + colours['UNDERLINE']
        print("{}{}{}".format(colours[type.upper()],string,colours['ENDC']))
    else:
        print(string)