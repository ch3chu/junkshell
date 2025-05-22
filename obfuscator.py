import re
import random
import string

from base64 import b64encode

from utils import randomBytes, randomStr

OPCODES = [
    [0x48, 0x31, 0xc0, 0x90],
    [0x31, 0xc0, 0x90, 0x90],
    [0x66, 0x31, 0xc0, 0x90],
    [0x30, 0xc0, 0x90, 0x90],
    [0x30, 0xe4, 0x90, 0x90],
    [0x48, 0x31, 0xc9, 0x90],
    [0x31, 0xc9, 0x90, 0x90],
    [0x66, 0x31, 0xc9, 0x90],
    [0x30, 0xc9, 0x90, 0x90],
    [0x30, 0xed, 0x90, 0x90],
    [0x48, 0x31, 0xdb, 0x90],
    [0x31, 0xdb, 0x90, 0x90],
    [0x66, 0x31, 0xdb, 0x90],
    [0x30, 0xdb, 0x90, 0x90],
    [0x30, 0xff, 0x90, 0x90],
    [0x48, 0x31, 0xd2, 0x90],
    [0x31, 0xd2, 0x90, 0x90],
    [0x66, 0x31, 0xd2, 0x90],
    [0x30, 0xd2, 0x90, 0x90],
    [0x30, 0xf6, 0x90, 0x90],
    [0x48, 0x31, 0xf6, 0x90],
    [0x31, 0xf6, 0x90, 0x90],
    [0x66, 0x31, 0xf6, 0x90]
]

LIST_JUNKS = [
f"""
function func01 {{
    param([string]$var03)

    $var01 = "random_string"
    $var02 = "random_string"

    while ($true){{
        if ($var01 -eq $var02){{break;}}
        if ($var01 -gt $var02){{$var01 = $var01 - 1;}}
        if ($var01 -lt $var02){{$var02 = $var02 - 1;}}
    }}
    return "random_string"
}}
{"\n".join([f'func01 -var03 "random_string"' for _ in range(random.randint(5,15))])}
""",
f"""
$var04 = number
{
"\n".join(
    [f"$var04 += number {random.choices(['-', '+', '/', '*'])[0]} number" for _ in range(random.randint(5,15))]
)
}
""",
f"""
try{{
    "random_string" -split "." |%{{ random_string $_}}
}} catch {{
    $random_string = $_.Exception
    sleep number-(number-1)
}}
"""
]

def replaceString(string, idx, first_char_idx, step):
    s = list(string)
   
    """
    first_char_idx = 4 (B)
    step = 3 (C)

    [A, A, A, A, A, A, A, A, A]
    [B, B, B, A, A, A, A, A, A, A, A, A]
    [B, B, B, A, C, C, A, C, C, A, C, C A, C, C A]

    """

    if idx == 0:
        s[idx:idx+1] = randomStr(first_char_idx, first_char_idx)[:first_char_idx-1] + s[idx]
        #s[idx:idx+1] = ("_"*30)[:first_char_idx-1] + s[idx] # For testing
        idx+=first_char_idx
    else:
        s[idx:step+idx] = randomStr(step, step)[:step-1] + "".join(s[idx:step+idx])
        #s[idx:step+idx] = ("|"*30)[:step-1] + "".join(s[idx:step+idx]) # For testing
        idx+=step

    if idx >= len(s):
        return "".join(s)

    return replaceString("".join(s), idx, first_char_idx, step)

class Obfuscator():
    def __init__(self):
        self.key = randomBytes(random.randint(128, 256))
        self.len_key = len(self.key)
        self.first_char_idx = random.randint(6, 15)
        self.step = random.randint(4, 6)

    def encodeXOR(self, data) -> bytes:
        enc = bytearray()

        for i in range(len(data)):
            enc.append(data[i] ^ self.key[i % self.len_key])

        return bytes(enc)


    def stringsEncoder(self, string) -> str:
        """
        a = list("abcdlksfdljf")
        a[1:2] = "hola" + a[1]
        """

        return '"' + replaceString(string, 0, self.first_char_idx, self.step) + '"'

    @staticmethod
    def replaceVars(code) -> str:
        variables = re.findall(r"(\$[a-zA-Z0-9_]{,29})[\ ]{0,}(?:[+\-\*]|)(?:=|,|\s)", code)
        variables = list(set(variables))
        variables = sorted(variables, key=len, reverse=True)

        if "$ErrorActionPreference" in variables:
            variables.remove("$ErrorActionPreference")
        elif "$_" in variables:
            variables.remove("$_")
        
        for var in variables:
            code = code.replace(var, "$"+randomStr(5, 30))

        return code

    @staticmethod
    def replaceFunctions(code) -> str:
        new_item = (
            "N`i", "n`I", "N`I", "NI", "n`i"
        )

        functions = re.findall(r"(function[\ ]{1,}[a-zA-Z0-9_]{,29})\s{0,}\{", code, flags=re.IGNORECASE)
        
        for func in functions:
            parts = [x.strip() for x in func.split()]
            char = random.choices(list(string.ascii_letters))[0]

            code = code.replace(func, f"{random.choices(new_item)[0]} -p (([String](Get-Command {char}:).CommandType)+':') -n {parts[1]} -value ")
            code = code.replace(parts[1], randomStr(5, 30))

        return code

    @staticmethod
    def junkOPCodes() -> list:
        ops = []

        for op in OPCODES:
            ops.append("@(0x{:02x},0x{:02x},0x{:02x},0x{:02x})".format(op[0], op[1], op[2], op[3]))

        return ops

    @staticmethod
    def getJunkCode() -> str:
        code = random.choices(LIST_JUNKS)[0]

        patterns = [
            r"random_string",
            r"number",
            r"func\d{1,3}",
            r"var\d{1,3}"
        ]

        for p in patterns:
            res = re.findall(p, code)

            if p == r"random_string":
                for i in range(len(res)):
                    code = code.replace(p, randomStr(30, 250), 1)
            elif p == r"number":
                for i in range(len(res)):
                    code = code.replace(p, str(random.randint(1,10000)), 1)
            else:
                res = set(res)

                for r in res:
                    code = code.replace(r, randomStr(30,50))

        return code