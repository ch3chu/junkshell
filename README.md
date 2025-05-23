### Original: https://github.com/amauricio/junkshell


## TODO:
* Refactor code: `re.findall` and `replace` for variables, functions names, etc
* Handle errors when executing shellcode (Exit func Thread?)
* Change RWX to RW -> RX
* Obfuscate more names/IOCs
* Add more layers? (Ej: AES)
* Improve junk shellcode: more random, more opcodes
* handle both x86 and x64 shellcode

### TODO Maybe:
* Load EXE
* Load DLL
* Steager via URLs


# 🗑️ Junkshell: powershell shellcode loader
Sometimes, you need a fast way to encode your shellcode and execute it easily without being blocked by AV/EDR. Junkshell is a tool designed to encode your shellcode and execute it directly in memory by generating a Powershell script. The best part is the powershell script is different on each generation, so it's hard to detect.

## Changelog
### v0.2
![virus total bypass](https://github.com/amauricio/junkshell/blob/master/resources/vt.jpg?raw=true)

- Added Junk Code inside the powershell.
- Fixed bypass in many EDRs/AVs.
- Multiple base64 encoding in the shellcode.
- Multiple obfuscation (Right now is implemented only XOR)


## How it works

Junkshell utilizes an old technique based on `junk codes`. Essentially, it involves reserving a large chunk of memory and filling it with junk code. The shellcode is then placed at the end of this `junk code` and executed. This approach allows for bypassing AV/EDR detection, as the trick lies in using valid instructions instead of traditional `NOPs` to fill the memory. While `NOPs` are typically ignored by AV/EDR, using instructions like `xor eax, 0` or `sub eax, 0`, which do nothing but are still valid instructions, helps achieve successful execution of the shellcode. Check my [blog post](https://synawk.com/blog/junkshell-a-naive-approach-to-bypass-av-edr) for more details.

Finally the AV/EDR stops the analysis because the payload is too long to be analyzed. The ammount of `junk code` is generate randomly always above 10000 bytes.

![junk code shellcode](https://github.com/amauricio/junkshell/blob/master/resources/junk_code_shellcode.gif?raw=true)

## How to use it
```bash
python3 junkshell.py -s shellcode.bin -o revshell.ps1
```
It will generate a powershell script that you can run directly on the target machine.

## Actually works?

This is an example bypassing a meterpreter reverse shell in Sophos.

![junk code shellcode sophos](https://github.com/amauricio/junkshell/blob/master/resources/junk_code_shellcode_sophos.gif?raw=true)

## Output

```bash
[!]          Powershell script generated          [!]

You should run the powershell script below:

>> powershell.exe -exec Bypass -File data.ps1 <<
```

