# Founding

![GitHub Logo](/Founding/Eren.png)

## Description
The Founding is a tool that receives a Shellcode in .bin format, Obfuscates or Encrypts this shellcode and then generates a new binarie utilizing some execution techniques.

### The tool has the following features for Encryption and Obfuscation:

- Supports IPv4/IPv6/MAC/UUID Obfuscation

- Supports XOR/RC4/AES encryption

- Supports payload padding

- Randomly generated encryption keys on every run

### The tool has the following features for Executing the Payload:
- Supports executes the Shellcode utilizing Asynchronous Procedure Calls

- Supports executes the Shellcode utilizing Asynchronous Procedure Calls with a Remote Debug Process

- Supports executes the Shellcode utilizing Asynchronous Procedure Calls with a Remote Suspended Process

- Supports executes the Shellcode utilizing Callback function EnumThreadWindows

- Supports executes the Shellcode utilizing Local Mapping and Thread in Suspend State

## Usage
![GitHub Logo](/Founding/Usage.png)

```bash
Founding.exe <Input Payload FileName> <Enc/Obf *Option*> <Shellcode Execution type> <Optional flag>
```
### Utilize Donut to generate the Shellcode

To help generating shellcode I added to the releases [donut](https://github.com/TheWover/donut), using this project we can provide an .exe binarie that we want to run and donut will generate .bin shellcode.
```bash
donut.exe --input:mimikatz.exe --output:mimi.bin
```

### Example Command
```bash
donut.exe --input:mimikatz.exe --output:mimi.bin
...
The_Founding.exe mimi.bin aes APC --compile
...
Compilation successful.
Shinzo wo Sasageyo'!' Erwin.exe Created.
```
## Credits
- Some techniques used learnt from [Maldev Academy](https://maldevacademy.com), it is an awesome course, highly recommended
- Inspired by [HellShell](https://github.com/NUL0x4C/HellShell)



