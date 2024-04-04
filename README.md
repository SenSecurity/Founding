# Founding

![GitHub Logo](/Founding/Eren.png)

## Description
Founding is a tool that receives a Shellcode in ```.bin``` format, Obfuscates or Encrypts this shellcode and then generates a new binary utilizing some execution techniques.

### The tool has the following features for Encryption and Obfuscation:

- Supports IPv4/IPv6/MAC/UUID Obfuscation

- Supports XOR/RC4/AES encryption

- Supports payload padding

- Randomly generated encryption keys on every run

### The tool has the following features for Executing the Shellcode:
- Asynchronous Procedure Calls

- Asynchronous Procedure Calls with a Remote Debug Process

- Asynchronous Procedure Calls with a Remote Suspended Process

- Callback function EnumThreadWindows

- Local Mapping and Thread in Suspend State

## Usage
![GitHub Logo](/Founding/Usage.png)

```bash
Founding.exe <Input Payload FileName> <Enc/Obf *Option*> <Shellcode Execution type> <Optional flag>
```
### Utilize Donut to generate the Shellcode

To help generating shellcode I added to the releases [donut](https://github.com/TheWover/donut), using this project we can provide an ```.exe``` binary that we want to run and donut will generate ```.bin``` shellcode.
```bash
donut.exe --input:mimikatz.exe --output:mimi.bin
```

### Example Command
```bash
donut.exe --input:mimikatz.exe --output:mimi.bin


[ Donut shellcode generator v1 (built Mar  3 2023 13:33:22)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP/ETW : continue
  [ PE Headers    : overwrite
  [ Shellcode     : "mimi.bin"
  [ Exit          : Thread
```
```bash
Founding.exe mimi.bin aes APC --compile


Compilation successful.
Shinzo wo Sasageyo! Erwin.exe Created.
```


### Note
- Shellcodes that need an interactive shell like *mimikatz* can't be used with Remote Process techniques.
- To utilize the compile functionality I recommend downloading the releases because it will have all the necessary dependencies.

## Credits
- Some techniques used learnt from [Maldev Academy](https://maldevacademy.com), it is an awesome course, highly recommend
- Inspired by [HellShell](https://github.com/NUL0x4C/HellShell)



