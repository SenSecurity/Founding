# Founding
<img src='/Founding/Eren.png' width='800'>

## Description
The Founding is a tool that receives a Shellcode in .bin format, Obfuscates or Encrypts this shellcode and then generates a new binarie utilizing some execution techniques.

**The tool has the following features for Encryption and Obfuscation:**

- Supports IPv4/IPv6/MAC/UUID Obfuscation

- Supports XOR/RC4/AES encryption

- Supports payload padding

- Randomly generated encryption keys on every run

**The tool has the following features for Executing the Payload:**
- Supports executes the Shellcode utilizing Asynchronous Procedure Calls

- Supports executes the Shellcode utilizing Asynchronous Procedure Calls with a Remote Debug Process

- Supports executes the Shellcode utilizing Asynchronous Procedure Calls with a Remote Suspended Process

- Supports executes the Shellcode utilizing Callback function EnumThreadWindows

- Supports executes the Shellcode utilizing Local Mapping and Thread in Suspend State

## Usage
<img src='/Founding/Usage.png'>

```bash
Founding.exe <Input Payload FileName> <Enc/Obf *Option*> <Shellcode Execution type> <Optional flag>
```
##Utilizing Donut to generate the Shellcode
The handler depends on [a link](https://github.com/TheWover/donut) 

## Example Command
```bash
The_Founding.exe .\calc.bin aes APC --compile
```


