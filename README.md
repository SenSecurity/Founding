# Founding
<img src='/Founding/Eren.png' width='800'>



## Description




**The tool has the following features for Encryption and Obfuscation:**

- Supports IPv4/IPv6/MAC/UUID Obfuscation

- Supports XOR/RC4/AES encryption

- Supports payload padding

- Randomly generated encryption keys on every run

**The tool has the following features for Executing the Payload:**
- Supports createThread to run the shellcode

- Supports function pointer to run the shellcode

- Supports process injection to inject shellcode on a running process


## Usage
```bash
The_Founding.exe <Input Payload FileName> <Enc/Obf *Option*> <Shellcode Execution type>
```
## Example Command
```bash
The_Founding.exe .\calc.bin aes process_injection
```


