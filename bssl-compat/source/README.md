# Adding boringSSL in BSSL-COMPAT
- Currently, BSSL-COMPAT Calls OpenSSL Function through BoringSSL Headers
- For Adding BoringSSL in BSSL-COMPAT, We needs control variable which is parameter for choosing Encryption Engine
## Control variable
- Determines for using Crypto Lib
```c
global int use_ossl; 
```
- 1 for ossl
- 0 for bssl
