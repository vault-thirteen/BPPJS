# BPPJS

`BPPJS` is a client-side variant of the `Byte Packed Password` library ported to
_JavaScript_ for web browsers.

The original `Byte Packed Password` library is written in _Go_ programming
language and is intended to be used on a server side. Its repository is
https://github.com/vault-thirteen/BytePackedPassword

This ported variant of the library is intended to be used on a client side.
Thus, it contains only those functions which are used by client.

Note that this library is not written in pure _JavaScript_. The main part of it
is using the _Argon 2_ library which was written in _C_ programming language
and was compiled for the _Web Assembly_ (_WASM_). A cross-platform variant of
the _Argon 2_ library is accessible in the following repository –
https://github.com/vault-thirteen/argon2 – while the original source code comes
from a separate repository – https://github.com/P-H-C/phc-winner-argon2 .

## Web Assembly

_Web Assembly_ (_WASM_) is still an experimental technology, and it is very
cumbersome and inconvenient. In its current state, each executable file of
_WASM_ requires an environment emulator written in _JavaScript_ programming
language. Taking into consideration that even modern versions of _JavaScript_
language do not support the _Uint8_ type, the emulator for _WASM_ typically
looks like a monster of Frankenstein. The emulator for the _WASM_ executable
and the executable itself were compiled with the help of _Emscripten SDK_.

Support for _WASM_ in various web browsers can be viewed here:  
https://caniuse.com/wasm

Please, note that such web browsers as _Internet Explorer 11_ and _Opera Mini_
do not support _WASM_.

_Web Assembly_ specifications are available on the following page:  
https://webassembly.github.io/spec/

## Functions

List of ported functions is following.

| # | Ported | Go function        | JS function       |
|---|:------:|--------------------|-------------------|
| 1 |   ✅    | PackSymbols        | packSymbols       |
| 2 |   ❌    | UnpackBytes        | -                 |
| 3 |   ✅    | IsPasswordAllowed  | isPasswordAllowed |
| 4 |   ✅    | MakeHashKey        | makeHashKey       |
| 5 |   ❌    | CheckHashKey       | -                 |
| 6 |   ❌    | GenerateRandomSalt | -                 |

## Build information

_WASM_ executable file and an environment emulator were built with the help of
following tools.

* **Custom Emscripten Docker container**
    * https://github.com/vault-thirteen/argon2?tab=readme-ov-file#building-for-wasm-in-emscripten-docker-container


* **Emscripten SDK**
    * https://emscripten.org

## Tests

Manual hash tests were performed using following tools.

* **Mozilla Firefox** web browser, version 130.0.
    * https://www.mozilla.org


* **VSFS** _HTTP_ server, version 0.11.8.
    * https://github.com/vault-thirteen/VSFS

## Usage

A complete usage example with a sample _HTML_ page with scripts is available
in following files:

* test.html
* test.js

## Feedback

If you find any bugs or have any suggestions, your feedback is always welcome
in the `Issues` section of this repository. 
