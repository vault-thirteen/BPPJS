// While JavaScript does not support workspaces as in C++, we add prefixes to
// constant names as in old C. And this is year 2024 ... JavaScript must die.

// Byte packing & password settings.
const BPP_FirstSymbol = ' '; // White Space.
const BPP_LastSymbol = '_'; // Low Line.
const BPP_MinAllowedSymbol = BPP_FirstSymbol;
const BPP_MaxAllowedSymbol = BPP_LastSymbol;
const BPP_MinPasswordLength = 16;
const BPP_SaltLengthRequired = 1024;

// Settings for Argon2.
const BPP_Argon2Iterations = 8;
const BPP_Argon2Memory = 8 * 1024; // 8 MiB.
const BPP_Argon2Threads = 1;
const BPP_Argon2KeyLength = 1024;

// Errors and messages.
const BPP_errArgNotString = "Argument is not a string";
const BPP_errArgNotByteArray = "Argument is not a byte array";
const BPP_errCountNotMultipleOfFour = "Symbols count is not multiple of four";
const BPP_errPasswordNotValid = "Password is not valid";
const BPP_errSaltSizeWrong = "Salt size is wrong";

let isString = value => typeof value === 'string';

let isByteArray = value => value instanceof Uint8Array;

function mustBeString(s) {
    if (!isString(s)) {
        throw new Error(BPP_errArgNotString);
    }
}

function mustBeByteArray(ba) {
    if (!isByteArray(ba)) {
        throw new Error(BPP_errArgNotByteArray);
    }
}

function base64ToByteArray(s) {
    mustBeString(s);
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function byteArrayToBase64(ba) {
    mustBeByteArray(ba);

    let bs = '';
    let len = ba.byteLength;
    for (let i = 0; i < len; i++) {
        bs += String.fromCharCode(ba[i]);
    }

    return btoa(bs);
}

function isPasswordAllowed(pwd) {
    let len = pwd.length;

    if (len % 4 !== 0) {
        return false;
    }

    if (len < BPP_MinPasswordLength) {
        return false;
    }

    [...pwd].forEach(c => {
        if ((c < BPP_MinAllowedSymbol) || (c > BPP_MaxAllowedSymbol)) {
            return false;
        }
    });

    return true;
}

function packSymbols(symbols) {
    let len = symbols.length;
    if ((len % 4) !== 0) {
        throw new Error(BPP_errCountNotMultipleOfFour);
    }

    let unpackedBytes = [];
    let n = 0;
    let fscc = BPP_FirstSymbol.charCodeAt(0);
    [...symbols].forEach(c => {
        unpackedBytes.push(c.charCodeAt(0) - fscc);
    });

    let quadIdxMax = unpackedBytes.length / 4;
    let quad = [];
    let buf = [];
    let packedBytes = [];
    for (let quadIdx = 0; quadIdx < quadIdxMax; quadIdx++) {
        let start = quadIdx * 4;
        quad = unpackedBytes.slice(start, start + 4);
        buf = [0, 0, 0];

        // 1.
        buf[0] = quad[0] << 2;
        buf[0] = buf[0] & 255; // See [*].

        // 2.
        buf[0] = buf[0] | (quad[1] >> 4)
        buf[0] = buf[0] & 255; // See [*].
        buf[1] = quad[1] << 4
        buf[1] = buf[1] & 255; // See [*].

        // 3.
        buf[1] = buf[1] | (quad[2] >> 2)
        buf[1] = buf[1] & 255; // See [*].
        buf[2] = quad[2] << 6
        buf[2] = buf[2] & 255; // See [*].

        // 4.
        buf[2] = buf[2] | quad[3]
        buf[2] = buf[2] & 255; // See [*].

        // Save the piece into accumulator.
        packedBytes.push(buf[0]);
        packedBytes.push(buf[1]);
        packedBytes.push(buf[2]);

        // Comments.
        // [*]: JavaScript does not have an Uint8 type !
    }

    return Uint8Array.from(packedBytes);
}

/*
ARGON2_PUBLIC int argon2id_hash_raw
(
    const uint32_t t_cost,      // Number of iterations.
    const uint32_t m_cost,      // Memory usage in KiB.
    const uint32_t parallelism, // Number of threads.
    const void *pwd,            // Password.
    const size_t pwdlen,        // Length of password.
    const void *salt,           // Salt.
    const size_t saltlen,       // Length of salt.
    void *hash,                 // Key (hash sum). [Output]
    const size_t hashlen        // Key size (hash sum length).
);
Source: https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h#L314
*/
function argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashSize) {
    let fn = Module.cwrap('argon2id_hash_raw', null, ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number']);

    const pwdSize = pwd.length;
    const saltSize = salt.length;

    // Allocate array elements.
    let bufHash = Module._malloc(hashSize);
    let bufPwd = Module._malloc(pwdSize);
    let bufSalt = Module._malloc(saltSize);

    // Set the initial values.
    for (let i = 0; i < pwdSize; i++) {
        // https://emscripten.org/docs/api_reference/preamble.js.html#setValue
        Module.setValue(bufPwd + i, pwd[i], 'i8');
    }

    for (let i = 0; i < saltSize; i++) {
        // https://emscripten.org/docs/api_reference/preamble.js.html#setValue
        Module.setValue(bufSalt + i, salt[i], 'i8');
    }

    // Run the function.
    fn(t_cost, m_cost, parallelism, bufPwd, pwdSize, bufSalt, saltSize, bufHash, hashSize);

    // Get the output.
    let result = [];
    let x;
    for (let i = 0; i < hashSize; i++) {
        // https://emscripten.org/docs/porting/connecting_cpp_and_javascript/Interacting-with-code.html
        x = Module.getValue(bufHash + i, 'i8');
        result.push(x);
    }

    // Free the memory.
    Module._free(bufHash);
    Module._free(bufPwd);
    Module._free(bufSalt);

    return Uint8Array.from(result);
}

function makeHashKey(pwdStr, saltBA) {
    mustBeString(pwdStr);
    mustBeByteArray(saltBA);

    if (!isPasswordAllowed(pwdStr)) {
        throw new Error(BPP_errPasswordNotValid);
    }

    if (saltBA.length !== BPP_SaltLengthRequired) {
        throw new Error(BPP_errSaltSizeWrong + ": " + saltBA.length);
    }

    let pwdPacked = packSymbols(pwdStr);

    return argon2id_hash_raw(BPP_Argon2Iterations, BPP_Argon2Memory, BPP_Argon2Threads, pwdPacked, saltBA, BPP_Argon2KeyLength);
}
