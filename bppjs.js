// Byte packing & password settings.
const FirstSymbol = ' '; // White Space.
const LastSymbol = '_'; // Low Line.
const MinAllowedSymbol = FirstSymbol;
const MaxAllowedSymbol = LastSymbol;
const MinPasswordLength = 16;
const SaltLengthRequired = 1024;

// Settings for Argon 2.
const Argon2Iterations = 8;
const Argon2Memory = 8 * 1024; // 8 MiB.
const Argon2Threads = 1;
const Argon2KeyLength = 1024;

let isString = value => typeof value === 'string';

let isByteArray = value => value instanceof Uint8Array;

function mustBeString(s)
{
    if (!isString(s))
    {
        throw new Error('Argument is not a string');
    }
}

function mustBeByteArray(ba)
{
    if (!isByteArray(ba))
    {
        throw new Error('Argument is not a byte array');
    }
}

function base64ToByteArray(s)
{
    mustBeString(s);
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function byteArrayToBase64(ba)
{
    mustBeByteArray(ba);

    let bs = '';
    let len = ba.byteLength;
    for (let i = 0; i < len; i++)
    {
        bs += String.fromCharCode(ba[i]);
    }

    return btoa(bs);
}

function isPasswordAllowed(pwd)
{
    let len = pwd.length;

    if (len % 4 !== 0)
    {
        return false;
    }

    if (len < MinPasswordLength)
    {
        return false;
    }

    [...pwd].forEach(c =>
    {
        if ((c < MinAllowedSymbol) || (c > MaxAllowedSymbol))
        {
            return false;
        }
    });

    return true;
}

function packSymbols(symbols)
{
    let len = symbols.length;
    if ((len % 4) !== 0)
    {
        throw new Error('Symbols count is not a multiple of four');
    }

    let unpackedBytes = [];
    let n = 0;
    let fscc = FirstSymbol.charCodeAt(0);
    [...symbols].forEach(c =>
    {
        unpackedBytes.push(c.charCodeAt(0) - fscc);
    });

    let quadIdxMax = unpackedBytes.length / 4;
    let quad = [];
    let buf = [];
    let packedBytes = [];
    for (let quadIdx = 0; quadIdx < quadIdxMax; quadIdx++)
    {
        let start = quadIdx * 4;
        quad = unpackedBytes.slice(start, start + 4);
        buf = [0, 0, 0];

        // 1.
        buf[0] = quad[0] << 2;
        buf[0] = buf[0] & 255; // JavaScript does not have an Uint8 type !

        // 2.
        buf[0] = buf[0] | (quad[1] >> 4)
        buf[0] = buf[0] & 255; // JavaScript does not have an Uint8 type !
        buf[1] = quad[1] << 4
        buf[1] = buf[1] & 255; // JavaScript does not have an Uint8 type !

        // 3.
        buf[1] = buf[1] | (quad[2] >> 2)
        buf[1] = buf[1] & 255; // JavaScript does not have an Uint8 type !
        buf[2] = quad[2] << 6
        buf[2] = buf[2] & 255; // JavaScript does not have an Uint8 type !

        // 4.
        buf[2] = buf[2] | quad[3]
        buf[2] = buf[2] & 255; // JavaScript does not have an Uint8 type !

        // Save the piece into accumulator.
        packedBytes.push(buf[0]);
        packedBytes.push(buf[1]);
        packedBytes.push(buf[2]);
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
function argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hashSize)
{
    let fn = Module.cwrap('argon2id_hash_raw', null, ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number', 'number']);

    const pwdSize = pwd.length;
    const saltSize = salt.length;

    // Allocate array elements.
    let bufHash = Module._malloc(hashSize);
    let bufPwd = Module._malloc(pwdSize);
    let bufSalt = Module._malloc(saltSize);

    // Set the initial values.
    for (let i = 0; i < pwdSize; i++)
    {
        // https://emscripten.org/docs/api_reference/preamble.js.html#setValue
        Module.setValue(bufPwd + i, pwd[i], 'i8');
    }

    for (let i = 0; i < saltSize; i++)
    {
        // https://emscripten.org/docs/api_reference/preamble.js.html#setValue
        Module.setValue(bufSalt + i, salt[i], 'i8');
    }

    // Run the function.
    fn(t_cost, m_cost, parallelism, bufPwd, pwdSize, bufSalt, saltSize, bufHash, hashSize);

    // Get the output.
    let result = [];
    let x;
    for (let i = 0; i < hashSize; i++)
    {
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

function makeHashKey(pwdStr, saltBA)
{
    mustBeString(pwdStr);
    mustBeByteArray(saltBA);

    if (!isPasswordAllowed(pwdStr))
    {
        throw new Error('Password is not valid');
    }

    if (saltBA.length !== SaltLengthRequired)
    {
        throw new Error('Salt size is wrong');
    }

    let pwdPacked = packSymbols(pwdStr);

    return argon2id_hash_raw(Argon2Iterations, Argon2Memory, Argon2Threads, pwdPacked, saltBA, Argon2KeyLength);
}
