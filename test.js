function onLoad()
{
}

function calculate()
{
    clearKey();

    let saltBA = base64ToByteArray(getSalt());

    let pwdStr = getPwd();
    if (!isPasswordAllowed(pwdStr))
    {
        alert('Password is not valid');
        return;
    }

    let keyBA = makeHashKey(pwdStr, saltBA)
    setKey(byteArrayToBase64(keyBA));
}

function getSalt()
{
    return document.getElementById("salt").value;
}

function getPwd()
{
    return document.getElementById("pwd").value;
}

function setKey(key)
{
    mustBeString(key);
    document.getElementById("key").value = key;
}

function clearKey()
{
    setKey("");
}
