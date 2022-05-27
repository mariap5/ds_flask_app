const loginButton = document.getElementById("login-button");
const usernameInput = document.getElementById("username-input");
const passwordInput  = document.getElementById("password-input");
const loginError = document.getElementById("login-error");

loginButton.addEventListener('click', async (event) => {
    event.preventDefault();
    var response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: usernameInput.value,
          password: passwordInput.value
        })
    });
    console.log(passwordInput.value)
    response = await response.json()
    if (response.status_code === 400) {
           loginError.innerHTML = response.message
           loginError.style.display = "block"
    }

    challenge = response.challenge
    userId = response.user_id
    private_key = localStorage.getItem('private_key');
    if (private_key === null) {
        loginError.innerHTML = "Please insert your usb key"
        loginError.style.display = "block"
        return
    }
    console.log(JSON.parse(private_key))
    var sign = new JSEncrypt();
    sign.setPrivateKey(JSON.parse(private_key))
    encrypted_challenge = sign.sign( challenge, CryptoJS.SHA256, "sha256");
    console.log(encrypted_challenge)
    const challenge_response = await fetch('/login/challenge', {
        method: "POST",
        headers: {
               'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            encrypted_challenge: encrypted_challenge,
            user_id: userId
        })


    })
    challenge_response.json().then(data => {
        console.log(data.status_code)
        if (data.status_code !== undefined) {
            loginError.innerHTML = data.message
            loginError.style.display = "block"
        } else if (data.jwt !== undefined) {
            localStorage.setItem("jwt", data.jwt)
            window.location.replace(data.redirect_url)
        } else {
            loginError.innerHTML = "Something went wrong."
            loginError.style.display = "block"
        }
    })
});

function str2ab(str) {
    var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}