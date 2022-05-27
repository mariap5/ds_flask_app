var registerButton = document.getElementById('register-button')
var usernameInput = document.getElementById('username-input');
var passwordInput = document.getElementById('password-input');
var option_2fa = document.getElementById("2fa-option");


registerButton.addEventListener('click', async (event) => {
    event.preventDefault();
    console.log("test")
    const username = usernameInput.value;
    const password = passwordInput.value;
    var option_2fa_value;
    if (option_2fa.value === undefined) {
        option_2fa_value = "usb_token"
    } else {
        option_2fa_value = option_2fa.value;
    }
    console.log(option_2fa_value)
    body = JSON.stringify({"username": username, "password": password, "2fa_option": option_2fa_value})
    const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: body
      })
    response.json().then(data => {
          let jwt = data.jwt
          let redirect_url = data.redirect_url
          localStorage.setItem("jwt", jwt)
          window.location = redirect_url
      })
})