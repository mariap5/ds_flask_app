console.log("test register usb token")
var uploadCertificateButton = document.getElementById("upload-certificate");
var uploadPrivateKeyButton = document.getElementById("upload-private-key");
var registerUSBbutton = document.getElementById("register_usb_token");
var publicKeyInput = document.getElementById("public-key-input");
var privateKeyInput = document.getElementById("private-key-input")
var publicKeyFileName = document.getElementById("public_key_file_name");
var privateKeyFileName = document.getElementById("private_key_file_name")
var userIdInput = document.getElementById("user-id-input")

var certificate_file;
var private_key_file;

var register_usb_token_request_body = {}

uploadCertificateButton.addEventListener("click", uploadCertificate);
uploadPrivateKeyButton.addEventListener("click", uploadPrivateKey)
registerUSBbutton.addEventListener("click", registerUSB)
publicKeyInput.addEventListener('change', (event) => {
    certificate_file = event.target.files[0];
    publicKeyFileName.innerHTML="Uploaded certificate: " + certificate_file.name;
    var fileReader = new FileReader();
    fileReader.onload=function() {
        register_usb_token_request_body["certificate"] = fileReader.result;
        console.log(fileReader.result)
    }
    fileReader.readAsText(certificate_file)
})
privateKeyInput.addEventListener('change', (event) => {
    private_key_file = event.target.files[0];
    privateKeyFileName.innerHTML = "Uploaded private key: " + private_key_file.name + " (will remain in local storage)";
    var fileReader = new FileReader();
    fileReader.onload=function() {
        localStorage.setItem("private_key", JSON.stringify(fileReader.result))
    }
    fileReader.readAsText(private_key_file);

})

function uploadCertificate() {
    publicKeyInput.click();
}

function uploadPrivateKey() {
    privateKeyInput.click();
}

async function registerUSB() {
  encoded_jwt = localStorage.getItem("jwt")
  var decoded_jwt = JSON.parse(atob(encoded_jwt.split(".")[1]))
  register_usb_token_request_body["jwt"] = encoded_jwt;
    if(register_usb_token_request_body && private_key_file) {
      var body = JSON.stringify(register_usb_token_request_body);
      console.log(body)
      const response = await fetch('/register/register-usb-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: body
      })
      response.json().then(data => {
          jwt = data.jwt
          redirect_url = data.redirect_url
          localStorage.setItem("jwt", jwt)
          window.location = redirect_url
      })
    }
}

async function getUser(user_id) {
      const response = await fetch('/user/' + user_id, {
      method: 'GET',
      headers: {
          'Content-Type': 'application/json',
          'JsonWebToken': encoded_jwt
      },
  })
  const user = response.json().then((data) => {
      return data
  })

  return user;
}
