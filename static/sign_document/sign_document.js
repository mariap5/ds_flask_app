var logoutButton = document.getElementById("logout-button")

var uploadDocumentBox = document.getElementById("upload-document")
var uploadDocumentInputFile = document.getElementById("upload-document-input")
var uploadDocumentCheckStep = document.getElementById("upload-document-check-step")

var signDocumentBox = document.getElementById("sign-document");
var signDocumentCheckStep = document.getElementById("sign-document-check-step")

var downloadDocumentBox = document.getElementById("download-document")
var downloadDocumentErrorBox = document.getElementById("download-document-error-box")
var downloadDocumentCheckStep = document.getElementById("download-document-check-step")

var document_to_sign;
var document_content;
var document_signature;
var sign_document_request_body = {}
var blob;

var signature_text = document.getElementById("signature-base64");

logoutButton.addEventListener('click', () => {
    localStorage.removeItem("jwt");
    window.location.replace('/login');
})
uploadDocumentBox.addEventListener('click', (event) => {
    uploadDocumentInputFile.click();
})

uploadDocumentInputFile.addEventListener('change', (event) => {
    document_to_sign = event.target.files[0];
    var fileReader = new FileReader();
    fileReader.onload=function() {
        sign_document_request_body["document"] = fileReader.result;
        document_content = fileReader.result
        uploadDocumentCheckStep.style.display = 'flex';
        signDocumentBox.style.display = 'flex';
    }

    fileReader.readAsText(document_to_sign)
})


signDocumentBox.addEventListener('click', (event) => {
    private_key = localStorage.getItem('private_key');
    if (private_key === null) {
        alert('No private key found, "please insert your usb key"')
        window.location.replace('/login')
    }
    var sign = new JSEncrypt();
    sign.setPrivateKey(JSON.parse(private_key))
    document_signature = sign.sign( document_content, CryptoJS.SHA256, "sha256");
    console.log("document signature: ", document_signature)

    blob = new Blob([JSON.stringify({
        "content": document_content,
        "signature": document_signature
        })],
                { type: "text/plain;charset=utf-8" });
    signDocumentCheckStep.style.display = 'flex';
    downloadDocumentBox.style.display = 'flex';

    signature_text.innerHTML = "Signature in base64: " + document_signature;
})


downloadDocumentBox.addEventListener('click', async (event) => {
    saveAs(blob, "signed_document.ds")
})


