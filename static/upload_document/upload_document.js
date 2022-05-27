const uploadDocumentBox = document.getElementById("upload-document")
const uploadDocumentCheck = document.getElementById("upload-document-check-step")
const uploadDocumentError = document.getElementById("upload-document-error-box")

const uploadSignedDocumentInput = document.getElementById("upload-signed-document-input")

const sendDocumentBox = document.getElementById("send-document")
const sendDocumentCheck = document.getElementById("send-document-check-step")
const sendDocumentError = document.getElementById("send-document-error-box")

const verifyDocumentBox = document.getElementById("verify-success-document")
const verifyDocumentCheck = document.getElementById("verify-success-document-check-step")
const verifyDocumentError = document.getElementById("verify-success-document-error-box")

const errorMessage = document.getElementById("error-message")

var document_signature;
var document_content;



uploadDocumentBox.addEventListener("click", (event) => {
    uploadSignedDocumentInput.click()
})

uploadSignedDocumentInput.addEventListener("change", (event) => {
    try {

        console.log(event.target.files[0])
        const signed_document = event.target.files[0]
        var fileReader = new FileReader();
        fileReader.onload=function() {
            const signed_document_content = JSON.parse(fileReader.result)
            console.log(signed_document_content)
            document_signature = signed_document_content["signature"]
            document_content = signed_document_content["content"]
            uploadDocumentCheck.style.display = "flex";
            sendDocumentBox.style.display = "flex";
        }
        fileReader.readAsText(signed_document)
    }
    catch(e) {
        uploadDocumentError.style.display = 'flex';
        errorMessage.innerHTML = "Failed to parse uploaded document"
    }
})


sendDocumentBox.addEventListener('click', async (event) => {
    var decoded_jwt = JSON.parse(atob(localStorage.getItem("jwt").split(".")[1]))
    console.log(decoded_jwt)

    const response = await fetch('/document/verify-signature', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            "document_signature": document_signature,
            "document_content": document_content,
            "user_id": decoded_jwt.user_id
        })
    })
    sendDocumentCheck.style.display = "flex"

    response.json()
        .then((data) => {
            if(data["valid"]) {
                verifyDocumentBox.style.display = "flex";
                verifyDocumentCheck.style.display = "flex"
            }
        })
        .catch((e) => {
            verifyDocumentError.style.display = "flex";
        })

})
