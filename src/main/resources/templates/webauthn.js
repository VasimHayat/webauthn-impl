function base64UrlToArrayBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(0);
    }
    return bytes.buffer;
}

function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function initWebAuthn(creationOptions, userId) {
    creationOptions.publicKey.challenge = base64UrlToArrayBuffer(creationOptions.publicKey.challenge);
    creationOptions.publicKey.user.id = base64UrlToArrayBuffer(userId);
    creationOptions.publicKey.pubKeyCredParams.forEach(param => {
        param.alg = parseInt(param.alg);
    });

    navigator.credentials.create({ publicKey: creationOptions.publicKey })
        .then(credential => {
            const response = {
                id: credential.id,
                rawId: arrayBufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: arrayBufferToBase64Url(credential.response.attestationObject)
                }
            };
            document.getElementById('registrationResponseJSON').value = JSON.stringify(response);
            document.getElementById('webauthnForm').submit();
        })
        .catch(error => console.error('Error:', error));
}

function startWebAuthnAuthentication(options) {
    options.challenge = base64UrlToArrayBuffer(options.challenge);
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(cred => ({
            ...cred,
            id: base64UrlToArrayBuffer(cred.id)
        }));
    }

    navigator.credentials.get({ publicKey: options })
        .then(credential => {
            document.getElementById('credentialId').value = credential.id;
            document.getElementById('clientDataJSON').value = arrayBufferToBase64Url(credential.response.clientDataJSON);
            document.getElementById('authenticatorData').value = arrayBufferToBase64Url(credential.response.authenticatorData);
            document.getElementById('signature').value = arrayBufferToBase64Url(credential.response.signature);
            document.getElementById('clientExtensionsJSON').value = JSON.stringify(credential.getClientExtensionResults());
            document.getElementById('webauthnForm').submit();
        })
        .catch(error => console.error('Error:', error));
}