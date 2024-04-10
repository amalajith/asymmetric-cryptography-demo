const express = require('express');
const path = require('path');
const crypto = require('node:crypto');
const fs = require('fs/promises');

const app = express();
app.use(express.json());

/**
 * Remove the headers from the public key as window.subtle.crypto doesn't require it.
 * @param publicKey
 * @returns {*}
 */
function removeHeaders(publicKey) {
    // Replace the header and footer lines with empty strings.
    publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

    // Return the public key without the headers.
    return publicKey;
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/public-key', async (req, res) => {

    let keyData;

    //Check if private/public key is already generated and stored
    try {
         let keyDataString = await fs.readFile(path.join(__dirname,'keydata.json'), { encoding: 'utf8' });
         keyData = JSON.parse(keyDataString);
    } catch (e) {
        console.log(e);
    }

    //If no existing key data, then generate a new private/public key pair
    if(!keyData?.privateKey || !keyData?.publicKey){
        console.log('No existing public/private key, generating new one');

        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem',
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        const newKeyData = {
            privateKey: privateKey,
            publicKey: publicKey
        }

        console.log(newKeyData);

        try {
            await fs.writeFile(path.join(__dirname,'keydata.json'), JSON.stringify(newKeyData))
            keyData = newKeyData;
        } catch (e){
            console.log(e);
        }

    }

    return res.send({
        publicKey: removeHeaders(keyData.publicKey).trim(),
    })

})

app.post('/decrypt-using-private', async (req, res) => {
   const password = req.body.password;

   let keyData;
    try {
        let keyDataString = await fs.readFile(path.join(__dirname,'keydata.json'), { encoding: 'utf8' });
        keyData = JSON.parse(keyDataString);

        const buffer = Buffer.from(password, "base64");
        const decrypted = await  crypto.privateDecrypt({ key: keyData.privateKey, oaepHash: 'sha-256' }, buffer);
        const decryptedString =  decrypted.toString("utf8");

        res.send({
            "decrypted_password": decryptedString
        })

    } catch (e) {
        console.log(e);
        res.end();
    }

})

app.listen(3000,() => {
    console.log('running on port 3000');
})
