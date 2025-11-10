'use strict';

const crypto = require('crypto');

class GovEsbHelper {
    constructor(options = {}) {
        this.clientPrivateKey = options.clientPrivateKey || null; // base64 (PKCS8 DER, no headers)
        this.esbPublicKey = options.esbPublicKey || null; // base64 (X.509 DER, no headers)
        this.clientId = options.clientId || null;
        this.clientSecret = options.clientSecret || null;
        this.esbTokenUrl = options.esbTokenUrl || null;
        this.esbEngineUrl = options.esbEngineUrl || null;
        this.nidaUserId = options.nidaUserId || null;

        this.apiCode = null;
        this.requestBody = null;
        this.format = 'json';
        this.accessToken = null;
        this.fetchFn = options.fetch || globalThis.fetch;
    }

    // ---------------------------
    // OAuth token
    // ---------------------------
    async getAccessToken() {
        const plainCredentials = `${this.clientId}:${this.clientSecret}`;
        const authorizationHeader = `Basic ${Buffer.from(plainCredentials).toString('base64')}`;

        const form = new URLSearchParams();
        form.set('client_id', this.clientId);
        form.set('client_secret', this.clientSecret);
        form.set('grant_type', 'client_credentials');

        if (!this.fetchFn) {
            throw new Error('Global fetch is not available. Use Node 18+ or provide a fetch polyfill.');
        }

        const res = await this.fetchFn(this.esbTokenUrl, {
            method: 'POST',
            headers: {
                Authorization: authorizationHeader,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: form.toString()
        });

        const json = await res.json();
        if (!res.ok) {
            throw new Error('Could not get access token from ESB');
        }
        if (json && json.access_token) {
            this.accessToken = json.access_token;
        }
        return json;
    }

    // ---------------------------
    // Public API
    // ---------------------------
    async requestData(apiCode, requestBody, format) {
        return this.#request(apiCode, requestBody, format, false, null, `${this.esbEngineUrl}/request`, null);
    }

    async requestNida(apiCode, requestBody, format) {
        if (this.nidaUserId == null) {
            throw new Error('nidaUserId is required');
        }
        return this.#request(apiCode, requestBody, format, false, this.nidaUserId, `${this.esbEngineUrl}/nida-request`, null);
    }

    async pushData(apiCode, requestBody, format) {
        return this.#request(apiCode, requestBody, format, true, null, `${this.esbEngineUrl}/push-request`, null);
    }

    async successResponse(requestBody, format) {
        return this.#esbResponse(true, requestBody, null, format, false);
    }

    async failureResponse(requestBody, message, format) {
        return this.#esbResponse(false, requestBody, message, format, false);
    }

    handledFailureResponse(requestBody, message, format) {
        try {
            return this.#esbResponse(false, requestBody, message, format, false);
        } catch (e) {
            return null;
        }
    }

    async asyncSuccessResponse(requestBody, format) {
        return this.#esbResponse(true, requestBody, null, format, true);
    }

    async asyncFailureResponse(requestBody, message, format) {
        return this.#esbResponse(false, requestBody, message, format, true);
    }

    // ---------------------------
    // Response helpers
    // ---------------------------
    async #esbResponse(isSuccess, requestBody, message, format, isAsyncResponse) {
        return this.#createEsbResponse(isSuccess, requestBody, message, isAsyncResponse, format);
    }

    async #createEsbResponse(isSuccess, requestBody, message, isAsyncResponse, format) {
        if (format) this.format = format;
        if (this.format === 'json') {
            return this.#createJsonResponse(isSuccess, requestBody, message, isAsyncResponse);
        }
        return this.#createXmlResponse(isSuccess, requestBody, message, isAsyncResponse);
    }

    async #createJsonResponse(isSuccess, requestBody, message, isAsyncResponse) {
        const dataNode = this.#createResponseData(isSuccess, requestBody, message, isAsyncResponse);
        const payload = JSON.stringify(dataNode);
        const signature = this.#signData(payload);
        return JSON.stringify({ data: dataNode, signature });
    }

    async #createXmlResponse(isSuccess, requestBody, message, isAsyncResponse) {
        const dataNode = this.#createResponseData(isSuccess, requestBody, message, isAsyncResponse);
        const dataXml = this.#toXml('data', dataNode);
        const signature = this.#signData(dataXml);
        const resp = { data: dataNode, signature };
        return this.#toXml('esbresponse', resp);
    }

    #createResponseData(isSuccess, requestBody, message, isAsyncResponse) {
        const node = { success: !!isSuccess };
        if (requestBody != null) {
            try {
                node.esbBody = JSON.parse(requestBody);
            } catch {
                node.esbBody = requestBody;
            }
        }
        if (!isSuccess && message != null) {
            node.message = message;
        }
        if (isAsyncResponse && isSuccess) {
            node.requestId = this.apiCode || null;
        }
        return node;
    }

    // ---------------------------
    // Verify + extract
    // ---------------------------
    verifyThenReturnData(esbResponse, format) {
        if (format) this.format = format;
        let dataString = '';
        let signature = '';

        if (this.format === 'json') {
            const node = typeof esbResponse === 'string' ? JSON.parse(esbResponse) : esbResponse;
            signature = node.signature;
            dataString = JSON.stringify(node.data);
        } else {
            signature = this.#extractXmlTag(esbResponse, 'signature') || '';
            const dataXml = this.#extractXmlTagWithContent(esbResponse, 'data') || '';
            dataString = `<data>${dataXml}</data>`;
        }

        const isValid = this.#verifyPayloadECC(dataString, signature);
        if (!isValid) {
            return null;
        }
        return dataString;
    }

    getEsbData(dataBody, format, field) {
        if (format) this.format = format;
        if (this.format === 'json') {
            const obj = typeof dataBody === 'string' ? JSON.parse(dataBody) : dataBody;
            return obj && obj[field] != null ? JSON.stringify(obj[field]) : '';
        }
        const xmlField = this.#extractXmlTagWithContent(dataBody, field);
        return xmlField ? `<${field}>${xmlField}</${field}>` : '';
    }

    // ---------------------------
    // Request builder + sender
    // ---------------------------
    async #request(apiCode, requestBody, format, isPushRequest, nidaUserId, esbRequestUrl, headers) {
        await this.#initializeRequest(apiCode, requestBody, format);
        const esbRequestBody = await this.#createEsbRequest(isPushRequest, nidaUserId);
        const esbResponse = await this.#sendEsbRequest(esbRequestBody, esbRequestUrl, headers);
        return this.verifyThenReturnData(esbResponse, this.format);
    }

    async #initializeRequest(apiCode, requestBody, format) {
        await this.#assertNotNull();
        await this.getAccessToken();
        this.#validateRequestParameters(apiCode, requestBody, format);
    }

    async #sendEsbRequest(body, url, headers) {
        const h = Object.assign(
            {
                Authorization: `Bearer ${this.accessToken}`,
                'Content-Type': `application/${this.format}; charset=utf-8`
            },
            headers || {}
        );

        if (!this.fetchFn) {
            throw new Error('Global fetch is not available. Use Node 18+ or provide a fetch polyfill.');
        }

        const res = await this.fetchFn(url, {
            method: 'POST',
            headers: h,
            body
        });
        const text = await res.text();
        return text;
    }

    async #createEsbRequest(isPushRequest, userId) {
        if (this.format === 'json') {
            return this.#createJsonRequest(isPushRequest, userId);
        }
        if (this.format === 'xml') {
            return this.#createXmlRequest(isPushRequest, userId);
        }
        return null;
    }

    #createJsonRequest(isPushRequest, userId) {
        const data = this.#createEsbData(isPushRequest, userId);
        const payload = JSON.stringify(data);
        const signature = this.#signData(payload);
        return JSON.stringify({ data, signature });
    }

    #createXmlRequest(isPushRequest, userId) {
        if (this.requestBody != null) {
            this.requestBody = `<root>${this.requestBody}</root>`;
        }
        const data = this.#createEsbData(isPushRequest, userId);
        const payload = this.#toXml('data', data);
        const signature = this.#signData(payload);
        const wrapped = { data, signature };
        return this.#toXml('esbrequest', wrapped);
    }

    #createEsbData(isPushRequest, userId) {
        const isUser = userId != null;
        const obj = {};
        obj[isPushRequest ? 'pushCode' : 'apiCode'] = this.apiCode;
        if (isUser) {
            obj.userId = this.nidaUserId;
            let payloadParsed;
            try {
                payloadParsed = JSON.parse(this.requestBody);
            } catch {
                payloadParsed = this.requestBody;
            }
            obj.esbBody = { Payload: payloadParsed };
        } else {
            if (this.requestBody != null) {
                try {
                    obj.esbBody = JSON.parse(this.requestBody);
                } catch {
                    obj.esbBody = this.requestBody;
                }
            }
        }
        return obj;
    }

    // ---------------------------
    // Signing and verification (ECDSA SHA-256)
    // ---------------------------
    #signData(payload) {
        return this.#signPayloadECC(payload);
    }

	// Public signing helper for consumers
	signPayload(payload) {
		const stringified = typeof payload === 'string' ? payload : JSON.stringify(payload);
		return this.#signData(stringified);
	}

	// Public verification helper for consumers
	verifySignature(data, signatureB64) {
		const stringified = typeof data === 'string' ? data : JSON.stringify(data);
		return this.#verifyPayloadECC(stringified, signatureB64);
	}

    #signPayloadECC(payload) {
        const pem = this.#wrapPrivateKeyPem(this.clientPrivateKey);
        const sign = crypto.createSign('sha256');
        sign.update(Buffer.from(payload, 'utf8'));
        sign.end();
        // Java uses ASN.1 DER for ECDSA signatures (SHA256withECDSA).
        const signature = sign.sign({ key: pem, dsaEncoding: 'der' });
        return Buffer.from(signature).toString('base64');
    }

    #verifyPayloadECC(data, signatureB64) {
        try {
            const pem = this.#wrapPublicKeyPem(this.esbPublicKey);
            const verify = crypto.createVerify('sha256');
            verify.update(Buffer.from(data, 'utf8'));
            verify.end();
            const sig = Buffer.from(signatureB64, 'base64');
            return verify.verify({ key: pem }, sig);
        } catch {
            return false;
        }
    }

	// Public helpers for external signing/verification
	signPayload(payload) {
		return this.#signPayloadECC(payload);
	}

	verifyPayload(data, signatureB64) {
		return this.#verifyPayloadECC(data, signatureB64);
	}

    // ---------------------------
    // ECDH + HKDF + AES-256-GCM
    // ---------------------------
    encrypt(data, recipientPublicKeyBase64) {
        const recipientPem = this.#wrapPublicKeyPem(recipientPublicKeyBase64);
        const curveName = this.getPublicKeyCurveName(recipientPem);

        // Generate ephemeral EC key pair
        const { publicKey: ephPub, privateKey: ephPriv } = crypto.generateKeyPairSync('ec', {
            namedCurve: curveName
        });

        const recipientPubKey = crypto.createPublicKey(recipientPem);
        const sharedSecret = crypto.diffieHellman({ privateKey: ephPriv, publicKey: recipientPubKey });

        // HKDF with ikm=sharedSecret, salt=zeroes (32 bytes), info='aes-encryption'
        const aesKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32), Buffer.from('aes-encryption'), 32);

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        const ciphertext = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
        const tag = cipher.getAuthTag();

        // Tag first, then ciphertext (to match Java packaging)
        const encryptedDataWithTag = Buffer.concat([tag, ciphertext]);

        // Ephemeral public key as PEM, then base64 the PEM text
        const ephPubPem = ephPub.export({ type: 'spki', format: 'pem' });
        const json = {
            ephemeralKey: Buffer.from(ephPubPem, 'utf8').toString('base64'),
            iv: iv.toString('base64'),
            encryptedData: encryptedDataWithTag.toString('base64')
        };
        return JSON.stringify(json);
    }

    decrypt(encryptedDataJson) {
        const payload = typeof encryptedDataJson === 'string' ? JSON.parse(encryptedDataJson) : encryptedDataJson;
        const ephPem = Buffer.from(payload.ephemeralKey, 'base64').toString('utf8');
        const iv = Buffer.from(payload.iv, 'base64');
        const encryptedDataWithTag = Buffer.from(payload.encryptedData, 'base64');

        const tag = encryptedDataWithTag.subarray(0, 16);
        const ciphertext = encryptedDataWithTag.subarray(16);

        const privatePem = this.#wrapPrivateKeyPem(this.clientPrivateKey);
        const privateKeyObj = crypto.createPrivateKey(privatePem);
        const ephPubKeyObj = crypto.createPublicKey(ephPem);

        const sharedSecret = crypto.diffieHellman({ privateKey: privateKeyObj, publicKey: ephPubKeyObj });
        // HKDF with ikm=sharedSecret, salt=zeroes (32 bytes), info='aes-encryption'
        const aesKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32), Buffer.from('aes-encryption'), 32);

        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return plaintext.toString('utf8');
    }

    // ---------------------------
    // Key helpers
    // ---------------------------
    getPublicKeyCurveName(pemKey) {
        try {
            const keyObj = crypto.createPublicKey(pemKey);
            const details = keyObj.asymmetricKeyDetails || {};
            if (details.namedCurve) return details.namedCurve;
        } catch { }
        // Fallback common curve
        return 'prime256v1';
    }

    #wrapPublicKeyPem(base64Der) {
        return `-----BEGIN PUBLIC KEY-----\n${base64Der}\n-----END PUBLIC KEY-----`;
    }

    #wrapPrivateKeyPem(base64Der) {
        return `-----BEGIN PRIVATE KEY-----\n${base64Der}\n-----END PRIVATE KEY-----`;
    }

    // ---------------------------
    // Validation
    // ---------------------------
    async #assertNotNull() {
        if (
            !this.clientId ||
            !this.clientSecret ||
            !this.clientPrivateKey ||
            !this.esbPublicKey ||
            !this.esbTokenUrl ||
            !this.esbEngineUrl
        ) {
            throw new Error('Some EsbHelper properties are null: make sure all required properties are set');
        }
    }

    #validateRequestParameters(apiCode, requestBody, format) {
        if (apiCode) {
            this.apiCode = apiCode;
        }
        if (requestBody) {
            this.requestBody = requestBody;
        }
        if (format) {
            this.format = format;
        }
        if (!this.apiCode) {
            throw new Error('apiCode can not be null');
        }
        if (!this.format || (this.format.toLowerCase() !== 'json' && this.format.toLowerCase() !== 'xml')) {
            throw new Error('format can not be null');
        }
    }

    // ---------------------------
    // Simple XML helpers (minimal)
    // ---------------------------
    #toXml(rootName, obj) {
        const serialize = (value, key) => {
            if (value == null) return '';
            if (Array.isArray(value)) {
                return value.map(v => serialize(v, key)).join('');
            }
            if (typeof value === 'object') {
                const inner = Object.keys(value)
                    .map(k => serialize(value[k], k))
                    .join('');
                return key ? `<${key}>${inner}</${key}>` : inner;
            }
            // primitives
            const escaped = String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return key ? `<${key}>${escaped}</${key}>` : escaped;
        };
        return `<${rootName}>${serialize(obj)}</${rootName}>`;
    }

    #extractXmlTag(xml, tag) {
        const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(xml);
        return m ? m[1].trim() : null;
    }

    #extractXmlTagWithContent(xml, tag) {
        // returns inner XML (without outer tag)
        const m = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(xml);
        return m ? m[1] : null;
    }

    // ---------------------------
    // Setters (parity with Java)
    // ---------------------------
    setClientPrivateKey(v) {
        this.clientPrivateKey = v;
    }
    setEsbPublicKey(v) {
        this.esbPublicKey = v;
    }
    setClientId(v) {
        this.clientId = v;
    }
    setClientSecret(v) {
        this.clientSecret = v;
    }
    setEsbTokenUrl(v) {
        this.esbTokenUrl = v;
    }
    setEsbEngineUrl(v) {
        this.esbEngineUrl = v;
    }
    setNidaUserId(v) {
        this.nidaUserId = v;
    }
    setAccessToken(v) {
        this.accessToken = v;
    }
    getFormat() {
        return this.format;
    }
}

module.exports = { GovEsbHelper };


