'use strict';

const crypto = require('crypto');
const { GovEsbHelper } = require('govesb-connector-js');

(async () => {
	// Generate keys for demo (prime256v1)
	const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
	const privateDerB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
	const publicDerB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

	// Create helper with keys (no live ESB calls here)
	const helper = new GovEsbHelper({
		clientPrivateKey: privateDerB64,
		esbPublicKey: publicDerB64
	});

	// 1) Sign + verify a JSON response
	const response = await helper.successResponse(JSON.stringify({ ok: true, when: new Date().toISOString() }), 'json');
	console.log('Signed response:', response);

	const verified = helper.verifyThenReturnData(response, 'json');
	console.log('Verified data   :', verified);

	// 2) Encrypt + decrypt a payload
	const payload = JSON.stringify({ secret: 'hello-world', counter: 1 });
	const encrypted = helper.encrypt(payload, publicDerB64);
	console.log('Encrypted blob  :', encrypted);

	const decrypted = helper.decrypt(encrypted);
	console.log('Decrypted text  :', decrypted);

	// Optional: uncomment to see parsed object
	// console.log(JSON.parse(decrypted));
})().catch(err => {
	console.error(err);
	process.exit(1);
});


