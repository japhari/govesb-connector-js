# Examples

Two-minute demo showing how to use `govesb-connector-js` without any live ESB calls (pure crypto/signing).

## Basic

```bash
cd examples/basic
npm i
npm start
```

What it does:
- Generates an EC keypair (prime256v1)
- Signs a JSON response and verifies it
- Encrypts a payload and decrypts it back

To try request/response with a real ESB later, instantiate `GovEsbHelper` with real credentials and call `getAccessToken()` and `requestData(...)` in your app.


