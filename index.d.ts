export interface GovEsbHelperOptions {
	clientPrivateKey?: string; // base64 PKCS8 DER (no PEM headers)
	esbPublicKey?: string; // base64 X.509 DER (no PEM headers)
	clientId?: string;
	clientSecret?: string;
	esbTokenUrl?: string;
	esbEngineUrl?: string;
	nidaUserId?: string | null;
	fetch?: typeof fetch;
}

export class GovEsbHelper {
	constructor(options?: GovEsbHelperOptions);

	getAccessToken(): Promise<any>;

	signPayload(payload: string | object): string;
	verifySignature(data: string | object, signatureB64: string): boolean;

	requestData(apiCode: string, requestBody: string, format: 'json' | 'xml'): Promise<string | null>;
	requestNida(apiCode: string, requestBody: string, format: 'json' | 'xml'): Promise<string | null>;
	pushData(apiCode: string, requestBody: string, format: 'json' | 'xml'): Promise<string | null>;

	successResponse(requestBody: string | null, format: 'json' | 'xml'): Promise<string>;
	failureResponse(requestBody: string | null, message: string, format: 'json' | 'xml'): Promise<string>;
	handledFailureResponse(requestBody: string | null, message: string, format: 'json' | 'xml'): string | null;
	asyncSuccessResponse(requestBody: string | null, format: 'json' | 'xml'): Promise<string>;
	asyncFailureResponse(requestBody: string | null, message: string, format: 'json' | 'xml'): Promise<string>;

	verifyThenReturnData(esbResponse: string, format: 'json' | 'xml'): string | null;
	getEsbData(dataBody: string, format: 'json' | 'xml', field: string): string;

	encrypt(data: string, recipientPublicKeyBase64: string): string;
	decrypt(encryptedDataJson: string): string;

	setClientPrivateKey(v: string): void;
	setEsbPublicKey(v: string): void;
	setClientId(v: string): void;
	setClientSecret(v: string): void;
	setEsbTokenUrl(v: string): void;
	setEsbEngineUrl(v: string): void;
	setNidaUserId(v: string | null): void;
	setAccessToken(v: string): void;
	getFormat(): 'json' | 'xml';
}


