import { generateKeyPairSync } from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';

type KeyPair = {
	publicKey: string;
	privateKey: string;
};

type PublicKeys = {
	signingPublicKey: string;
	encryptionPublicKey: string;
	format: string;
};

type StoredKeys = {
	username: string;
	createdAt: string;
	format: string;
	signing: KeyPair;
	encryption: KeyPair;
};

const KEY_DIR = '.keys';

function normalizeUsername(value: string): string {
	return (value || '').trim().toLowerCase();
}

const exportKeyPair = (pair: { publicKey: any; privateKey: any }): KeyPair => {
	const publicKey = pair.publicKey
		.export({ type: 'spki', format: 'der' })
		.toString('base64');
	const privateKey = pair.privateKey
		.export({ type: 'pkcs8', format: 'der' })
		.toString('base64');

	return { publicKey, privateKey };
};

export async function generateAndStoreKeys(username: string): Promise<{ filePath: string; publicKeys: PublicKeys }> {
	const normalizedUsername = normalizeUsername(username);
	if (!normalizedUsername) {
		throw new Error('Username is required for key generation');
	}

	const signingPair = generateKeyPairSync('ed25519');
	const encryptionPair = generateKeyPairSync('x25519');

	const signing = exportKeyPair(signingPair);
	const encryption = exportKeyPair(encryptionPair);

	const payload = {
		username: normalizedUsername,
		createdAt: new Date().toISOString(),
		format: 'der-base64',
		signing,
		encryption
	};

	const dirPath = path.join(process.cwd(), KEY_DIR);
	await fs.mkdir(dirPath, { recursive: true });

	const filePath = path.join(dirPath, `${normalizedUsername}.json`);
	await fs.writeFile(filePath, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });

	return {
		filePath,
		publicKeys: {
			signingPublicKey: signing.publicKey,
			encryptionPublicKey: encryption.publicKey,
			format: payload.format
		}
	};
}

export async function loadStoredKeys(username: string): Promise<StoredKeys | null> {
	const normalizedUsername = normalizeUsername(username);
	if (!normalizedUsername) {
		throw new Error('Username is required to load keys');
	}

	const filePath = path.join(process.cwd(), KEY_DIR, `${normalizedUsername}.json`);
	try {
		const raw = await fs.readFile(filePath, 'utf8');
		return JSON.parse(raw) as StoredKeys;
	} catch (err: any) {
		if (err?.code === 'ENOENT') {
			return null;
		}
		throw err;
	}
}
