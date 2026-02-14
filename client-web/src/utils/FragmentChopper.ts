export interface FragmentPacket {
    msg_id: string;
    frag_id: number;
    total_frags: number;
    checksum: string;
    payload: string;
    to: string;
}

const MIN_FRAGMENT_BYTES = 20;
const MAX_FRAGMENT_BYTES = 31;

const encoder = new TextEncoder();
const byteLength = (value: string): number => encoder.encode(value).length;

function randomFragmentSize(): number {
    return MIN_FRAGMENT_BYTES + Math.floor(Math.random() * (MAX_FRAGMENT_BYTES - MIN_FRAGMENT_BYTES + 1));
}

// Splits a UTF-16 string into UTF-8 sized fragments without cutting surrogate pairs.
function splitUtf8ByByteWindow(input: string): string[] {
    const chunks: string[] = [];
    let cursor = 0;

    while (cursor < input.length) {
        const remaining = input.slice(cursor);
        const remainingBytes = byteLength(remaining);
        const targetBytes = remainingBytes <= MAX_FRAGMENT_BYTES ? remainingBytes : randomFragmentSize();

        let consumedBytes = 0;
        let end = cursor;

        while (end < input.length) {
            const codePoint = input.codePointAt(end);
            if (codePoint === undefined) {
                break;
            }

            const char = String.fromCodePoint(codePoint);
            const charBytes = byteLength(char);

            if (consumedBytes + charBytes > MAX_FRAGMENT_BYTES && consumedBytes > 0) {
                break;
            }

            if (consumedBytes + charBytes > targetBytes && consumedBytes >= MIN_FRAGMENT_BYTES) {
                break;
            }

            consumedBytes += charBytes;
            end += char.length;

            if (consumedBytes >= targetBytes) {
                break;
            }
        }

        if (end === cursor) {
            const codePoint = input.codePointAt(cursor);
            if (codePoint === undefined) {
                break;
            }
            end += String.fromCodePoint(codePoint).length;
        }

        chunks.push(input.slice(cursor, end));
        cursor = end;
    }

    return chunks;
}

async function sha256Hex(input: string): Promise<string> {
    const data = encoder.encode(input);
    const digestBuffer = await crypto.subtle.digest('SHA-256', data);
    const digestArray = Array.from(new Uint8Array(digestBuffer));
    return digestArray.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function fragmentMessage(message: { to: string } & Record<string, unknown>): Promise<FragmentPacket[]> {
    const to = typeof message.to === 'string' ? message.to.trim() : '';
    if (!to) {
        throw new Error('Message recipient is required for fragmentation');
    }

    const serialized = JSON.stringify(message);
    const checksum = await sha256Hex(serialized);
    const payloadChunks = splitUtf8ByByteWindow(serialized);
    const msgId = crypto.randomUUID();

    return payloadChunks.map((payload, frag_id) => ({
        msg_id: msgId,
        frag_id,
        total_frags: payloadChunks.length,
        checksum,
        payload,
        to
    }));
}
