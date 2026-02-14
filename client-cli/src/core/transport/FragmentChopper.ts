import { createHash, randomInt, randomUUID } from 'node:crypto';

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

const byteLength = (value: string): number => Buffer.byteLength(value, 'utf8');

// Builds UTF-8 safe chunks while keeping each chunk <= 31 bytes.
function splitUtf8ByByteWindow(input: string): string[] {
    const chunks: string[] = [];
    let cursor = 0;

    while (cursor < input.length) {
        const remaining = input.slice(cursor);
        const remainingBytes = byteLength(remaining);
        const targetBytes = remainingBytes <= MAX_FRAGMENT_BYTES
            ? remainingBytes
            : randomInt(MIN_FRAGMENT_BYTES, MAX_FRAGMENT_BYTES + 1);

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

        const chunk = input.slice(cursor, end);
        chunks.push(chunk);
        cursor = end;
    }

    return chunks;
}

export function fragmentMessage(message: { to: string } & Record<string, unknown>): FragmentPacket[] {
    const to = typeof message.to === 'string' ? message.to.trim() : '';
    if (!to) {
        throw new Error('Message recipient is required for fragmentation');
    }

    const serialized = JSON.stringify(message);
    const checksum = createHash('sha256').update(serialized, 'utf8').digest('hex');
    const payloadChunks = splitUtf8ByByteWindow(serialized);
    const msgId = randomUUID();

    return payloadChunks.map((payload, frag_id) => ({
        msg_id: msgId,
        frag_id,
        total_frags: payloadChunks.length,
        checksum,
        payload,
        to
    }));
}
