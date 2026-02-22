import fs from 'node:fs';
import path from 'node:path';

export interface DirectMessage {
    id: string;
    from: string;
    to: string;
    content: string;
    timestamp: string;
    status?: string;
    encrypted?: boolean;
    iv?: string;
    content_type?: string;
    transport?: string;
}

const STORAGE_DIR = path.join(process.cwd(), 'data');

/**
 * Saves a message to a local JSON file for the specific user.
 * This ensures that even if the server deletes the message, the client keeps it.
 */
export function saveMessageLocally(username: string, message: DirectMessage) {
    if (!fs.existsSync(STORAGE_DIR)) {
        fs.mkdirSync(STORAGE_DIR, { recursive: true });
    }

    const filePath = path.join(STORAGE_DIR, `history_${username.toLowerCase()}.json`);
    let history: DirectMessage[] = [];

    if (fs.existsSync(filePath)) {
        try {
            history = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        } catch (e) {
            console.error('Failed to parse history file, starting fresh.');
        }
    }

    // Deduplicate by ID to prevent ghost messages if standard sync re-runs
    if (!history.find(m => m.id === message.id)) {
        history.push(message);
        fs.writeFileSync(filePath, JSON.stringify(history, null, 2));
    }
}

/**
 * Loads messages involving a specific contact from the local file.
 */
export function loadLocalHistory(username: string, contact: string): DirectMessage[] {
    const filePath = path.join(STORAGE_DIR, `history_${username.toLowerCase()}.json`);
    if (!fs.existsSync(filePath)) return [];

    try {
        const history: DirectMessage[] = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const normalizedContact = contact.toLowerCase();
        const normalizedUser = username.toLowerCase();

        return history
            .filter(m =>
                (m.from.toLowerCase() === normalizedUser && m.to.toLowerCase() === normalizedContact) ||
                (m.from.toLowerCase() === normalizedContact && m.to.toLowerCase() === normalizedUser)
            )
            .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    } catch (e) {
        return [];
    }
}
