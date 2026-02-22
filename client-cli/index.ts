import inquirer from 'inquirer';
import chalk from 'chalk';
import { v4 as uuidv4 } from 'uuid';
import socketProvider from './src/core/transport/SocketProvider.ts';
import { generateAndStoreKeys, loadStoredKeys } from './src/crypto/keyManager.ts';
import { saveMessageLocally, loadLocalHistory } from './src/core/storage/MessageStore.ts';
import dotenv from 'dotenv';
dotenv.config();
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
let currentUser: string | null = null;
let currentToken: string | null = null;
// No room concept anymore, just direct chat context if needed or purely command based
let currentRecipient: string | null = null;
let currentKeys: any = null;

async function main() {
    console.log(chalk.blue.bold('Welcome to OffTheGrid CLI Chat!'));

    try {
        socketProvider.connect(SERVER_URL);
        console.log(chalk.gray(`Connected to socket server at ${SERVER_URL}...`));

        socketProvider.socket!.on('error', (err: any) => {
            // suppress global error spam, let handlers deal with it
        });

    } catch (error) {
        console.error(chalk.red('Failed to connect:', error));
        return;
    }

    await authFlow();
}

async function authFlow() {
    const { action } = await inquirer.prompt([{
        type: 'list',
        name: 'action',
        message: 'Welcome! Please select an option:\n1. Login\n2. Register\n3. Exit\nEnter choice number:',
        choices: [
            '1', '2', '3'
        ]
    }]);

    if (action.includes('3')) {
        console.log(chalk.blue('Goodbye!'));
        process.exit(0);
    }

    const credentials = await inquirer.prompt([
        { type: 'input', name: 'username', message: 'Username:' },
        { type: 'input', name: 'password', message: 'Password:' }
    ]);

    const { username, password } = credentials;

    if (action.includes('2')) {
        console.log(chalk.gray('Registering...'));
        socketProvider.socket!.emit('register', { id: uuidv4(), username, password });

        const result = await waitForAuth('register_success');
        if (result.success) {
            const userId = result.data?.userId;
            try {
                const { filePath, publicKeys } = await generateAndStoreKeys(username);
                socketProvider.socket!.emit('upload_public_keys', {
                    userId,
                    username,
                    ...publicKeys
                });
                console.log(chalk.green(`✔ Keys generated and saved to ${filePath}`));
            } catch (err: any) {
                console.error(chalk.red(`✘ Key generation failed: ${err.message || 'Unknown error'}`));
            }

            console.log(chalk.green('✔ Registration successful! Please login.'));
            await authFlow();
        } else {
            console.error(chalk.red(`✘ Registration failed: ${result.message}`));
            await authFlow();
        }

    } else if (action.includes('1')) {
        console.log(chalk.gray('Logging in...'));
        socketProvider.socket!.emit('login', { username, password });

        const result = await waitForAuth('login_success');
        if (result.success) {
            currentUser = result.data.username;
            currentToken = result.data.token;
            const userId = result.data.userId;
            // Update socket for future automatic re-authentications
            socketProvider.setAuth(currentToken);
            if (currentUser) {
                try {
                    currentKeys = await loadStoredKeys(currentUser);
                    if (!currentKeys) {
                        const { filePath, publicKeys } = await generateAndStoreKeys(currentUser);
                        socketProvider.socket!.emit('upload_public_keys', {
                            userId,
                            username: currentUser,
                            ...publicKeys
                        });
                        console.log(chalk.yellow(`⚠ No local keys found. New keys generated at ${filePath}`));
                        currentKeys = await loadStoredKeys(currentUser);
                    }
                } catch (err: any) {
                    console.error(chalk.red(`✘ Failed to load or generate local keys: ${err.message || 'Unknown error'}`));
                }
            }
            startBackgroundMessageProcessing();
            await mainMenu();
        } else {
            console.error(chalk.red(`✘ Login failed: ${result.message}`));
            await authFlow();
        }
    }
}

function waitForAuth(successEvent: string): Promise<{ success: boolean; data?: any; message?: string }> {
    return new Promise((resolve) => {
        const successHandler = (data: any) => {
            cleanup();
            resolve({ success: true, data });
        };

        const errorHandler = (err: any) => {
            cleanup();
            const msg = err.message || (typeof err === 'string' ? err : 'Unknown error');
            resolve({ success: false, message: msg });
        };

        const timeout = setTimeout(() => {
            cleanup();
            resolve({ success: false, message: 'Server did not respond (Timeout)' });
        }, 5000);

        const cleanup = () => {
            clearTimeout(timeout);
            socketProvider.socket!.off(successEvent, successHandler);
            socketProvider.socket!.off('error', errorHandler);
        };

        socketProvider.socket!.once(successEvent, successHandler);
        socketProvider.socket!.once('error', errorHandler);
    });
}

async function mainMenu() {
    console.log('');
    const { action } = await inquirer.prompt([{
        type: 'list',
        name: 'action',
        message: `Main Menu (${currentUser}):\nSelect an action:\n1. Start Direct Chat\n2. View Inbox\n3. Logout\n4. Exit\nEnter choice number:`,
        choices: [
            '1',
            '2',
            '3',
            '4'
        ]
    }]);

    if (action.includes('1')) {
        await chatSetupFlow();
    } else if (action.includes('2')) {
        await inboxMenu();
    } else if (action.includes('3')) {
        currentUser = null;
        currentToken = null;
        socketProvider.setAuth(null);
        console.log(chalk.yellow('Logged out.'));
        await authFlow();
    } else if (action.includes('4')) {
        console.log(chalk.blue('Goodbye!'));
        process.exit(0);
    }
}

async function chatSetupFlow() {
    const { recipient } = await inquirer.prompt([{
        type: 'input',
        name: 'recipient',
        message: 'Enter username to chat with (or type "back"):',
        validate: input => input.trim() !== ''
    }]);

    const target = recipient.trim();

    if (target.toLowerCase() === 'back') {
        await mainMenu();
        return;
    }

    console.log(chalk.green(`✔ Chatting with: ${target}`));
    console.log(chalk.gray('--- Loading Local Chat History... ---'));

    // Load from local store instead of server
    const history = loadLocalHistory(currentUser || '', target);

    history.forEach(msg => {
        const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const isMe = msg.from === currentUser;
        const color = isMe ? chalk.gray : chalk.cyan;
        const name = isMe ? 'You' : msg.from;
        console.log(color(`[${time}] [${name}]: ${msg.content}`));
    });

    console.log(chalk.gray('--- Chat Started (Type "exit" to leave) ---'));

    setupChatListeners(target);
    await startChatLoop(target);
}

async function inboxMenu() {
    console.log(chalk.blue.bold('\n--- Registered Users & Online Status ---'));

    const userStatusPromise = new Promise<any[]>(resolve => {
        const timer = setTimeout(() => {
            socketProvider.socket!.off('all_users_status_data', handler);
            resolve([]);
        }, 3000);
        const handler = (data: any) => {
            clearTimeout(timer);
            resolve(data || []);
        };
        socketProvider.socket!.once('all_users_status_data', handler);
    });

    socketProvider.socket!.emit('get_all_users_status');

    const usersStatus = await userStatusPromise;

    if (!Array.isArray(usersStatus) || usersStatus.length === 0) {
        console.log(chalk.yellow('\nNo other users are currently registered in the system.'));
        await mainMenu();
        return;
    }

    // Sort: Online users first, then alphabetically
    const sortedUsers = [...usersStatus].sort((a, b) => {
        if (a.status === 'online' && b.status !== 'online') return -1;
        if (a.status !== 'online' && b.status === 'online') return 1;
        return (a.username || '').localeCompare(b.username || '');
    });

    const choices = sortedUsers.map((user) => {
        const isOnline = user.status === 'online';
        // USE PLAIN TEXT for names to avoid rendering issues
        const label = isOnline ? `(ONLINE) ${user.username}` : `(OFFLINE) ${user.username}`;

        return {
            name: label,
            value: user.username
        };
    });

    choices.push({ name: '← Back to Main Menu', value: 'back' });

    const { selectedContact } = await inquirer.prompt([{
        type: 'rawlist', // More robust for varied Windows terminals
        name: 'selectedContact',
        message: 'Select a user to chat with (Enter number):',
        choices: choices
    }]);

    if (selectedContact === 'back') {
        await mainMenu();
    } else {
        await chatSetupFlow_Direct(selectedContact);
    }
}

async function chatSetupFlow_Direct(target: string) {
    console.log(chalk.green(`✔ Continuing chat with: ${target}`));
    console.log(chalk.gray('--- Chat Started (Type "exit" to leave) ---'));

    setupChatListeners(target);
    await startChatLoop(target);
}

let activeChatCleanup: (() => void) | null = null;

function setupChatListeners(recipient: string) {
    if (activeChatCleanup) activeChatCleanup();

    const cleanupUI = socketProvider.onMessage((data: any) => {
        const sender = data.from || 'Anonymous';
        const text = data.content;
        const time = data.timestamp ? new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Now';

        if (sender === recipient) {
            console.log(chalk.cyan(`\n[${time}] [${sender}]: ${text}`));
        } else if (sender !== currentUser) {
            console.log(chalk.magenta(`\n[${time}] [New Message from ${sender}]: ${text}`));
        }
    });

    const onNotification = (msg: any) => console.log(chalk.yellow(`\n[Info]: ${msg}`));
    const onUserStatus = (data: any) => {
        const { username, status } = data;
        if (username.toLowerCase() === recipient.toLowerCase()) {
            const color = status === 'online' ? chalk.green : chalk.red;
            console.log(color(`\n[System]: ${username} is now ${status}.`));
        }
    };

    socketProvider.socket!.on('notification', onNotification);
    socketProvider.socket!.on('user_status', onUserStatus);

    activeChatCleanup = () => {
        cleanupUI();
        socketProvider.socket!.off('notification', onNotification);
        socketProvider.socket!.off('user_status', onUserStatus);
        activeChatCleanup = null;
    };
}

let isBackgroundProcessingStarted = false;
function startBackgroundMessageProcessing() {
    if (!socketProvider.socket || isBackgroundProcessingStarted) return;
    isBackgroundProcessingStarted = true;

    const backgroundHandler = (data: any) => {
        if (currentUser) {
            saveMessageLocally(currentUser, data);
        }
        socketProvider.socket!.emit('message_delivered_ack', { msgId: data.id });
    };

    socketProvider.socket.on('direct_message', backgroundHandler);
    socketProvider.socket.on('message', backgroundHandler);
}

async function startChatLoop(recipient: string) {
    const { message } = await inquirer.prompt([{
        type: 'input',
        name: 'message',
        message: '>'
    }]);

    if (message.trim().toLowerCase() === 'exit') {
        if (activeChatCleanup) activeChatCleanup();
        console.log(chalk.yellow('Ended chat.'));
        await mainMenu();
        return;
    }

    if (message.trim()) {
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        process.stdout.write(chalk.gray(`[${time}] [You]: ${message}\n`));

        const messagePayload = {
            id: uuidv4(),
            from: currentUser,
            to: recipient,
            timestamp: new Date().toISOString(),
            content: message,
            content_type: "text",
            transport: "internet",
            status: "sent"
        };

        if (currentUser) {
            saveMessageLocally(currentUser, messagePayload as any);
        }

        socketProvider.send(messagePayload);
    }

    await startChatLoop(recipient);
}

main();