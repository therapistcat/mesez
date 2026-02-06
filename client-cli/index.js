import inquirer from 'inquirer';
import chalk from 'chalk';
import { v4 as uuidv4 } from 'uuid';
import socketProvider from './src/core/transport/SocketProvider.js';
import dotenv from 'dotenv';
dotenv.config();
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
let currentUser = null;
let currentToken = null;
// No room concept anymore, just direct chat context if needed or purely command based
let currentRecipient = null;

async function main() {
    console.log(chalk.blue.bold('Welcome to OffTheGrid CLI Chat!'));

    try {
        socketProvider.connect(SERVER_URL);
        console.log(chalk.gray(`Connected to socket server at ${SERVER_URL}...`));

        socketProvider.socket.on('error', (err) => {
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
        socketProvider.socket.emit('register', { username, password });

        const result = await waitForAuth('register_success');
        if (result.success) {
            console.log(chalk.green('✔ Registration successful! Please login.'));
            await authFlow();
        } else {
            console.error(chalk.red(`✘ Registration failed: ${result.message}`));
            await authFlow();
        }

    } else if (action.includes('1')) {
        console.log(chalk.gray('Logging in...'));
        socketProvider.socket.emit('login', { username, password });

        const result = await waitForAuth('login_success');
        if (result.success) {
            currentUser = result.data.username;
            currentToken = result.data.token;
            // Update socket for future automatic re-authentications
            socketProvider.setAuth(currentToken);
            console.log(chalk.green(`✔ Logged in as ${chalk.bold(currentUser)}`));
            await mainMenu();
        } else {
            console.error(chalk.red(`✘ Login failed: ${result.message}`));
            await authFlow();
        }
    }
}

function waitForAuth(successEvent) {
    return new Promise((resolve) => {
        const successHandler = (data) => {
            cleanup();
            resolve({ success: true, data });
        };

        const errorHandler = (err) => {
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
            socketProvider.socket.off(successEvent, successHandler);
            socketProvider.socket.off('error', errorHandler);
        };

        socketProvider.socket.once(successEvent, successHandler);
        socketProvider.socket.once('error', errorHandler);
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

    // Fetch History
    console.log(chalk.gray('Loading chat history...'));
    socketProvider.socket.emit('get_chat_history', { contact: target });

    await new Promise(resolve => {
        socketProvider.socket.once('chat_history', (data) => {
            if (data.contact.toLowerCase() === target.toLowerCase()) {
                data.messages.forEach(msg => {
                    const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const displaySender = msg.sender_username === currentUser ? 'You' : msg.sender_username;
                    const color = msg.sender_username === currentUser ? chalk.gray : chalk.cyan;
                    console.log(color(`[${time}] [${displaySender}]: ${msg.content}`));
                });
            }
            resolve();
        });
        setTimeout(resolve, 2000); // Timeout fallback
    });

    console.log(chalk.gray('--- Chat Started (Type "exit" to leave) ---'));

    setupChatListeners(target);
    await startChatLoop(target);
}

async function inboxMenu() {
    console.log(chalk.blue.bold('\n--- Registered Users & Online Status ---'));

    const userStatusPromise = new Promise(resolve => {
        const timer = setTimeout(() => {
            socketProvider.socket.off('all_users_status_data', handler);
            resolve([]);
        }, 3000);
        const handler = (data) => {
            clearTimeout(timer);
            resolve(data || []);
        };
        socketProvider.socket.once('all_users_status_data', handler);
    });

    socketProvider.socket.emit('get_all_users_status');

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

async function chatSetupFlow_Direct(target) {
    console.log(chalk.green(`✔ Continuing chat with: ${target}`));

    // Fetch History
    socketProvider.socket.emit('get_chat_history', { contact: target });

    await new Promise(resolve => {
        socketProvider.socket.once('chat_history', (data) => {
            if (data.contact.toLowerCase() === target.toLowerCase()) {
                data.messages.forEach(msg => {
                    const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const displaySender = msg.sender_username === currentUser ? 'You' : msg.sender_username;
                    const color = msg.sender_username === currentUser ? chalk.gray : chalk.cyan;
                    console.log(color(`[${time}] [${displaySender}]: ${msg.content}`));
                });
            }
            resolve();
        });
        setTimeout(resolve, 2000);
    });

    setupChatListeners(target);
    await startChatLoop(target);
}

function setupChatListeners(recipient) {
    socketProvider.socket.off('message');
    socketProvider.socket.off('notification');
    socketProvider.socket.off('user_status');

    socketProvider.onMessage((data) => {
        const sender = data.from || 'Anonymous';
        const text = data.content;
        const time = data.timestamp ? new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Now';

        if (sender === recipient) {
            console.log(chalk.cyan(`\n[${time}] [${sender}]: ${text}`));
        } else if (sender !== currentUser) {
            console.log(chalk.magenta(`\n[${time}] [New Message from ${sender}]: ${text}`)); // Notification for message from others
        }
    });

    socketProvider.socket.on('notification', (msg) => {
        console.log(chalk.yellow(`\n[Info]: ${msg}`));
    });

    socketProvider.socket.on('user_status', (data) => {
        const { username, status } = data;
        if (username.toLowerCase() === recipient.toLowerCase()) {
            const color = status === 'online' ? chalk.green : chalk.red;
            console.log(color(`\n[System]: ${username} is now ${status}.`));
        }
    });
}

async function startChatLoop(recipient) {
    const { message } = await inquirer.prompt([{
        type: 'input',
        name: 'message',
        message: '>'
    }]);

    if (message.trim().toLowerCase() === 'exit') {
        console.log(chalk.yellow('Ended chat.'));
        socketProvider.socket.off('message');
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
        socketProvider.send(messagePayload);
    }

    // Loop
    await startChatLoop(recipient);
}

main();