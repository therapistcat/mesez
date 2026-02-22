import { io, Socket } from "socket.io-client";
import { fragmentMessage } from "./FragmentChopper.ts";

class SocketProvider {
    socket: Socket | null;

    constructor() {
        this.socket = null;
    }

    connect(url: string, token: string | null = null) {
        this.socket = io(url, {
            auth: { token },
            transports: ['websocket', 'polling'] // Force websocket first
        });

        this.socket.on("connect_error", (err: any) => {
            console.error("Connection error:", err.message);
        });

        this.socket.on("connect", () => {
            // Connection logic handled in main index
        });
    }

    setAuth(token: string | null) {
        if (this.socket) {
            this.socket.auth = { token };
        }
    }

    send(message: any) {
        if (this.socket) {
            try {
                const fragments = fragmentMessage(message);
                fragments.forEach((fragment) => {
                    this.socket!.emit("fragment", fragment);
                });
            } catch (err: any) {
                console.error("Fragmentation failed, using legacy message event:", err?.message || err);
                // Fallback keeps compatibility if fragmentation fails unexpectedly.
                this.socket.emit("message", message);
            }
        }
    }

    onMessage(callback: (data: any) => void) {
        if (this.socket) {
            const handler = (data: any) => {
                callback(data);
            };

            this.socket.on("direct_message", handler);
            this.socket.on("message", handler);

            // Return a cleanup function
            return () => {
                this.socket!.off("direct_message", handler);
                this.socket!.off("message", handler);
            };
        }
        return () => { };
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
        }
    }
}

export default new SocketProvider();
