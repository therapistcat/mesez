import dotenv from 'dotenv';
dotenv.config();

export const SERVER_URL =
  process.env.VITE_SERVER_URL || process.env.SERVER_URL || "http://localhost:3000";
