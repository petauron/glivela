export type { AppData } from "./types";
export type Mutate = (operation: () => Promise<unknown>, success?: string, options?: { reportError?: boolean }) => Promise<void>;
