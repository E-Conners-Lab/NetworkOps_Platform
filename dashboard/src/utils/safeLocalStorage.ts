export const safeLocalStorage = {
  getItem(key: string): string | null {
    try { return localStorage.getItem(key); }
    catch { console.warn(`Failed to read localStorage key "${key}"`); return null; }
  },
  setItem(key: string, value: string): void {
    try { localStorage.setItem(key, value); }
    catch { console.warn(`Failed to write localStorage key "${key}"`); }
  },
  removeItem(key: string): void {
    try { localStorage.removeItem(key); }
    catch { console.warn(`Failed to remove localStorage key "${key}"`); }
  },
};
