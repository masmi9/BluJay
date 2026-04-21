import { useState, useCallback, useEffect } from 'react';

/**
 * Type-safe localStorage hook with JSON serialization.
 * Listens for cross-tab storage events to keep state in sync.
 */
export function useLocalStorage<T>(key: string, defaultValue: T): [T, (value: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      if (raw === null) return defaultValue;
      try {
        return JSON.parse(raw) as T;
      } catch {
        // Preserve pre-existing raw string values (e.g. 'standard' instead of '"standard"')
        return raw as unknown as T;
      }
    } catch {
      return defaultValue;
    }
  });

  const set = useCallback((next: T | ((prev: T) => T)) => {
    setValue((prev) => {
      const resolved = typeof next === 'function' ? (next as (prev: T) => T)(prev) : next;
      try {
        localStorage.setItem(key, JSON.stringify(resolved));
      } catch { /* quota exceeded - keep in-memory value */ }
      return resolved;
    });
  }, [key]);

  // Sync across tabs via storage event
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== key) return;
      try {
        setValue(e.newValue === null ? defaultValue : JSON.parse(e.newValue) as T);
      } catch {
        setValue(defaultValue);
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [key, defaultValue]);

  return [value, set];
}
