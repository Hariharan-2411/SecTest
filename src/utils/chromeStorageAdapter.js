// A Web-Storage-like adapter backed by chrome.storage.local, so the Supabase
// auth session survives popup close/reopen and is reachable from any extension
// context (popup, background). Each method returns a Promise, which Supabase's
// auth storage option supports. All access is guarded so a missing chrome API
// degrades to "no stored session" instead of throwing.

export const chromeStorageAdapter = {
  getItem(key) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get([key], (res) => {
          resolve(res && res[key] != null ? res[key] : null);
        });
      } catch (_) {
        resolve(null);
      }
    });
  },

  setItem(key, value) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.set({ [key]: value }, () => resolve());
      } catch (_) {
        resolve();
      }
    });
  },

  removeItem(key) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.remove([key], () => resolve());
      } catch (_) {
        resolve();
      }
    });
  },
};

export default chromeStorageAdapter;
