const { contextBridge, ipcRenderer } = require('electron');

// Expose a safe, limited API to the renderer (HTML/JS)
// The renderer cannot access Node.js directly — only through this bridge
contextBridge.exposeInMainWorld('electronAPI', {
    getData: () => ipcRenderer.invoke('db:get-data'),
    updateConfig: (config) => ipcRenderer.invoke('config:update', config)
});
