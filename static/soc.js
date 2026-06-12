// SOC Dashboard JS (future expansion)
console.log("SOC Dashboard Loaded");

async function fetchLogs() {
    const res = await fetch('/api/logs');
    const data = await res.json();
    console.log("Logs:", data);
}

setInterval(fetchLogs, 10000);