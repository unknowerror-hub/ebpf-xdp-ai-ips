const SERVER_IP = "45.9.15.253";

async function fetchMetrics() {
    try {
        // Явное указание внешнего IP адреса хоста для обхода прокси-зависаний
        const response = await fetch(`http://${SERVER_IP}:8005/api/metrics`);
        if (!response.ok) throw new Error("Нет авторизации");
        
        const data = await response.json();
        
        // Текстовые данные
        document.getElementById('cpu-val').innerText = data.cpu;
        document.getElementById('ram-val').innerText = data.ram;
        document.getElementById('disk-val').innerText = data.disk;
        document.getElementById('sec-events').innerText = data.security.last_events_count_5m;
        
        // CSS Индикаторы (Progress Bars) вместо Chart.js
        document.getElementById('cpu-fill').style.width = data.cpu + '%';
        document.getElementById('ram-fill').style.width = data.ram + '%';

        document.getElementById('stat-black').innerText = data.security.total_blocks;
        document.getElementById('stat-white').innerText = data.security.total_whitelist;

        document.getElementById('services-zone').innerHTML = `
            <div class="service-row"><span>PostgreSQL Engine</span><span class="${data.services.postgresql === 'ACTIVE' ? 'srv-active' : 'srv-stopped'}">${data.services.postgresql}</span></div>
            <div class="service-row"><span>DHCP/DNS Daemon</span><span class="${data.services.dnsmasq === 'ACTIVE' ? 'srv-active' : 'srv-stopped'}">${data.services.dnsmasq}</span></div>
            <div class="service-row"><span>VPN Core Infrastructure</span><span class="${data.services.openvpn === 'ACTIVE' ? 'srv-active' : 'srv-stopped'}">${data.services.openvpn}</span></div>
        `;

        let rows = "";
        for (const [name, info] of Object.entries(data.interfaces)) {
            const cls = info.state === "UP" ? "status-up" : "status-down";
            rows += `<tr>
                <td><b>${name}</b></td>
                <td><span class="${cls}">${info.state}</span></td>
                <td><code>${info.ip}</code></td>
                <td><span style="color:#10b981;">⬇ ${info.speed_rx || 0.0} KB/s</span></td>
                <td><span style="color:#38bdf8;">⬆ ${info.speed_tx || 0.0} KB/s</span></td>
                <td>In: ${info.packets_recv} / Out: ${info.packets_sent}</td>
                <td><span style="color:${info.errors > 0 ? '#ef4444' : '#e2e8f0'}">${info.errors}</span></td>
            </tr>`;
        }
        document.getElementById('iface-body').innerHTML = rows;
    } catch (e) {
        console.error("Ошибка обновления данных:", e);
    }
}

setInterval(fetchMetrics, 1000);
fetchMetrics();
