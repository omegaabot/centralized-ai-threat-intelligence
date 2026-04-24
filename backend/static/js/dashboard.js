function createChart(canvasId, configBuilder) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    try {
        const payload = JSON.parse(canvas.dataset.chart || "{}");
        const config = configBuilder(payload);
        config.options = {
            maintainAspectRatio: false,
            ...config.options,
        };
        new Chart(canvas, config);
    } catch (error) {
        console.error(`Unable to render ${canvasId}`, error);
    }
}

createChart("riskChart", (payload) => ({
    type: "doughnut",
    data: {
        labels: payload.labels || [],
        datasets: [{
            data: payload.values || [],
            backgroundColor: ["#ff5f6d", "#ffbe55", "#20d6c7"],
            borderWidth: 0,
        }],
    },
    options: {
        plugins: {
            legend: { labels: { color: "#dff6ff" } },
        },
    },
}));

createChart("typeChart", (payload) => ({
    type: "bar",
    data: {
        labels: payload.labels || [],
        datasets: [{
            label: "IOC Count",
            data: payload.values || [],
            backgroundColor: "#5df2ff",
            borderRadius: 8,
        }],
    },
    options: {
        scales: {
            x: { ticks: { color: "#dff6ff" }, grid: { color: "rgba(255,255,255,0.06)" } },
            y: { ticks: { color: "#dff6ff" }, grid: { color: "rgba(255,255,255,0.06)" } },
        },
        plugins: {
            legend: { display: false },
        },
    },
}));

createChart("sourceChart", (payload) => ({
    type: "bar",
    data: {
        labels: payload.labels || [],
        datasets: [{
            label: "Feed Count",
            data: payload.values || [],
            backgroundColor: "#ff8c42",
            borderRadius: 8,
        }],
    },
    options: {
        indexAxis: "y",
        scales: {
            x: { ticks: { color: "#dff6ff" }, grid: { color: "rgba(255,255,255,0.06)" } },
            y: { ticks: { color: "#dff6ff" }, grid: { display: false } },
        },
        plugins: {
            legend: { display: false },
        },
    },
}));

createChart("timelineChart", (payload) => ({
    type: "line",
    data: {
        labels: payload.labels || [],
        datasets: [{
            label: "Threats",
            data: payload.values || [],
            borderColor: "#20d6c7",
            pointBackgroundColor: "#5df2ff",
            tension: 0.35,
            fill: true,
            backgroundColor: "rgba(32, 214, 199, 0.12)",
        }],
    },
    options: {
        scales: {
            x: { ticks: { color: "#dff6ff" }, grid: { color: "rgba(255,255,255,0.04)" } },
            y: { ticks: { color: "#dff6ff" }, grid: { color: "rgba(255,255,255,0.04)" } },
        },
        plugins: {
            legend: { labels: { color: "#dff6ff" } },
        },
    },
}));

createChart("statusChart", (payload) => ({
    type: "doughnut",
    data: {
        labels: payload.labels || [],
        datasets: [{
            data: payload.values || [],
            backgroundColor: ["#20d6c7", "#ffbe55", "#64748b"],
            borderWidth: 0,
        }],
    },
    options: {
        plugins: {
            legend: { labels: { color: "#dff6ff" } },
        },
    },
}));

createChart("tacticChart", (payload) => ({
    type: "radar",
    data: {
        labels: payload.labels || [],
        datasets: [{
            label: "Tactics",
            data: payload.values || [],
            borderColor: "#5df2ff",
            backgroundColor: "rgba(93, 242, 255, 0.16)",
            pointBackgroundColor: "#20d6c7",
        }],
    },
    options: {
        scales: {
            r: {
                angleLines: { color: "rgba(255,255,255,0.08)" },
                grid: { color: "rgba(255,255,255,0.08)" },
                pointLabels: { color: "#dff6ff" },
                ticks: { display: false },
            },
        },
        plugins: {
            legend: { display: false },
        },
    },
}));

document.querySelectorAll(".clickable-row").forEach((row) => {
    row.addEventListener("click", (event) => {
        const interactive = event.target.closest("a, button, input, select, form");
        if (interactive) return;
        const href = row.dataset.href;
        if (href) {
            window.location.href = href;
        }
    });
});
