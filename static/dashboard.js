const chartData = window.dashboardChartData || {};

const severityLabels = chartData.severity_labels || [];
const severityValues = chartData.severity_values || [];

const alertTypeLabels = chartData.alert_type_labels || [];
const alertTypeValues = chartData.alert_type_values || [];

const mitreLabels = chartData.mitre_labels || [];
const mitreValues = chartData.mitre_values || [];

Chart.defaults.color = "#e5e7eb";
Chart.defaults.borderColor = "rgba(148, 163, 184, 0.25)";

new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
        labels: severityLabels,
        datasets: [{
            data: severityValues,
            backgroundColor: ["#ef4444", "#f59e0b", "#22c55e"],
            borderColor: "#111827",
            borderWidth: 2
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: "bottom"
            }
        }
    }
});

new Chart(document.getElementById("alertTypeChart"), {
    type: "bar",
    data: {
        labels: alertTypeLabels,
        datasets: [{
            label: "Alerts",
            data: alertTypeValues,
            backgroundColor: "rgba(56, 189, 248, 0.65)",
            borderColor: "#38bdf8",
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            x: {
                beginAtZero: true,
                ticks: {
                    precision: 0
                }
            }
        }
    }
});

new Chart(document.getElementById("mitreChart"), {
    type: "bar",
    data: {
        labels: mitreLabels,
        datasets: [{
            label: "Alerts",
            data: mitreValues,
            backgroundColor: "rgba(129, 140, 248, 0.65)",
            borderColor: "#818cf8",
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        plugins: {
            legend: {
                display: false
            }
        },
        scales: {
            x: {
                beginAtZero: true,
                ticks: {
                    precision: 0
                }
            }
        }
    }
});