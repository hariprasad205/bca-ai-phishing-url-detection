/**
 * PhishShield Dashboard Visualizations & Analytics (Chart.js)
 * Accessible High-Contrast Visualizations
 */

document.addEventListener("DOMContentLoaded", function () {
  // 1. User Dashboard: Risk Distribution Donut Chart
  const riskCanvas = document.getElementById("riskDistributionChart");
  if (riskCanvas) {
    const low = parseInt(riskCanvas.dataset.low || "0", 10);
    const mod = parseInt(riskCanvas.dataset.moderate || "0", 10);
    const high = parseInt(riskCanvas.dataset.high || "0", 10);
    const crit = parseInt(riskCanvas.dataset.critical || "0", 10);

    const total = low + mod + high + crit;

    new Chart(riskCanvas, {
      type: "doughnut",
      data: {
        labels: ["Low Risk (0-24)", "Moderate Risk (25-54)", "High Risk (55-79)", "Critical Risk (80-100)"],
        datasets: [{
          data: total > 0 ? [low, mod, high, crit] : [1],
          backgroundColor: total > 0
            ? ["#10B981", "#F59E0B", "#F97316", "#F43F5E"]
            : ["#334155"],
          borderColor: "#111B30",
          borderWidth: 3,
          hoverOffset: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#CBD5E1",
              font: { size: 12, weight: "600" },
              padding: 16,
              usePointStyle: true,
              pointStyle: "circle",
            }
          },
          tooltip: {
            enabled: total > 0,
            backgroundColor: "#0B1220",
            titleColor: "#FFFFFF",
            bodyColor: "#CBD5E1",
            borderColor: "#293750",
            borderWidth: 1,
            padding: 10,
            callbacks: {
              label: function (context) {
                const count = context.raw;
                const pct = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
                return ` ${context.label}: ${count} scan(s) (${pct}%)`;
              }
            }
          }
        },
        cutout: "68%"
      }
    });
  }

  // 2. Admin Model Comparison Metrics Bar Chart
  const modelCompCanvas = document.getElementById("modelMetricsChart");
  if (modelCompCanvas) {
    try {
      const rawData = JSON.parse(modelCompCanvas.dataset.models || "[]");
      // Distinct label formatting to distinguish versions
      const labels = rawData.map((m, idx) => {
        const vPart = m.version ? m.version.split("-").slice(-1)[0] : `#${idx + 1}`;
        return `${m.name} (${vPart})`;
      });
      const accuracy = rawData.map(m => m.accuracy);
      const recall = rawData.map(m => m.recall_score);
      const f1 = rawData.map(m => m.f1_score);
      const precision = rawData.map(m => m.precision_score);

      new Chart(modelCompCanvas, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [
            { label: "Accuracy", data: accuracy, backgroundColor: "#22D3EE", borderRadius: 4 },
            { label: "Recall (Phishing)", data: recall, backgroundColor: "#F43F5E", borderRadius: 4 },
            { label: "F1-Score", data: f1, backgroundColor: "#10B981", borderRadius: 4 },
            { label: "Precision", data: precision, backgroundColor: "#A855F7", borderRadius: 4 }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          layout: {
            padding: { top: 10, bottom: 5, left: 10, right: 10 }
          },
          scales: {
            y: {
              beginAtZero: true,
              max: 1.0,
              ticks: {
                color: "#CBD5E1",
                font: { size: 12, weight: "600" },
                callback: function (val) {
                  return (val * 100) + "%";
                }
              },
              grid: {
                color: "rgba(255, 255, 255, 0.08)"
              }
            },
            x: {
              ticks: {
                color: "#F8FAFC",
                font: { size: 12, weight: "600" },
                maxRotation: 25,
                minRotation: 0,
              },
              grid: {
                display: false
              }
            }
          },
          plugins: {
            legend: {
              position: "top",
              labels: {
                color: "#F8FAFC",
                font: { size: 13, weight: "700" },
                padding: 16,
                usePointStyle: true,
              }
            },
            tooltip: {
              backgroundColor: "#0B1220",
              titleColor: "#FFFFFF",
              bodyColor: "#CBD5E1",
              borderColor: "#293750",
              borderWidth: 1,
              padding: 12,
              callbacks: {
                label: function (ctx) {
                  return ` ${ctx.dataset.label}: ${(ctx.raw * 100).toFixed(2)}%`;
                }
              }
            }
          }
        }
      });
    } catch (err) {
      console.warn("Failed to initialize model metrics chart:", err);
    }
  }
});
