
(function(){
  const initial = window.__DASH_ANALYTICS__ || null;

  const elDays = document.getElementById("rangeDays");
  const kpi = {
    signals: document.getElementById("kpiSignals"),
    direct: document.getElementById("kpiDirect"),
    attachments: document.getElementById("kpiAttachments"),
    escalations: document.getElementById("kpiEscalations"),
    ackRate: document.getElementById("kpiAckRate"),
    overdue: document.getElementById("kpiOverdue"),
    ackReq: document.getElementById("kpiAckRequired"),
  };

  const chips = Array.from(document.querySelectorAll(".dash-range .chip[data-days]"));

  const issuerBody = document.getElementById("issuerLeaderboard");

  function setActiveChip(days){
    chips.forEach(c => c.classList.toggle("chip-active", String(c.dataset.days) === String(days)));
  }

  function setKPIs(data){
    if(!data || !data.kpis) return;
    if(elDays) elDays.textContent = String(data.days || "");
    if(kpi.signals) kpi.signals.textContent = String(data.kpis.signals ?? 0);
    if(kpi.direct) kpi.direct.textContent = String(data.kpis.direct ?? 0);
    if(kpi.attachments) kpi.attachments.textContent = String(data.kpis.attachments ?? 0);
    if(kpi.escalations) kpi.escalations.textContent = String(data.kpis.escalations ?? 0);
    if(kpi.ackRate) kpi.ackRate.textContent = String((data.kpis.ack_rate_pct ?? 0)) + "%";
    if(kpi.overdue) kpi.overdue.textContent = String(data.kpis.overdue_ack ?? 0);
    if(kpi.ackReq) kpi.ackReq.textContent = String(data.kpis.total_ack_required ?? 0);
  }

  function setLeaderboard(data){
    if(!issuerBody) return;
    issuerBody.innerHTML = "";
    const rows = (data && data.issuer_leaderboard) ? data.issuer_leaderboard : [];
    if(!rows.length){
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4" class="muted">No data in this range.</td>`;
      issuerBody.appendChild(tr);
      return;
    }
    rows.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(r.issuer || "Unknown")}</td>
        <td class="t-right">${Number(r.count || 0)}</td>
        <td class="t-right">${Number(r.requires_ack || 0)}</td>
        <td class="t-right">${Number(r.your_ack_rate || 0)}%</td>
      `;
      issuerBody.appendChild(tr);
    });
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
    }[c]));
  }

  let ackChart = null;
  let unitChart = null;

  function buildCharts(data){
    if(!window.Chart) return;
    const ackEl = document.getElementById("ackTrendChart");
    const unitEl = document.getElementById("unitActivityChart");

    const ack = data.ack_trend || {labels:[], required:[], acked:[]};
    const ua = data.unit_activity || {labels:[], signals:[], direct:[], attachments:[], overdue:[]};

    if(ackEl && !ackChart){
      ackChart = new Chart(ackEl, {
        type: "line",
        data: {
          labels: ack.labels || [],
          datasets: [
            { label: "Required", data: ack.required || [], tension: 0.35 },
            { label: "ACKed", data: ack.acked || [], tension: 0.35 }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 650 },
          interaction: { mode: "index", intersect: false },
          plugins: {
            legend: { display: true }
          },
          scales: {
            x: { ticks: { maxTicksLimit: 10 } },
            y: { beginAtZero: true, ticks: { precision: 0 } }
          }
        }
      });
    }

    if(unitEl && !unitChart){
      unitChart = new Chart(unitEl, {
        type: "bar",
        data: {
          labels: ua.labels || [],
          datasets: [
            { label: "Signals", data: ua.signals || [] },
            { label: "Direct", data: ua.direct || [] },
            { label: "Attachments", data: ua.attachments || [] },
            { label: "Overdue ACK", data: ua.overdue || [] }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 650 },
          plugins: { legend: { display: true } },
          interaction: { mode: "nearest", intersect: false },
          scales: {
            x: { ticks: { maxTicksLimit: 8 } },
            y: { beginAtZero: true, ticks: { precision: 0 } }
          }
        }
      });
    }
  }

  function updateCharts(data){
    if(ackChart && data.ack_trend){
      ackChart.data.labels = data.ack_trend.labels || [];
      ackChart.data.datasets[0].data = data.ack_trend.required || [];
      ackChart.data.datasets[1].data = data.ack_trend.acked || [];
      ackChart.update();
    }
    if(unitChart && data.unit_activity){
      unitChart.data.labels = data.unit_activity.labels || [];
      unitChart.data.datasets[0].data = data.unit_activity.signals || [];
      unitChart.data.datasets[1].data = data.unit_activity.direct || [];
      unitChart.data.datasets[2].data = data.unit_activity.attachments || [];
      unitChart.data.datasets[3].data = data.unit_activity.overdue || [];
      unitChart.update();
    }
  }

  async function fetchAnalytics(days){
    const url = `/api/analytics/dashboard?days=${encodeURIComponent(days)}`;
    const res = await fetch(url, { headers: { "Accept": "application/json" }});
    if(!res.ok) throw new Error("Failed to load analytics");
    return await res.json();
  }

  async function applyRange(days){
    setActiveChip(days);
    try{
      const data = await fetchAnalytics(days);
      setKPIs(data);
      setLeaderboard(data);
      updateCharts(data);
    }catch(e){
      // keep UI stable; nothing noisy
      console.warn(e);
    }
  }

  // init
  if(initial){
    setKPIs(initial);
    setLeaderboard(initial);
    buildCharts(initial);
  } else {
    buildCharts({ack_trend:{labels:[],required:[],acked:[]}, unit_activity:{labels:[],signals:[],direct:[],attachments:[],overdue:[]}});
  }

  chips.forEach(c => {
    c.addEventListener("click", () => applyRange(c.dataset.days));
  });

  // show smooth default
  setActiveChip((initial && initial.days) ? initial.days : 7);
})();
