import React, { useMemo } from 'react';
import PlotModule from 'react-plotly.js';

const Plot = PlotModule.default || PlotModule;

// --- DICI Theme Constants ---
const BLUE = '#00d4ff';
const GRN = '#00ff9d';
const YLW = '#ffb700';
const GRID = '#1e2d45';
const TEXT = '#607080';

interface Exp2Data {
  [key: string]: {
    f1?: number;
    precision?: number;
    recall?: number;
  };
}

const ModelComparisonChart: React.FC<{ exp2Data: Exp2Data }> = ({ exp2Data }) => {
  const fmt = (v?: number) => (v != null ? v.toFixed(2) + '%' : '0.00%');

  const chartData = useMemo(() => {
    const keys = ['IDS_CTI_Transfer', 'IDS_IoC_Database', 'Standalone_IDS', 'IoC_DB_only'];
    const labels = ['IDS+CTI<br>Transfer', 'IDS+IoC<br>Database', 'Standalone<br>IDS', 'IoC DB<br>Only'];

    if (!exp2Data || Object.keys(exp2Data).length === 0) return null;

    return [
      {
        type: 'bar',
        name: 'F1 Score',
        x: labels,
        y: keys.map((k) => exp2Data[k]?.f1 || 0),
        marker: { color: BLUE, opacity: 0.85 },
        text: keys.map((k) => fmt(exp2Data[k]?.f1)),
        textposition: 'outside',
        hovertemplate: '%{x}<br>F1: <b>%{y:.2f}%</b><extra></extra>',
      },
      {
        type: 'bar',
        name: 'Precision',
        x: labels,
        y: keys.map((k) => exp2Data[k]?.precision || 0),
        marker: { color: GRN, opacity: 0.85 },
        hovertemplate: '%{x}<br>Prec: <b>%{y:.2f}%</b><extra></extra>',
      },
      {
        type: 'bar',
        name: 'Recall',
        x: labels,
        y: keys.map((k) => exp2Data[k]?.recall || 0),
        marker: { color: YLW, opacity: 0.85 },
        hovertemplate: '%{x}<br>Recall: <b>%{y:.2f}%</b><extra></extra>',
      },
    ];
  }, [exp2Data]);

  if (!chartData) {
    return (
      <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45] flex items-center justify-center h-[380px]">
        <p className="text-[#607080] font-mono text-[10px] uppercase tracking-widest">Awaiting Model Comparison Data...</p>
      </div>
    );
  }

  return (
    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45] w-full">
      <h3 className="text-[10px] text-gray-500 uppercase mb-6 tracking-widest flex items-center gap-2">
        <div className="w-1.5 h-1.5 bg-blue-400 rounded-full shadow-[0_0_8px_#00d4ff]" />
        Exp 2: Performance Metrics Comparison
      </h3>

      <Plot
        className="w-full h-[320px]"
        data={chartData as any}
        layout={{
          paper_bgcolor: 'transparent',
          plot_bgcolor: 'transparent',
          barmode: 'group',
          font: { family: "'Space Mono', monospace", color: TEXT, size: 10 },
          margin: { t: 20, r: 20, b: 60, l: 50 },
          legend: { 
            orientation: 'h', 
            y: 1.15, 
            font: { color: '#e8f0fe', size: 10 } 
          },
          xaxis: {
            gridcolor: GRID,
            zerolinecolor: GRID,
            tickfont: { color: '#e8f0fe' },
          },
          yaxis: {
            title: 'Performance (%)',
            gridcolor: GRID,
            zerolinecolor: GRID,
            range: [0, 115],
            tickfont: { color: '#e8f0fe' },
          },
        }}
        config={{
          responsive: true,
          displayModeBar: false,
        }}
      />
    </div>
  );
};

export default ModelComparisonChart;