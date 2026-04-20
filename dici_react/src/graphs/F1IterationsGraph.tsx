import React from 'react';
import PlotModule from 'react-plotly.js';

const Plot = PlotModule.default || PlotModule;


const COLORS = {
    bg: '#111827', accent: '#00d4ff', green: '#00ff9d', warn: '#ffb700',
    danger: '#ff4757', text: '#e8f0fe', muted: '#607080', grid: '#1e2d45'
};
const PLOT_LAYOUT_BASE: any = {
    paper_bgcolor: 'transparent', plot_bgcolor: 'transparent',
    font: { family: "'Space Mono', monospace", color: COLORS.muted, size: 10 },
    margin: { t: 30, r: 20, b: 40, l: 45 },
    xaxis: { gridcolor: COLORS.grid, zerolinecolor: COLORS.grid, tickfont: { color: COLORS.text } },
    yaxis: { gridcolor: COLORS.grid, zerolinecolor: COLORS.grid, tickfont: { color: COLORS.text } },
    legend: { orientation: 'h', y: 1.1, font: { color: COLORS.text } }
};

// The component assumes 'results' is passed as a prop from your main state
const F1IterationsGraph = ({ results }) => {
    const e1 = results.exp1 || {};
    const imp = e1.improvement || 0;

    // Generate iterations array if not provided by API
    const iters = e1.iterations ||
        (e1.with_cti_f1 ? [...Array(e1.with_cti_f1.length).keys()] : []);

    // Return null or a loader if data isn't ready
    if (!e1.with_cti_f1 || !e1.no_cti_f1) return <div className="text-gray-500">Loading Chart...</div>;

    return (
        <Plot
            className="w-full h-[340px]"
            data={[
                {
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'ML-IDS + CTI',
                    x: iters,
                    y: e1.with_cti_f1,
                    line: { color: '#00ff9d', width: 2.5 }, // Matches GRN
                    marker: { size: 6, color: '#00ff9d' },
                    hovertemplate: 'Iteration %{x}<br>F1: <b>%{y:.2f}%</b><extra>IDS+CTI</extra>',
                    fill: 'tozeroy',
                    fillcolor: 'rgba(0,255,157,.04)',
                },
                {
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'ML-IDS (no CTI)',
                    x: iters.slice(0, e1.no_cti_f1.length),
                    y: e1.no_cti_f1.slice(0, iters.length),
                    line: { color: '#ff4757', width: 2, dash: 'dot' }, // Matches RED
                    marker: { size: 6, color: '#ff4757', symbol: 'x' },
                    hovertemplate: 'Iteration %{x}<br>F1: <b>%{y:.2f}%</b><extra>No CTI</extra>',
                },
                {
                    type: 'scatter',
                    mode: 'lines',
                    name: 'Paper target (89.52%)',
                    x: [0, iters.length - 1],
                    y: [89.52, 89.52],
                    line: { color: '#ffb700', width: 1, dash: 'dashdot' }, // Matches YLW
                    showlegend: true,
                    hovertemplate: 'Paper: 89.52%<extra></extra>',
                },
            ]}
            layout={{
                ...PLOT_LAYOUT_BASE, // Ensure this constant is defined globally or imported
                xaxis: {
                    ...PLOT_LAYOUT_BASE.xaxis,
                    title: 'Iteration',
                    gridcolor: '#1e2d45'
                },
                yaxis: {
                    ...PLOT_LAYOUT_BASE.yaxis,
                    title: 'F1 Score (%)',
                    range: [60, 100],
                    gridcolor: '#1e2d45'
                },
                annotations: [
                    {
                        x: iters[iters.length - 1],
                        y: e1.with_cti_f1[e1.with_cti_f1.length - 1] + 1,
                        text: `<b>+${imp.toFixed(2)}%</b>`,
                        showarrow: false,
                        font: { color: '#00ff9d', size: 12, family: "'Space Mono', monospace" },
                    },
                ],
            }}
            config={{
                responsive: true,
                displayModeBar: false
            }}
        />
    );
};

export default F1IterationsGraph;