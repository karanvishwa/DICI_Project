import React from 'react';
import PlotModule from 'react-plotly.js';

const Plot = PlotModule.default || PlotModule;

// Constants matching your DICI theme
const GRN = '#00ff9d';
const BLUE = '#00d4ff';
const BG = '#111827';
const TEXT = '#607080';
const GRID = '#1e2d45';

interface SightingGraphProps {
  data: Record<string, number>;
}

const SightingGraph: React.FC<SightingGraphProps> = ({ data }) => {
  // 1. Data Transformation: Sort by value ascending for a better horizontal bar look
  const sortedKeys = Object.keys(data).sort((a, b) => data[a] - data[b]);
  const values = sortedKeys.map((k) => data[k]);
  const maxVal = Math.max(...values);

  // 2. Dynamic Bar Colors: Highlight the best performer
  const colors = values.map((v) => (v === maxVal ? GRN : BLUE));

  return (
    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45] w-full">
      <h3 className="text-[10px] text-gray-500 uppercase mb-4 tracking-widest flex items-center gap-2">
        <span className="w-2 h-2 bg-cyan-400 rounded-full"></span>
        Exp 4: F1 Score by Sighting Type
      </h3>
      
      <Plot
        className="w-full h-[350px]"
        data={[
          {
            type: 'bar',
            orientation: 'h',
            name: 'F1 Score',
            y: sortedKeys,
            x: values,
            marker: { 
              color: colors, 
              opacity: 0.85,
              line: { color: BG, width: 1 }
            },
            text: values.map((v) => v.toFixed(2) + '%'),
            textposition: 'outside',
            hovertemplate: '<b>%{y}</b><br>F1: %{x:.2f}%<extra></extra>',
          },
        ]}
        layout={{
          paper_bgcolor: 'transparent',
          plot_bgcolor: 'transparent',
          font: { family: "'Space Mono', monospace", color: TEXT, size: 10 },
          margin: { t: 20, r: 50, b: 40, l: 110 }, // Increased left margin for labels
          xaxis: {
            title: 'F1 Score (%)',
            gridcolor: GRID,
            zerolinecolor: GRID,
            range: [0, 110],
            tickfont: { color: '#e8f0fe' },
          },
          yaxis: {
            gridcolor: GRID,
            zerolinecolor: GRID,
            automargin: true,
            tickfont: { color: '#e8f0fe' },
          },
          annotations: [
            {
              x: values[values.length - 1],
              y: sortedKeys[sortedKeys.length - 1],
              showarrow: true,
              arrowhead: 0,
              ax: 40,
              ay: 0,
              font: { color: GRN, size: 11 },
            },
          ],
        }}
        config={{
          responsive: true,
          displayModeBar: false,
        }}
      />
    </div>
  );
};

export default SightingGraph;