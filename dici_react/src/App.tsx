import React, { useState, useEffect, useCallback } from 'react';
import { Activity, Zap } from 'lucide-react';
import PlotModule from 'react-plotly.js';

const Plot = PlotModule.default || PlotModule;

// --- Types ---
interface TrafficStream {
  benign: number;
  malicious: number;
  outlier: number;
  total: number;
}

interface DashboardState {
  results: any;
  last_updated: string;
  pipeline_running: boolean;
  traffic_stream: TrafficStream;
}

// --- Constants ---
const API_BASE = "http://localhost:5000";

const COLORS = {
  bg: '#111827',
  accent: '#00d4ff',
  green: '#00ff9d',
  warn: '#ffb700',
  danger: '#ff4757',
  text: '#e8f0fe',
  muted: '#607080'
};

const PLOT_LAYOUT_BASE = {
  paper_bgcolor: 'transparent',
  plot_bgcolor: 'transparent',
  font: { color: COLORS.muted },
};

// --- Component ---
function App() {
  const [state, setState] = useState<DashboardState | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/state`);
      const data = await res.json();
      setState(data);
      setIsRunning(data.pipeline_running);
    } catch (err) {
      console.error("Error:", err);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const runPipeline = async () => {
    setIsRunning(true);
    await fetch(`${API_BASE}/api/run_pipeline`, { method: 'POST' });
  };

  // --- KPI Component ---
  const KPI = ({ label, val, sub }: any) => (
    <div className="bg-[#111827] border border-[#1e2d45] rounded-xl p-5 w-full">
      <div className="text-xs text-gray-400">{label}</div>
      <div className="text-2xl font-bold mt-1">{val}</div>
      <div className="text-xs text-gray-500">{sub}</div>
    </div>
  );

  const [ctiSearch, setCtiSearch] = useState("");
  const [ctiData, setCtiData] = useState<any>(null);
  const [isSearching, setIsSearching] = useState(false);

  const handleSearch = async () => {
    if (!ctiSearch) return;
    setIsSearching(true);
    try {
      const res = await fetch(`${API_BASE}/api/cti_lookup/${ctiSearch}`);
      const data = await res.json();
      setCtiData(data);
    } catch (err) {
      console.error("CTI Lookup Failed", err);
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050810] text-white">


      {/* Header */}
      <header className="w-full border-b border-[#1e2d45] px-8 py-4 flex justify-between items-center">
        <div>
          <div className="text-xl font-bold text-cyan-400">⚡ DICI</div>
          <div className="text-xs text-gray-500">Dynamic IDS Dashboard</div>
        </div>

        <div className="flex items-center gap-4">
          <span className="text-xs text-gray-400">
            {state?.last_updated || "Connecting..."}
          </span>

          <button
            onClick={runPipeline}
            className="bg-cyan-500 px-4 py-2 rounded text-black text-xs"
          >
            {isRunning ? "Running..." : "Run Pipeline"}
          </button>
        </div>
      </header>

      {/* Main */}
      <main className="w-full max-w-[1400px] mx-auto p-6 space-y-8">

        {/* Running alert */}
        {isRunning && (
          <div className="bg-yellow-500/10 text-yellow-400 p-3 rounded flex items-center gap-2">
            <Zap size={14} /> Pipeline running...
          </div>
        )}

        <div className="bg-[#111827] border border-[#1e2d45] rounded-xl p-6">
          <h3 className="text-[10px] text-gray-500 uppercase mb-4">VirusTotal CTI Lookup</h3>
          <div className="flex gap-2 mb-6">
            <input
              type="text"
              placeholder="Enter IP (e.g., 8.8.8.8)"
              className="bg-[#050810] border border-[#1e2d45] rounded-md px-3 py-2 text-sm w-full outline-none focus:border-cyan-500"
              onChange={(e) => setCtiSearch(e.target.value)}
            />
            <button
              onClick={handleSearch}
              className="bg-cyan-600 px-4 py-2 rounded-md text-xs font-bold uppercase"
            >
              {isSearching ? '...' : 'Search'}
            </button>
          </div>

          {ctiData && (
            <div className="space-y-4 animate-in fade-in">
              <div className="flex justify-between items-center border-b border-[#1e2d45] pb-2">
                <span className="text-xs text-gray-400">Reputation Score</span>
                <span className={`font-mono ${ctiData.reputation < 0 ? 'text-red-500' : 'text-green-500'}`}>
                  {ctiData.reputation}
                </span>
              </div>
              <div className="flex justify-between items-center border-b border-[#1e2d45] pb-2">
                <span className="text-xs text-gray-400">Detection Rate</span>
                <span className="font-mono text-cyan-400">
                  {ctiData.malicious_count} / {ctiData.malicious_count + ctiData.harmless_count}
                </span>
              </div>
              <div className="flex gap-2 flex-wrap">
                {ctiData.tags?.map((tag: string) => (
                  <span key={tag} className="bg-cyan-500/10 border border-cyan-500/30 text-cyan-500 text-[10px] px-2 py-0.5 rounded">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* KPI Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
          <KPI
            label="F1 Score"
            val={state?.results?.exp1?.final_with != null
              ? state.results.exp1.final_with.toFixed(2) + '%'
              : '—'}
            sub="Paper: 89.52%"
          />

          <KPI
            label="Baseline"
            val={state?.results?.exp1?.no_cti_f1?.[0] != null
              ? state.results.exp1.no_cti_f1[0].toFixed(2) + '%'
              : '—'}
            sub="Static Model"
          />

          <KPI
            label="Improvement"
            val={state?.results?.exp1?.improvement != null
              ? '+' + state.results.exp1.improvement.toFixed(2) + '%'
              : '—'}
            sub="Target: +9.29%"
          />

          <KPI label="KMeans++ vs Rule" val="+30.92%" sub="Efficiency" />
          <KPI label="SVM FPR" val="7.70%" sub="Target" />
          <KPI label="KMeans FPR" val="42.78%" sub="Baseline" />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Line Chart */}
          <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
            <h3 className="text-sm text-gray-400 mb-4 flex items-center gap-2">
              <Activity size={14} /> F1 Score Trend
            </h3>

            <Plot
              className="w-full h-[350px]"
              data={[
                {
                  x: state?.results?.exp1?.iterations || [],
                  y: state?.results?.exp1?.with_cti_f1 || [],
                  type: 'scatter',
                  mode: 'lines+markers',
                  line: { color: COLORS.green }
                }
              ]}
              layout={{ ...PLOT_LAYOUT_BASE }}
              config={{ displayModeBar: false }}
            />
          </div>

          {/* Pie Chart */}
          <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
            <h3 className="text-sm text-gray-400 mb-4">Traffic Distribution</h3>

            <Plot
              className="w-full h-[350px]"
              data={[
                {
                  type: 'pie',
                  values: [
                    state?.traffic_stream?.benign || 1,
                    state?.traffic_stream?.malicious || 0,
                    state?.traffic_stream?.outlier || 0
                  ],
                  labels: ['Benign', 'Malicious', 'Outlier']
                }
              ]}
              layout={{ ...PLOT_LAYOUT_BASE }}
              config={{ displayModeBar: false }}
            />
          </div>

        </div>
      </main>
    </div>
  );
}

export default App;