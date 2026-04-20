import React, { useState, useEffect, useCallback } from 'react';
import { Activity, Zap, BarChart3, PieChart, Layers, Cpu, Table as TableIcon, Filter, HardDrive } from 'lucide-react';
import PlotModule from 'react-plotly.js';

const Plot = PlotModule.default || PlotModule;

// --- Types & Constants ---
interface TrafficStream { benign: number; malicious: number; outlier: number; total: number; }
interface DashboardState { results: any; last_updated: string; pipeline_running: boolean; traffic_stream: TrafficStream; }

const API_BASE = "http://localhost:5000";
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

function App2() {
    const [state, setState] = useState<DashboardState | null>(null);
    const [isRunning, setIsRunning] = useState(false);

    const fetchData = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/state`);
            const data = await res.json();
            setState(data);
            setIsRunning(data.pipeline_running);
        } catch (err) { console.error("Sync error:", err); }
    }, []);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, [fetchData]);

    const results = state?.results || {};

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
        <div className="min-h-screen bg-[#050810] text-white font-sans pb-12">
            {/* ── HEADER ── */}
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

            <main className="w-full max-w-[1600px] mx-auto p-6 space-y-8">

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


                {/* ── SECTION 1: CORE PERFORMANCE (3 GRAPHS) ── */}
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    {/* Graph 1: F1 Over Iterations (Fig 6) */}
                    <div className="xl:col-span-2 bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><Activity size={14} /> 1. F1 Score – Online Learning Iterations (Fig 6)</h3>
                        <Plot className="w-full h-[320px]" data={[
                            { x: results.exp1?.iterations, y: results.exp1?.with_cti_f1, name: 'IDS + CTI', type: 'scatter', mode: 'lines+markers', line: { color: COLORS.green, width: 3 } },
                            { x: results.exp1?.iterations, y: results.exp1?.no_cti_f1, name: 'No CTI', type: 'scatter', mode: 'lines', line: { color: COLORS.danger, dash: 'dot' } }
                        ]} layout={PLOT_LAYOUT_BASE} config={{ displayModeBar: false }} />
                    </div>

                    {/* Graph 2: Traffic Distribution (Donut) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><PieChart size={14} /> 2. Live Traffic Stream</h3>
                        <Plot className="w-full h-[320px]" data={[{
                            type: 'pie', hole: 0.6,
                            values: [state?.traffic_stream?.benign || 70, state?.traffic_stream?.malicious || 20, state?.traffic_stream?.outlier || 10],
                            labels: ['Benign', 'Malicious', 'Outlier'],
                            marker: { colors: [COLORS.green, COLORS.danger, COLORS.warn] }
                        }]} layout={{ ...PLOT_LAYOUT_BASE, margin: { t: 0, b: 0, l: 0, r: 0 } }} config={{ displayModeBar: false }} />
                    </div>

                    {/* Graph 3: Model Comparison Bar (Fig 8) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45] xl:col-span-3">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><BarChart3 size={14} /> 3. Performance Metrics: CTI Transfer vs IoC Database (Fig 8)</h3>
                        <Plot className="w-full h-[300px]" data={[
                            { x: ['IDS+CTI', 'IDS+IoC', 'Standalone', 'IoC Only'], y: [results.exp2?.IDS_CTI_Transfer?.f1, results.exp2?.IDS_IoC_Database?.f1, results.exp2?.Standalone_IDS?.f1, results.exp2?.IoC_DB_only?.f1], name: 'F1 Score', type: 'bar', marker: { color: COLORS.accent } },
                            { x: ['IDS+CTI', 'IDS+IoC', 'Standalone', 'IoC Only'], y: [results.exp2?.IDS_CTI_Transfer?.precision, results.exp2?.IDS_IoC_Database?.precision, results.exp2?.Standalone_IDS?.precision, results.exp2?.IoC_DB_only?.precision], name: 'Precision', type: 'bar', marker: { color: COLORS.green } }
                        ]} layout={{ ...PLOT_LAYOUT_BASE, barmode: 'group' }} config={{ displayModeBar: false }} />
                    </div>
                </div>

                {/* ── SECTION 2: CTI & FEATURE ANALYSIS (3 GRAPHS) ── */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Graph 4: Sighting Type Impact (Fig 12) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><Layers size={14} /> 4. F1 by Sighting Type (Fig 12)</h3>
                        <Plot className="w-full h-[300px]" data={[{
                            y: Object.keys(results.exp4 || {}), x: Object.values(results.exp4 || {}),
                            type: 'bar', orientation: 'h', marker: { color: COLORS.accent }
                        }]} layout={{ ...PLOT_LAYOUT_BASE, margin: { ...PLOT_LAYOUT_BASE.margin, l: 80 } }} config={{ displayModeBar: false }} />
                    </div>

                    {/* Graph 5: Feature Count vs F1 (Fig 13 Left) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><Filter size={14} /> 5. F1 vs Feature Count (Fig 13)</h3>
                        <Plot className="w-full h-[300px]" data={[{
                            x: Object.keys(results.exp3?.feature_count_f1 || {}), y: Object.values(results.exp3?.feature_count_f1 || {}),
                            type: 'scatter', mode: 'lines+markers', line: { color: COLORS.warn }
                        }]} layout={PLOT_LAYOUT_BASE} config={{ displayModeBar: false }} />
                    </div>

                    {/* Graph 6: KMeans++ vs Rule Bar (Fig 13 Right) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><BarChart3 size={14} /> 6. KMeans++ vs Rule Performance</h3>
                        <Plot className="w-full h-[300px]" data={[
                            { x: ['F1', 'Prec'], y: [results.exp3?.kmeanspp?.f1, results.exp3?.kmeanspp?.precision], name: 'KMeans++', type: 'bar', marker: { color: COLORS.green } },
                            { x: ['F1', 'Prec'], y: [results.exp3?.rule_based?.f1, results.exp3?.rule_based?.precision], name: 'Rule-Based', type: 'bar', marker: { color: COLORS.danger } }
                        ]} layout={{ ...PLOT_LAYOUT_BASE, barmode: 'group' }} config={{ displayModeBar: false }} />
                    </div>
                </div>

                {/* ── SECTION 3: SYSTEM OPTIMIZATION (2 GRAPHS + 1 TABLE) ── */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Graph 7: Batch Size Optimization (Fig 14/15) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><Layers size={14} /> 7. Batch Size Optimisation (Fig 14)</h3>
                        <Plot className="w-full h-[300px]" data={[{
                            x: [32, 64, 128, 224, 512], y: [65, 78, 85, 89.5, 87],
                            type: 'scatter', mode: 'lines+markers', line: { color: COLORS.accent }
                        }]} layout={PLOT_LAYOUT_BASE} config={{ displayModeBar: false }} />
                    </div>

                    {/* Graph 8: Resource Comparison (Fig 7) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><Cpu size={14} /> 8. Resource Utilisation (Fig 7)</h3>
                        <Plot className="w-full h-[300px]" data={[
                            { x: ['Time', 'Mem', 'CPU'], y: [3.22, 17.43, 36.6], name: 'ML-IDS', type: 'bar', marker: { color: COLORS.accent } },
                            { x: ['Time', 'Mem', 'CPU'], y: [59.3, 65.14, 79.5], name: 'DL-IDS', type: 'bar', marker: { color: COLORS.danger } }
                        ]} layout={{ ...PLOT_LAYOUT_BASE, barmode: 'group' }} config={{ displayModeBar: false }} />
                    </div>

                    {/* The Table: Detailed Results Summary */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><TableIcon size={14} /> 9. Experiment Results Table</h3>
                        <div className="overflow-y-auto h-[300px] font-mono text-[11px]">
                            <table className="w-full">
                                <thead>
                                    <tr className="text-left text-gray-500 border-b border-[#1e2d45]">
                                        <th className="pb-2">Exp</th><th className="pb-2">Config</th><th className="pb-2">F1 Score</th>
                                    </tr>
                                </thead>
                                <tbody className="text-gray-300">
                                    <tr className="border-b border-[#1e2d45]/50"><td className="py-2">1</td><td>IDS+CTI</td><td className="text-emerald-400">89.52%</td></tr>
                                    <tr className="border-b border-[#1e2d45]/50"><td className="py-2">2</td><td>Transfer</td><td className="text-cyan-400">88.10%</td></tr>
                                    <tr className="border-b border-[#1e2d45]/50"><td className="py-2">3</td><td>KMeans++</td><td className="text-emerald-400">92.40%</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}

export default App2;