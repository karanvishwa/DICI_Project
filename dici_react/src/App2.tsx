import React, { useState, useEffect, useCallback } from 'react';
import { Activity, Zap, BarChart3, PieChart, Layers, Cpu, Table as TableIcon, Filter } from 'lucide-react';
import PlotModule from 'react-plotly.js';
import ResultsTable from './graphs/ResultsTable';
import SightingGraph from './graphs/SightingGraph';
import F1IterationsGraph from './graphs/F1IterationsGraph';
import ModelComparisonChart from './graphs/ModelComparisonChart';

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

function fmt(v: any) { return v != null ? (+v).toFixed(2) + '%' : '—'; }
function fmtNum(v: any) { return v != null ? (+v).toFixed(2) : '—'; }

function App2() {
    const [state, setState] = useState<DashboardState | null>(null);
    const [isRunning, setIsRunning] = useState(false);

    // 1. Add the simTraffic function using useCallback
    const simTraffic = useCallback(async () => {
        try {
            await fetch(`${API_BASE}/api/simulate_traffic`, { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ n: Math.floor(Math.random() * 200 + 100) })
            });
        } catch (err) {
            console.error("Traffic sim error:", err);
        }
    }, []);

    const fetchData = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/api/state`);
            const data = await res.json();
            setState(data);

            // ── KPIs ──
            const e1 = data.results.exp1 || {};
            const e3 = data.results.exp3 || {};
            const baseline = e1.no_cti_f1 ? e1.no_cti_f1[0] : null;
            const withCTI = e1.final_with || null;
            const imp = e1.improvement || 0;
            setKPI('kpi_f1_cti', fmt(withCTI), 'bar_f1_cti', 100);
            setKPI('kpi_f1_base', fmt(baseline), 'bar_f1_base', 100);
            setKPI('kpi_imp', (imp >= 0 ? '+' : '') + fmtNum(imp) + '%', 'bar_imp', 20);
            const km_m = e3.kmeanspp || {};
            const rb_m = e3.rule_based || {};
            const km_imp = (km_m.f1 || 0) - (rb_m.f1 || 0);
            setKPI('kpi_km_imp', (km_imp >= 0 ? '+' : '') + fmtNum(km_imp) + '%', 'bar_km', 50);
            // SVM / KMeans FPR (from exp2 standalone IDS metrics)
            const sa = (data.results.exp2 || {}).Standalone_IDS || {};
            setKPI('kpi_svm_fpr', fmt(sa.svm_fpr || null), 'bar_svm_fpr', 20);
            setKPI('kpi_km_fpr', fmt(sa.kmeans_fpr || null), 'bar_km_fpr', 60);

            setIsRunning(data.pipeline_running);
        } catch (err) { console.error("Sync error:", err); }
    }, []);

    useEffect(() => {
        fetchData();
        simTraffic(); // Start simulating traffic on mount
        const interval = setInterval(() => {
            fetchData();
            simTraffic(); }, 3000);
        return () => clearInterval(interval);
    }, [fetchData, simTraffic]);

    const results = state?.results || {};

    const runPipeline = async () => {
        setIsRunning(true);
        await fetch(`${API_BASE}/api/run_pipeline`, { method: 'POST' });
    };

    const kpi_results = {
        kpi_f1_cti: {
            val: 0,
            width: 0,
        },
        kpi_f1_base: {
            val: 0,
            width: 0,
        },
        kpi_imp: {
            val: 0,
            width: 0,
        },
        kpi_km_imp: {
            val: 0,
            width: 0,
        },
        kpi_svm_fpr: {
            val: 0,
            width: 0,
        },
        kpi_km_fpr: {
            val: 0,
            width: 0,
        },
    }

    const [kpiResults, setKpiResults] = useState(kpi_results);

    const setKPI = (id: any, val: any, barId: any, max: number) => {
        setKpiResults(prev => ({
            ...prev,
            [id]: {
                val: val,
                width: Math.min(100, Math.abs(parseFloat(val) || 0) / max * 100) + '%'
            }
        }));
    }

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
            <header className="w-full border-b border-[#1e2d45] px-8 py-4 flex flex-row justify-between items-center">
                <div className="flex flex-row gap-5 items-center">
                    <div>
                        <div className="logo text-left">⚡ DICI</div>
                        <div className="subtitle">Dynamic IDS with CTI Integrated · IEEE TMLCN 2025</div>
                    </div>
                    <span className="pill green">ML-IDS</span>
                    <span className="pill">KMeans++</span>
                    <span className="pill warn">Online Learning</span>
                </div>

                <div className="flex items-center gap-4">

                    <div className="pulse"></div>
                    <span className="ts" id="ts">Updated</span>
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
                    <div className="kpi">
                        <div className="label text-left">IDS + CTI · F1 Score</div>
                        <div className="val c-green text-left" id="kpi_f1_cti">{kpiResults.kpi_f1_cti?.val ?? '—'}</div>
                        <div className="sub text-left">Paper target: 89.52%</div>
                        <div className="bar text-left"><div className="bar-fill" id="bar_f1_cti" style={{ width: kpiResults.kpi_f1_cti?.width ?? '0%', background: 'var(--accent2)' }}></div></div>
                    </div>
                    <div className="kpi">
                        <div className="label text-left">Baseline · No CTI</div>
                        <div className="val c-blue text-left" id="kpi_f1_base">{kpiResults.kpi_f1_base?.val ?? '—'}</div>
                        <div className="sub text-left">Static offline model</div>
                        <div className="bar text-left"><div className="bar-fill" id="bar_f1_base" style={{ width: kpiResults.kpi_f1_base?.width ?? '0%', background: 'var(--accent)' }}></div></div>
                    </div>
                    <div className="kpi">
                        <div className="label text-left">CTI F1 Improvement</div>
                        <div className="val c-warn text-left" id="kpi_imp">{kpiResults.kpi_imp?.val ?? '—'}</div>
                        <div className="sub text-left">Paper: +9.29%</div>
                        <div className="bar text-left"><div className="bar-fill" id="bar_imp" style={{ width: kpiResults.kpi_imp?.width ?? '0%', background: 'var(--warn)' }}></div></div>
                    </div>
                    <div className="kpi">
                        <div className="label text-left">KMeans++ vs Rule</div>
                        <div className="val c-green text-left" id="kpi_km_imp">{kpiResults.kpi_km_imp?.val ?? '—'}</div>
                        <div className="sub text-left">Paper: +30.92%</div>
                        <div className="bar text-left"><div className="bar-fill" id="bar_km" style={{ width: kpiResults.kpi_km_imp?.width ?? '0%', background: 'var(--accent2)' }}></div></div>
                    </div>
                    <div className="kpi">
                        <div className="label text-left">SVM False Positive Rate</div>
                        <div className="val c-blue text-left" id="kpi_svm_fpr">{kpiResults.kpi_svm_fpr?.val ?? '—'}</div>
                        <div className="sub text-left">Paper: 7.70%</div>
                        <div className="bar text-left"><div className="bar-fill" id="bar_svm_fpr" style={{ width: kpiResults.kpi_svm_fpr?.width ?? '0%', background: 'var(--accent)' }}></div></div>
                    </div>
                    <div className="kpi">
                        <div className="label text-left">KMeans False Positive</div>
                        <div className="val c-warn text-left" id="kpi_km_fpr">{kpiResults.kpi_km_fpr?.val ?? '—'}</div>
                        <div className="sub text-left">Paper: 42.78%</div>
                        <div className="bar text-left"><div className="bar-fill" id="bar_km_fpr" style={{ width: kpiResults.kpi_km_fpr?.width ?? '0%', background: 'var(--warn)' }}></div></div>
                    </div>
                </div>


                {/* ── SECTION 1: CORE PERFORMANCE (3 GRAPHS) ── */}
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    {/* Graph 1: F1 Over Iterations (Fig 6) */}
                    <div className="xl:col-span-2 bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><Activity size={14} /> 1. F1 Score – Online Learning Iterations (Fig 6)</h3>
                        <F1IterationsGraph results={results} />
                    </div>

                    {/* Graph 2: Traffic Distribution (Donut) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45]">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><PieChart size={14} /> 2. Live Traffic Stream</h3>
                        <Plot className="w-full h-[320px]" data={[{
                            type: 'pie', hole: 0.6,
                            values: [state?.traffic_stream?.benign || 70, state?.traffic_stream?.malicious || 20, state?.traffic_stream?.outlier || 10],
                            labels: ['Benign', 'Malicious', 'Outlier'],
                            marker: { colors: [COLORS.green, COLORS.danger, COLORS.warn] }
                        }]} layout={{
                            ...PLOT_LAYOUT_BASE, margin: { t: 0, b: 0, l: 0, r: 0 },
                            annotations: [
                                {
                                    x: 0.5,
                                    y: 0.5,
                                    text: `<b>${state?.traffic_stream?.total ?? 100}</b><br><span style="font-size:10px; color:#607080">flows</span>`,
                                    showarrow: false,
                                    font: { color: COLORS.text, size: 16 },
                                    xref: 'paper',
                                    yref: 'paper',
                                },
                            ],
                        }} config={{ displayModeBar: false }}
                        />
                    </div>

                    {/* Graph 3: Model Comparison Bar (Fig 8) */}
                    <div className="bg-[#111827] p-6 rounded-xl border border-[#1e2d45] xl:col-span-3">
                        <h3 className="text-[10px] text-gray-500 uppercase mb-4 flex items-center gap-2"><BarChart3 size={14} /> 3. Performance Metrics: CTI Transfer vs IoC Database (Fig 8)</h3>
                        <ModelComparisonChart exp2Data={results.exp2 || {}} />
                    </div>
                </div>

                {/* ── SECTION 2: CTI & FEATURE ANALYSIS (3 GRAPHS) ── */}
                <SightingGraph data={results.exp4 || {}} />

                {/* ── SECTION 2: CTI & FEATURE ANALYSIS (3 GRAPHS) ── */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
                </div>
                {/* ── RESULTS TABLE ── */}
                <div className="mt-1 flex items-center gap-2 mb-4">
                    <div className="font-mono text-[0.72rem] text-[#607080] tracking-widest uppercase flex items-center gap-2 w-full after:content-[''] after:flex-1 after:h-[1px] after:bg-[#1e2d45]">
                        Detailed Results Table
                    </div>
                </div>

                <div className="bg-[#111827] border border-[#1e2d45] rounded-[14px] overflow-hidden mx-0 mb-8">
                    <div className="overflow-x-auto">
                        <ResultsTable res={results} />
                    </div>
                </div>
            </main>
        </div>
    );
}

export default App2;