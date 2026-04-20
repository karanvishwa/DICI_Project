
interface ResultMetrics {
    f1?: number;
    precision?: number;
    recall?: number;
    final_with?: number;
    final_no?: number;
    no_cti_f1?: number[];
    improvement?: number;
}

interface ResultsState {
    exp1?: ResultMetrics;
    exp2?: Record<string, ResultMetrics>;
    exp3?: {
        kmeanspp?: ResultMetrics;
        rule_based?: ResultMetrics;
    };
}

const ResultsTable: React.FC<{ res: ResultsState }> = ({ res }) => {
    const fmt = (v: number | undefined) => (v != null ? `${v.toFixed(2)}%` : '—');

    // Logic to build the rows array
    const rows: React.ReactNode[] = [];
    const { exp1: e1 = {}, exp2: e2 = {}, exp3: e3 = {} } = res;

    // --- Experiment 1 Logic ---
    if (e1.final_with) {
        rows.push(
            <tr key="exp1-cti" className="hover:bg-[#161f30] border-t border-[#1e2d45]">
                <td className="p-4 text-[#607080]">Exp 1</td>
                <td className="p-4 font-bold">IDS + CTI Transfer</td>
                <td className="p-4 text-[#00ff9d] font-mono">{fmt(e1.final_with)}</td>
                <td className="p-4">—</td>
                <td className="p-4">—</td>
                <td className="p-4">
                    <span className="bg-[#00ff9d1a] text-[#00ff9d] border border-[#00ff9d4d] px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase">
                        +{e1.improvement?.toFixed(2)}% vs paper
                    </span>
                </td>
            </tr>
        );
        rows.push(
            <tr key="exp1-base" className="hover:bg-[#161f30] border-t border-[#1e2d45]">
                <td className="p-4 text-[#607080]">Exp 1</td>
                <td className="p-4 font-bold">IDS without CTI</td>
                <td className="p-4 text-[#00ff9d] font-mono">{fmt(e1.final_no || e1.no_cti_f1?.[0])}</td>
                <td className="p-4">—</td>
                <td className="p-4">—</td>
                <td className="p-4">
                    <span className="bg-[#ffb7001a] text-[#ffb700] border border-[#ffb7004d] px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase">
                        baseline
                    </span>
                </td>
            </tr>
        );
    }

    // --- Experiment 2 Logic ---
    const exp2Configs: [string, string, string][] = [
        ['IDS_CTI_Transfer', 'IDS+CTI Transfer', 'bg-[#00ff9d1a] text-[#00ff9d] border-[#00ff9d4d]'],
        ['IDS_IoC_Database', 'IDS+IoC Database', 'bg-[#ffb7001a] text-[#ffb700] border-[#ffb7004d]'],
        ['Standalone_IDS', 'Standalone IDS', 'bg-[#ff47571a] text-[#ff4757] border-[#ff47574d]'],
    ];

    exp2Configs.forEach(([key, label, badgeCls]) => {
        const m = e2[key];
        if (m?.f1) {
            rows.push(
                <tr key={`exp2-${key}`} className="hover:bg-[#161f30] border-t border-[#1e2d45]">
                    <td className="p-4 text-[#607080]">Exp 2</td>
                    <td className="p-4 font-bold">{label}</td>
                    <td className="p-4 text-[#00ff9d] font-mono">{fmt(m.f1)}</td>
                    <td className="p-4">{fmt(m.precision)}</td>
                    <td className="p-4">{fmt(m.recall)}</td>
                    <td className="p-4">
                        <span className={`px-2 py-0.5 rounded text-[0.65rem] font-mono border uppercase ${badgeCls}`}>
                            {key === 'IDS_CTI_Transfer' ? '✓ best' : 'baseline'}
                        </span>
                    </td>
                </tr>
            );
        }
    });

    // --- Experiment 3 Logic ---
    const km = e3.kmeanspp;
    const rb = e3.rule_based;

    if (km?.f1) {
        rows.push(
            <tr key="exp3-km" className="hover:bg-[#161f30] border-t border-[#1e2d45]">
                <td className="p-4 text-[#607080]">Exp 3</td>
                <td className="p-4 font-bold">KMeans++</td>
                <td className="p-4 text-[#00ff9d] font-mono">{fmt(km.f1)}</td>
                <td className="p-4">{fmt(km.precision)}</td>
                <td className="p-4">{fmt(km.recall)}</td>
                <td className="p-4">
                    <span className="bg-[#00ff9d1a] text-[#00ff9d] border border-[#00ff9d4d] px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase">
                        +{((km.f1 || 0) - (rb?.f1 || 0)).toFixed(2)}%
                    </span>
                </td>
            </tr>
        );
    }
    if (rb?.f1) {
        rows.push(
            <tr key="exp3-rb" className="hover:bg-[#161f30] border-t border-[#1e2d45]">
                <td className="p-4 text-[#607080]">Exp 3</td>
                <td className="p-4 font-bold">Rule-based</td>
                <td className="p-4 text-[#00ff9d] font-mono">{fmt(rb.f1)}</td>
                <td className="p-4">{fmt(rb.precision)}</td>
                <td className="p-4">{fmt(rb.recall)}</td>
                <td className="p-4">
                    <span className="bg-[#ffb7001a] text-[#ffb700] border border-[#ffb7004d] px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase">
                        baseline
                    </span>
                </td>
            </tr>
        );
    }

    return (
        <div className="w-full bg-[#111827] border border-[#1e2d45] rounded-xl overflow-hidden shadow-2xl">
            <div className="p-4 border-b border-[#1e2d45] font-mono text-[0.7rem] text-[#607080] uppercase tracking-widest bg-[#111827]">
                Experiment Summary
            </div>
            <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead className="bg-[#161f30] font-mono text-[0.68rem] text-[#607080] uppercase tracking-wider">
                        <tr>
                            <th className="p-4 font-normal">Experiment</th>
                            <th className="p-4 font-normal">Configuration</th>
                            <th className="p-4 font-normal">F1 Score</th>
                            <th className="p-4 font-normal">Precision</th>
                            <th className="p-4 font-normal">Recall</th>
                            <th className="p-4 font-normal">vs Paper</th>
                        </tr>
                    </thead>
                    <tbody className="text-[0.82rem]">
                        {rows.length > 0 ? (
                            rows
                        ) : (
                            <tr>
                                <td colSpan={6} className="text-center text-[#607080] py-12 px-4">
                                    No results yet — click <strong className="text-cyan-400">▶ RUN PIPELINE</strong> or check back soon.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ResultsTable;