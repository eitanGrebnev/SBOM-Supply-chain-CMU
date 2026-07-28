import { useCallback, useState } from "react";
import { runScan } from "./api";
import type { ScanRequest, ScanUpdate } from "./api";
import ScanForm from "./components/ScanForm";
import ScanProgressPanel from "./components/ScanProgressPanel";
import SummaryCards from "./components/SummaryCards";
import TierBarChart from "./components/TierBarChart";
import FindingsTable from "./components/FindingsTable";
import FindingDetail from "./components/FindingDetail";
import type { Finding, ScanResult } from "./types";

function downloadJson(result: ScanResult) {
	const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = "sbom-scorer-findings.json";
	a.click();
	URL.revokeObjectURL(url);
}

function downloadCsv(result: ScanResult) {
	const dims = ["reachability", "exploitability", "exposure", "centrality", "patch_latency", "maintainer_health"];
	const header = ["component_name", "component_version", "cve_id", "vex_status", "composite_score", "tier", ...dims];
	const rows = result.findings.map((f) => [
		f.component_name,
		f.component_version,
		f.cve_id,
		f.vex_status ?? "",
		f.composite_score ?? "",
		f.tier ?? "",
		...dims.map((d) => f.dimension_scores[d as keyof Finding["dimension_scores"]] ?? ""),
	]);
	const csv = [header, ...rows]
		.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
		.join("\n");
	const blob = new Blob([csv], { type: "text/csv" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = "sbom-scorer-findings.csv";
	a.click();
	URL.revokeObjectURL(url);
}

export default function App() {
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<ScanResult | null>(null);
	const [selected, setSelected] = useState<Finding | null>(null);
	const [update, setUpdate] = useState<ScanUpdate | null>(null);

	const handleSubmit = useCallback(async (req: ScanRequest) => {
		setLoading(true);
		setError(null);
		// Clear the previous run's progress and results up front, so a second
		// scan never shows the first one's log tail next to a live bar.
		setUpdate({ status: "pending" });
		setResult(null);
		try {
			const scanResult = await runScan(req, setUpdate);
			setResult(scanResult);
		} catch (err) {
			setError(err instanceof Error ? err.message : "scan failed");
		} finally {
			setLoading(false);
			setUpdate(null);
		}
	}, []);

	return (
		<div className="app">
			<header className="app-header">
				<h1>SBOM Vulnerability Scorer</h1>
				<p>
					Six-dimension weighted composite risk scoring for software supply chains —
					reachability, exploitability, exposure, blast radius, patch latency, and maintainer
					health, instead of relying on CVSS alone.
				</p>
			</header>

			<ScanForm onSubmit={handleSubmit} loading={loading} />

			{loading && update && <ScanProgressPanel update={update} />}

			{error && <div className="error-banner">{error}</div>}

			{result && (
				<section className="results">
					<div className="results-toolbar">
						<h2>Results</h2>
						<div className="download-buttons">
							<button type="button" onClick={() => downloadJson(result)}>
								Download JSON
							</button>
							<button type="button" onClick={() => downloadCsv(result)}>
								Download CSV
							</button>
						</div>
					</div>

					<SummaryCards summary={result.summary} />
					<TierBarChart summary={result.summary} />
					<FindingsTable findings={result.findings} onSelect={setSelected} />
				</section>
			)}

			{selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
		</div>
	);
}
