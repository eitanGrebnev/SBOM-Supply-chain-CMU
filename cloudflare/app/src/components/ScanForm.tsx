import { useState } from "react";
import type { FormEvent } from "react";
import type { ScanRequest } from "../api";

interface ScanFormProps {
	onSubmit: (req: ScanRequest) => void;
	loading: boolean;
}

export default function ScanForm({ onSubmit, loading }: ScanFormProps) {
	const [mode, setMode] = useState<"file" | "repo">("file");
	const [repo, setRepo] = useState("");
	const [sbomFile, setSbomFile] = useState<File | null>(null);
	const [codebaseFile, setCodebaseFile] = useState<File | null>(null);
	const [weightsYaml, setWeightsYaml] = useState("");
	const [showAdvanced, setShowAdvanced] = useState(false);

	function handleSubmit(event: FormEvent) {
		event.preventDefault();
		onSubmit({
			mode,
			repo: mode === "repo" ? repo : undefined,
			sbomFile: mode === "file" ? (sbomFile ?? undefined) : undefined,
			codebaseFile: codebaseFile ?? undefined,
			weightsYaml: weightsYaml || undefined,
		});
	}

	return (
		<form className="scan-form" onSubmit={handleSubmit}>
			<div className="mode-toggle" role="radiogroup" aria-label="SBOM source">
				<button
					type="button"
					className={mode === "file" ? "mode-btn active" : "mode-btn"}
					onClick={() => setMode("file")}
					aria-pressed={mode === "file"}
				>
					Upload SBOM file
				</button>
				<button
					type="button"
					className={mode === "repo" ? "mode-btn active" : "mode-btn"}
					onClick={() => setMode("repo")}
					aria-pressed={mode === "repo"}
				>
					GitHub repo
				</button>
			</div>

			{mode === "file" ? (
				<label className="field">
					<span>CycloneDX or SPDX SBOM (JSON)</span>
					<input
						type="file"
						accept=".json,application/json"
						onChange={(e) => setSbomFile(e.target.files?.[0] ?? null)}
						required
					/>
				</label>
			) : (
				<label className="field">
					<span>Repo URL or owner/repo</span>
					<input
						type="text"
						placeholder="https://github.com/owner/repo"
						value={repo}
						onChange={(e) => setRepo(e.target.value)}
						required
					/>
				</label>
			)}

			<button
				type="button"
				className="advanced-toggle"
				onClick={() => setShowAdvanced((v) => !v)}
			>
				{showAdvanced ? "Hide" : "Show"} advanced options
			</button>

			{showAdvanced && (
				<div className="advanced-panel">
					<label className="field">
						<span>Codebase archive (.zip, optional — enables Reachability scoring)</span>
						<input
							type="file"
							accept=".zip"
							onChange={(e) => setCodebaseFile(e.target.files?.[0] ?? null)}
						/>
					</label>
					<label className="field">
						<span>Custom weights.yaml (optional — overrides default dimension weights)</span>
						<textarea
							rows={6}
							placeholder="weights:&#10;  reachability: 0.25&#10;  exploitability: 0.20&#10;  ..."
							value={weightsYaml}
							onChange={(e) => setWeightsYaml(e.target.value)}
						/>
					</label>
				</div>
			)}

			<button type="submit" className="submit-btn" disabled={loading}>
				{loading ? "Scanning…" : "Run scan"}
			</button>
		</form>
	);
}
