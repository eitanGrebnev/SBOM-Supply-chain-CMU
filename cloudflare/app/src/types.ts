/**
 * Shared types — mirrors sbom_scorer.output.report.write_json's JSON shape
 * (see report.py's _finding_to_dict on the Python side).
 */

export interface DimensionScores {
	reachability?: number;
	exploitability?: number;
	exposure?: number;
	centrality?: number;
	patch_latency?: number;
	maintainer_health?: number;
}

export interface Finding {
	component_name: string;
	component_version: string;
	cve_id: string;
	vex_status: string | null;
	composite_score: number | null;
	tier: string | null;
	dimension_scores: DimensionScores;
	explanation: string;
}

export type TierSummary = Record<string, number>;

export interface ScanResult {
	summary: TierSummary;
	findings: Finding[];
}

export interface ScanErrorBody {
	error: string;
	detail?: string;
}
