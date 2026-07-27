// Canonical tier order/colors and dimension labels — mirror
// sbom_scorer.output.report / visualize's _TIER_ORDER, _TIER_COLORS, and
// _DIMENSION_LABELS so the UI matches the CLI's own report exactly.

export const TIER_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;
export type Tier = (typeof TIER_ORDER)[number];

export const TIER_COLORS: Record<string, string> = {
	Critical: "#b30000",
	High: "#e34a33",
	Medium: "#fdae61",
	Low: "#a6d96a",
	Informational: "#1a9850",
};

export const DIMENSION_LABELS: Record<string, string> = {
	reachability: "Reachability",
	exploitability: "Exploitability",
	exposure: "Exposure",
	centrality: "Centrality",
	patch_latency: "Patch Latency",
	maintainer_health: "Maintainer Health",
};

export const DIMENSION_ORDER = Object.keys(DIMENSION_LABELS);
