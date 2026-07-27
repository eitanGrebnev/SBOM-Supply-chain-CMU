import {
	PolarAngleAxis,
	PolarGrid,
	PolarRadiusAxis,
	Radar,
	RadarChart,
	ResponsiveContainer,
} from "recharts";
import { DIMENSION_LABELS, DIMENSION_ORDER, TIER_COLORS } from "../constants";
import type { Finding } from "../types";

interface FindingDetailProps {
	finding: Finding;
	onClose: () => void;
}

/** Per-finding six-dimension radar chart — mirrors visualize.py's finding_radar(). */
export default function FindingDetail({ finding, onClose }: FindingDetailProps) {
	const data = DIMENSION_ORDER.map((dim) => ({
		dimension: DIMENSION_LABELS[dim],
		score: finding.dimension_scores[dim as keyof Finding["dimension_scores"]] ?? 0,
	}));
	const color = finding.tier ? TIER_COLORS[finding.tier] : "#e34a33";

	return (
		<div className="modal-overlay" onClick={onClose}>
			<div className="modal" onClick={(e) => e.stopPropagation()}>
				<button type="button" className="modal-close" onClick={onClose} aria-label="Close">
					×
				</button>
				<h3>
					{finding.component_name}@{finding.component_version}
				</h3>
				<p className="modal-subtitle">
					{finding.cve_id}
					{finding.tier && (
						<span className="tier-badge" style={{ backgroundColor: color }}>
							{finding.tier}
						</span>
					)}
					{finding.vex_status && <span className="vex-badge">VEX: {finding.vex_status}</span>}
				</p>

				<ResponsiveContainer width="100%" height={280}>
					<RadarChart data={data}>
						<PolarGrid />
						<PolarAngleAxis dataKey="dimension" />
						<PolarRadiusAxis angle={90} domain={[0, 10]} />
						<Radar dataKey="score" stroke={color} fill={color} fillOpacity={0.35} />
					</RadarChart>
				</ResponsiveContainer>

				<p className="explanation">{finding.explanation}</p>
			</div>
		</div>
	);
}
