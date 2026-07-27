import { TIER_COLORS, TIER_ORDER } from "../constants";
import type { TierSummary } from "../types";

interface SummaryCardsProps {
	summary: TierSummary;
}

export default function SummaryCards({ summary }: SummaryCardsProps) {
	const total = Object.values(summary).reduce((sum, n) => sum + n, 0);

	return (
		<div className="summary-cards">
			<div className="summary-card total">
				<div className="summary-count">{total}</div>
				<div className="summary-label">Total findings</div>
			</div>
			{TIER_ORDER.map((tier) => (
				<div className="summary-card" key={tier} style={{ borderColor: TIER_COLORS[tier] }}>
					<div className="summary-count" style={{ color: TIER_COLORS[tier] }}>
						{summary[tier] ?? 0}
					</div>
					<div className="summary-label">{tier}</div>
				</div>
			))}
		</div>
	);
}
