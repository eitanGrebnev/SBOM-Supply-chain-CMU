import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { TIER_COLORS, TIER_ORDER } from "../constants";
import type { TierSummary } from "../types";

interface TierBarChartProps {
	summary: TierSummary;
}

/** Findings-by-tier bar chart — mirrors visualize.py's tier_distribution_bar(). */
export default function TierBarChart({ summary }: TierBarChartProps) {
	const data = TIER_ORDER.map((tier) => ({ tier, count: summary[tier] ?? 0 }));

	return (
		<div className="chart-card">
			<h3>Findings by Tier</h3>
			<ResponsiveContainer width="100%" height={260}>
				<BarChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
					<CartesianGrid strokeDasharray="3 3" vertical={false} />
					<XAxis dataKey="tier" />
					<YAxis allowDecimals={false} />
					<Tooltip />
					<Bar dataKey="count" radius={[4, 4, 0, 0]}>
						{data.map((entry) => (
							<Cell key={entry.tier} fill={TIER_COLORS[entry.tier]} />
						))}
					</Bar>
				</BarChart>
			</ResponsiveContainer>
		</div>
	);
}
