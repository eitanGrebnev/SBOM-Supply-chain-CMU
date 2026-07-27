import { useMemo, useState } from "react";
import { TIER_COLORS, TIER_ORDER } from "../constants";
import type { Finding } from "../types";

interface FindingsTableProps {
	findings: Finding[];
	onSelect: (finding: Finding) => void;
}

export default function FindingsTable({ findings, onSelect }: FindingsTableProps) {
	const [tierFilter, setTierFilter] = useState<string>("All");
	const [search, setSearch] = useState("");

	const filtered = useMemo(() => {
		const term = search.trim().toLowerCase();
		return findings
			.filter((f) => tierFilter === "All" || f.tier === tierFilter)
			.filter(
				(f) =>
					!term ||
					f.component_name.toLowerCase().includes(term) ||
					f.cve_id.toLowerCase().includes(term),
			)
			.sort((a, b) => (b.composite_score ?? 0) - (a.composite_score ?? 0));
	}, [findings, tierFilter, search]);

	return (
		<div className="findings-table-card">
			<div className="table-controls">
				<input
					type="search"
					placeholder="Search component or CVE…"
					value={search}
					onChange={(e) => setSearch(e.target.value)}
				/>
				<select value={tierFilter} onChange={(e) => setTierFilter(e.target.value)}>
					<option value="All">All tiers</option>
					{TIER_ORDER.map((tier) => (
						<option key={tier} value={tier}>
							{tier}
						</option>
					))}
				</select>
				<span className="result-count">
					{filtered.length} of {findings.length} finding(s)
				</span>
			</div>

			<div className="table-scroll">
				<table>
					<thead>
						<tr>
							<th>Component</th>
							<th>CVE</th>
							<th>Score</th>
							<th>Tier</th>
							<th>VEX</th>
							<th />
						</tr>
					</thead>
					<tbody>
						{filtered.map((f) => (
							<tr key={`${f.component_name}@${f.component_version}:${f.cve_id}`}>
								<td>
									{f.component_name}@{f.component_version}
								</td>
								<td>{f.cve_id}</td>
								<td>{f.composite_score?.toFixed(1) ?? "—"}</td>
								<td>
									{f.tier && (
										<span
											className="tier-badge"
											style={{ backgroundColor: TIER_COLORS[f.tier] }}
										>
											{f.tier}
										</span>
									)}
								</td>
								<td>{f.vex_status ? <span className="vex-badge">{f.vex_status}</span> : "—"}</td>
								<td>
									<button type="button" className="detail-btn" onClick={() => onSelect(f)}>
										Details
									</button>
								</td>
							</tr>
						))}
						{filtered.length === 0 && (
							<tr>
								<td colSpan={6} className="empty-row">
									No findings match the current filter.
								</td>
							</tr>
						)}
					</tbody>
				</table>
			</div>
		</div>
	);
}
