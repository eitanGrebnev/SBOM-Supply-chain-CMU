import { useEffect, useRef } from "react";
import type { ScanUpdate } from "../api";

interface Props {
	update: ScanUpdate;
}

/**
 * Live feedback while a scan runs: the current phase, a bar for the phase's
 * item count, and the tail of the scanner's own log.
 *
 * The phases are deliberately not merged into a single 0-100% bar. They are
 * wildly unequal — fetching and parsing an SBOM is seconds, while scoring
 * findings is the overwhelming majority of the wall clock — so one combined
 * bar would sprint to ~20% and then appear stuck for minutes. Showing the
 * named phase alongside a per-phase bar is less impressive and much more
 * honest about what is happening.
 */
export default function ScanProgressPanel({ update }: Props) {
	const logRef = useRef<HTMLPreElement>(null);
	const progress = update.progress;
	const lines = progress?.lines ?? [];

	// Keep the newest line visible without yanking the page around: only the
	// log element itself scrolls.
	useEffect(() => {
		const el = logRef.current;
		if (el) el.scrollTop = el.scrollHeight;
	}, [lines.length]);

	// `total` is null until a phase knows its size, and zero-item phases would
	// divide by zero, so the bar falls back to an indeterminate state.
	const total = progress?.total ?? 0;
	const completed = progress?.completed ?? 0;
	const hasRatio = total > 0;
	const percent = hasRatio ? Math.min(100, Math.round((completed / total) * 100)) : 0;

	// Before the pod is running there is genuinely nothing to report: the
	// scheduler is placing it and the node may still be pulling the image,
	// which can take minutes on a cold node. Saying so beats a stalled bar.
	const waiting = update.status === "pending" || !progress;

	return (
		<section className="scan-progress" aria-live="polite">
			<div className="scan-progress-head">
				<span className="scan-progress-phase">
					{waiting ? "Queued — starting scanner…" : progress.phase}
				</span>
				{!waiting && hasRatio && (
					<span className="scan-progress-count">
						{completed} / {total}
					</span>
				)}
			</div>

			<div
				className="scan-progress-track"
				role="progressbar"
				aria-valuemin={0}
				aria-valuemax={100}
				// Omitted while indeterminate so assistive tech announces it as
				// busy rather than reading out a fabricated 0%.
				aria-valuenow={waiting || !hasRatio ? undefined : percent}
			>
				<div
					className={`scan-progress-bar${waiting || !hasRatio ? " indeterminate" : ""}`}
					style={waiting || !hasRatio ? undefined : { width: `${percent}%` }}
				/>
			</div>

			{lines.length > 0 && (
				<pre className="scan-progress-log" ref={logRef}>
					{lines.join("\n")}
				</pre>
			)}
		</section>
	);
}
