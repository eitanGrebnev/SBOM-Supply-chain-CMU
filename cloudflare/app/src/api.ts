import type { ScanErrorBody, ScanResult } from "./types";

export interface ScanRequest {
	mode: "file" | "repo";
	sbomFile?: File;
	repo?: string;
	codebaseFile?: File;
	weightsYaml?: string;
}

/** Lifecycle of a scan job, as reported by the scanner API. */
export type ScanStatus = "pending" | "running" | "succeeded" | "failed";

/**
 * Live progress written by the scanner CLI onto the shared scans volume.
 *
 * `total` is null while a phase's size is still unknown, so a bar must not
 * assume it can compute a percentage.
 */
export interface ScanProgress {
	phase: string;
	completed: number;
	total: number | null;
	lines: string[];
}

export interface ScanUpdate {
	status: ScanStatus;
	/** Absent until the Job pod starts the CLI — an image pull can take minutes. */
	progress?: ScanProgress | null;
}

interface ScanSubmitBody {
	id: string;
	status: ScanStatus;
}

interface ScanStatusBody {
	id: string;
	status: ScanStatus;
	result?: ScanResult;
	detail?: string;
	progress?: ScanProgress | null;
}

/**
 * A scan takes minutes, but Cloudflare abandons an origin response after
 * roughly 100 s (error 524), so it cannot be a single request. Submitting
 * returns a job id immediately and we poll until it resolves.
 */
const POLL_INITIAL_MS = 2_000;
/**
 * While the job is still `pending` there is nothing to show but a spinner —
 * the pod is being scheduled and the image pulled — so polling backs off.
 * Once it is `running` there is a progress bar on screen, and a bar that
 * only moves every 10 s reads as frozen, so the interval is pinned short.
 * Even at this rate a 20-minute scan is a few hundred requests, which is
 * negligible against the Worker plan's daily quota.
 */
const POLL_MAX_MS = 10_000;
const POLL_RUNNING_MS = 2_500;
const POLL_TIMEOUT_MS = 20 * 60 * 1_000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function parseJson(res: Response): Promise<unknown> {
	try {
		return await res.json();
	} catch {
		throw new Error(`scan request failed (HTTP ${res.status})`);
	}
}

function throwApiError(body: unknown, status: number): never {
	const err = body as ScanErrorBody & { detail?: unknown };
	if (err?.error) {
		throw new Error(err.detail ? `${err.error}: ${err.detail}` : err.error);
	}
	// FastAPI reports HTTPException as a bare {"detail": ...}, so surface that
	// rather than discarding the only useful part of the response.
	if (typeof err?.detail === "string") {
		throw new Error(err.detail);
	}
	throw new Error(`scan request failed (HTTP ${status})`);
}

/** Submit a scan and resolve with its id. */
async function submitScan(req: ScanRequest): Promise<string> {
	const form = new FormData();
	form.set("mode", req.mode);

	if (req.mode === "repo") {
		if (!req.repo?.trim()) {
			throw new Error("repo is required");
		}
		form.set("repo", req.repo.trim());
	} else {
		if (!req.sbomFile) {
			throw new Error("an SBOM file is required");
		}
		form.set("sbom", req.sbomFile);
	}

	if (req.codebaseFile) {
		form.set("codebase", req.codebaseFile);
	}
	if (req.weightsYaml?.trim()) {
		form.set("weights", req.weightsYaml);
	}

	const res = await fetch("/api/scan", { method: "POST", body: form });
	const body = await parseJson(res);
	if (!res.ok) throwApiError(body, res.status);

	return (body as ScanSubmitBody).id;
}

/**
 * Submit a scan and poll until it finishes.
 *
 * `onUpdate` fires on each poll so the UI can distinguish "queued behind
 * another scan" from "actually running", which matters because a cold start
 * has to pull the scanner image before any work begins, and so it can render
 * the phase/counter the scanner reports while it works.
 */
export async function runScan(
	req: ScanRequest,
	onUpdate?: (update: ScanUpdate) => void,
): Promise<ScanResult> {
	const id = await submitScan(req);
	onUpdate?.({ status: "pending" });

	const deadline = Date.now() + POLL_TIMEOUT_MS;
	let delay = POLL_INITIAL_MS;

	while (Date.now() < deadline) {
		await sleep(delay);
		// Back off gradually while queued; see POLL_RUNNING_MS below for why
		// this is reset once the scan is actually running.
		delay = Math.min(delay * 1.5, POLL_MAX_MS);

		const res = await fetch(`/api/scan/${id}`);

		// The job may not be visible for a moment right after creation.
		if (res.status === 404) continue;

		const body = await parseJson(res);
		if (!res.ok) throwApiError(body, res.status);

		const status = body as ScanStatusBody;
		onUpdate?.({ status: status.status, progress: status.progress });

		if (status.status === "running") {
			delay = POLL_RUNNING_MS;
		}
		if (status.status === "succeeded") {
			if (!status.result) throw new Error("scan finished but returned no result");
			return status.result;
		}
		if (status.status === "failed") {
			throw new Error(status.detail ?? "scan failed");
		}
	}

	throw new Error("scan timed out");
}
