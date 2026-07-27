import type { ScanErrorBody, ScanResult } from "./types";

export interface ScanRequest {
	mode: "file" | "repo";
	sbomFile?: File;
	repo?: string;
	codebaseFile?: File;
	weightsYaml?: string;
}

/** POST a scan request to the Worker's /api/scan endpoint. */
export async function runScan(req: ScanRequest): Promise<ScanResult> {
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

	let body: unknown;
	try {
		body = await res.json();
	} catch {
		throw new Error(`scan request failed (HTTP ${res.status})`);
	}

	if (!res.ok) {
		const err = body as ScanErrorBody;
		throw new Error(err.detail ? `${err.error}: ${err.detail}` : err.error);
	}

	return body as ScanResult;
}
