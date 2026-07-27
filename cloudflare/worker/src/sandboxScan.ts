/**
 * Runs a scan inside a Sandbox container by invoking the real
 * `sbom-scorer` CLI (baked into the container image — see ../Dockerfile),
 * then reads back its JSON report. No scoring logic is duplicated here;
 * this module only orchestrates file I/O + one `exec()` call.
 */

import type { Sandbox } from "@cloudflare/sandbox";
import type { ScanResult } from "./types";

export const MAX_SBOM_BYTES = 15 * 1024 * 1024; // 15 MB
export const MAX_CODEBASE_BYTES = 50 * 1024 * 1024; // 50 MB

const REPO_SEGMENT = "[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?";
const REPO_RE = new RegExp(`^${REPO_SEGMENT}/${REPO_SEGMENT}$`);
const REPO_URL_RE = new RegExp(
	`^https://github\\.com/(${REPO_SEGMENT})/(${REPO_SEGMENT})(?:\\.git)?/?$`,
	"i",
);

/** Normalize a GitHub URL or "owner/repo" string, rejecting anything else. */
export function normalizeRepo(input: string): string {
	const trimmed = input.trim();
	const urlMatch = trimmed.match(REPO_URL_RE);
	if (urlMatch) {
		return `${urlMatch[1]}/${urlMatch[2]}`;
	}
	if (REPO_RE.test(trimmed)) {
		return trimmed;
	}
	throw new Error("invalid repo — expected 'owner/repo' or a github.com URL");
}

/** Base64-encode an ArrayBuffer without blowing the call stack on large files. */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	const chunkSize = 0x8000;
	for (let i = 0; i < bytes.length; i += chunkSize) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
	}
	return btoa(binary);
}

export interface ScanRequestInput {
	mode: "file" | "repo";
	repo?: string;
	sbomFile?: File;
	codebaseFile?: File;
	weightsYaml?: string;
}

export class ScanError extends Error {
	constructor(
		message: string,
		public readonly status: number,
		public readonly detail?: string,
	) {
		super(message);
	}
}

/**
 * Run one scan to completion in a fresh, dedicated sandbox instance.
 *
 * The sandbox is destroyed in a `finally` block regardless of outcome —
 * each scan gets its own container, so nothing is reused or leaked across
 * requests (see index.ts, which mints a new sandbox ID per request).
 */
export async function runScan(sandbox: Sandbox, input: ScanRequestInput): Promise<ScanResult> {
	try {
		await sandbox.mkdir("/workspace/input", { recursive: true });
		await sandbox.mkdir("/workspace/out", { recursive: true });

		let target: string;
		if (input.mode === "repo") {
			if (!input.repo?.trim()) {
				throw new ScanError("repo is required for mode=repo", 400);
			}
			target = `--repo ${normalizeRepo(input.repo)}`;
		} else {
			if (!input.sbomFile) {
				throw new ScanError("sbom file is required for mode=file", 400);
			}
			if (input.sbomFile.size > MAX_SBOM_BYTES) {
				throw new ScanError("sbom file too large (max 15 MB)", 413);
			}
			const sbomText = await input.sbomFile.text();
			await sandbox.writeFile("/workspace/input/sbom.json", sbomText);
			target = "/workspace/input/sbom.json";
		}

		let weightsFlag = "";
		if (input.weightsYaml?.trim()) {
			await sandbox.writeFile("/workspace/input/weights.yaml", input.weightsYaml);
			weightsFlag = " --weights /workspace/input/weights.yaml";
		}

		let codebaseFlag = "";
		if (input.codebaseFile) {
			if (input.codebaseFile.size > MAX_CODEBASE_BYTES) {
				throw new ScanError("codebase archive too large (max 50 MB)", 413);
			}
			const base64 = arrayBufferToBase64(await input.codebaseFile.arrayBuffer());
			await sandbox.writeFile("/workspace/input/codebase.zip", base64, {
				encoding: "base64",
			});
			await sandbox.mkdir("/workspace/input/codebase", { recursive: true });
			// Extract with Python's stdlib zipfile module — avoids depending on
			// an `unzip` binary being present in the sandbox image.
			const unzip = await sandbox.exec(
				"python3 -m zipfile -e /workspace/input/codebase.zip /workspace/input/codebase/",
				{ timeout: 30_000 },
			);
			if (!unzip.success) {
				throw new ScanError("could not extract codebase archive", 400, unzip.stderr);
			}
			codebaseFlag = " --codebase /workspace/input/codebase";
		}

		const command =
			`sbom-scorer ${target} --format json --output-dir /workspace/out` +
			`${weightsFlag}${codebaseFlag}`;

		// CVE discovery + per-finding scoring make one network call per
		// component/finding (see cli.py) — generous timeout for large SBOMs.
		const result = await sandbox.exec(command, { timeout: 240_000 });
		if (!result.success) {
			throw new ScanError("scan failed", 502, result.stderr || result.stdout);
		}

		const findingsFile = await sandbox.readFile("/workspace/out/findings.json");
		return JSON.parse(findingsFile.content) as ScanResult;
	} finally {
		await sandbox.destroy().catch((err: unknown) => {
			console.error("sandbox cleanup failed", err);
		});
	}
}
