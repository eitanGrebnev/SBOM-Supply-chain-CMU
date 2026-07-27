/**
 * Worker entry point: serves the React app (static assets, see
 * wrangler.jsonc's `assets` config) and a small /api surface backed by a
 * Sandbox container running the existing Python `sbom-scorer` CLI
 * unmodified (see sandboxScan.ts + ../Dockerfile).
 */

import { getSandbox, type Sandbox } from "@cloudflare/sandbox";
export { Sandbox } from "@cloudflare/sandbox";

import { runScan, ScanError } from "./sandboxScan";
import type { ScanErrorBody } from "./types";

interface Env {
	Sandbox: DurableObjectNamespace<Sandbox>;
	ASSETS: Fetcher;
}

function errorResponse(error: string, status: number, detail?: string): Response {
	const body: ScanErrorBody = detail ? { error, detail } : { error };
	return Response.json(body, { status });
}

async function handleScan(request: Request, env: Env): Promise<Response> {
	let form: FormData;
	try {
		form = await request.formData();
	} catch {
		return errorResponse("expected multipart/form-data", 400);
	}

	const mode = form.get("mode");
	if (mode !== "file" && mode !== "repo") {
		return errorResponse("mode must be 'file' or 'repo'", 400);
	}

	const repo = form.get("repo");
	const sbomFile = form.get("sbom");
	const codebaseFile = form.get("codebase");
	const weights = form.get("weights");

	// Each scan runs in its own, disposable container instance — a fresh
	// random ID rather than a stable per-user one, since a sandbox here is
	// single-use scratch space, not durable state to reconnect to.
	const sandbox = getSandbox(env.Sandbox, crypto.randomUUID());

	try {
		const result = await runScan(sandbox, {
			mode,
			repo: typeof repo === "string" ? repo : undefined,
			sbomFile: sbomFile instanceof File ? sbomFile : undefined,
			codebaseFile: codebaseFile instanceof File ? codebaseFile : undefined,
			weightsYaml: typeof weights === "string" ? weights : undefined,
		});
		return Response.json(result);
	} catch (err) {
		if (err instanceof ScanError) {
			return errorResponse(err.message, err.status, err.detail);
		}
		console.error("scan error", err);
		return errorResponse("internal error", 500);
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === "/api/health") {
			return Response.json({ status: "ok" });
		}

		if (url.pathname === "/api/scan") {
			if (request.method !== "POST") {
				return errorResponse("method not allowed", 405);
			}
			return handleScan(request, env);
		}

		if (url.pathname.startsWith("/api/")) {
			return errorResponse("not found", 404);
		}

		// Anything outside /api/* falls through to static assets (the React
		// SPA build) per wrangler.jsonc's run_worker_first: ["/api/*"].
		return env.ASSETS.fetch(request);
	},
} satisfies ExportedHandler<Env>;
