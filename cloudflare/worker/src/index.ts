/**
 * Worker entry point: serves the React app (static assets, see
 * wrangler.jsonc's `assets` config) and proxies /api/* to the sbom-scorer
 * API, which runs the Python CLI on self-hosted infrastructure.
 *
 * This Worker performs no compute. It holds no container and no Durable
 * Object, and it never parses a request or response body — bytes are streamed
 * straight through. That is what keeps it inside the Workers **free** plan,
 * whose binding limits are 10 ms CPU and 50 subrequests per invocation:
 * streaming costs almost no CPU, and each call makes exactly one subrequest.
 *
 * Scans are asynchronous by necessity. Cloudflare abandons an origin response
 * after roughly 100 s (error 524) while a real scan runs for minutes, so
 * POST /api/scan returns a job id immediately and the client polls
 * GET /api/scan/:id.
 */

import type { ScanErrorBody } from "./types";

interface Env {
	/** Base URL of the scanner API, e.g. https://sbom-api.example.org */
	SCANNER_ORIGIN: string;
	/** Shared secret; must match the API_KEY the scanner is deployed with. */
	SCANNER_API_KEY: string;
	ASSETS: Fetcher;
}

/** POST /api/scan, or GET /api/scan/<16 hex chars>. Nothing else proxies. */
const SCAN_PATH = /^\/api\/scan(?:\/[0-9a-f]{16})?$/;

function errorResponse(error: string, status: number, detail?: string): Response {
	const body: ScanErrorBody = detail ? { error, detail } : { error };
	return Response.json(body, { status });
}

async function proxyToScanner(request: Request, env: Env, url: URL): Promise<Response> {
	const target = new URL(url.pathname, env.SCANNER_ORIGIN);

	// Headers are rebuilt rather than forwarded wholesale. That drops any
	// client-supplied Cookie, Authorization or spoofed X-API-Key, so the only
	// credential the origin ever sees is the one injected here.
	const headers = new Headers();
	const contentType = request.headers.get("content-type");
	if (contentType) headers.set("content-type", contentType);
	headers.set("x-api-key", env.SCANNER_API_KEY);

	try {
		const upstream = await fetch(target, {
			method: request.method,
			headers,
			// Streamed, not buffered: a 50 MB codebase upload must never be
			// pulled into the isolate's 128 MB of memory.
			body: request.method === "POST" ? request.body : undefined,
			redirect: "manual",
		});

		const outHeaders = new Headers();
		const upstreamType = upstream.headers.get("content-type");
		if (upstreamType) outHeaders.set("content-type", upstreamType);
		// Scan status changes between polls; never let an edge cache serve it.
		outHeaders.set("cache-control", "no-store");

		return new Response(upstream.body, { status: upstream.status, headers: outHeaders });
	} catch {
		// The origin is self-hosted and may simply be down. A clean 503 is more
		// useful to the UI than a surfaced connection error.
		return errorResponse("scanner unavailable", 503);
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === "/api/health") {
			return Response.json({ status: "ok" });
		}

		if (SCAN_PATH.test(url.pathname)) {
			const isSubmit = url.pathname === "/api/scan" && request.method === "POST";
			const isPoll = url.pathname !== "/api/scan" && request.method === "GET";
			if (!isSubmit && !isPoll) {
				return errorResponse("method not allowed", 405);
			}
			return proxyToScanner(request, env, url);
		}

		if (url.pathname.startsWith("/api/")) {
			return errorResponse("not found", 404);
		}

		// Anything outside /api/* falls through to static assets (the React
		// SPA build) per wrangler.jsonc's run_worker_first: ["/api/*"].
		// Static-asset requests are free and unmetered.
		return env.ASSETS.fetch(request);
	},
} satisfies ExportedHandler<Env>;
