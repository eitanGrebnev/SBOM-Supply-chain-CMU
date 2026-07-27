import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Local dev: `npm run dev` here proxies /api to `wrangler dev` (default
// port 8787) in ../worker, so the two run side by side without CORS.
// Production: the Worker serves this app's build output directly as
// static assets (see ../worker/wrangler.jsonc), so no proxy is needed.
export default defineConfig({
	plugins: [react()],
	server: {
		proxy: {
			"/api": "http://localhost:8787",
		},
	},
	build: {
		outDir: "dist",
	},
});
