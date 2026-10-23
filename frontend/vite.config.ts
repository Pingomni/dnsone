import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const src = (path: string) => fileURLToPath(new URL(`./src/${path}`, import.meta.url));

export default defineConfig({
    base: '/',
    plugins: [react()],
    resolve: {
        alias: {
            // RadiusOne's components import Inertia; DNSOne is a plain SPA over the REST API,
            // so the same imports resolve to a small client-side router (src/shim/inertia.tsx).
            '@inertiajs/react': src('shim/inertia.tsx'),
            '@': src(''),
        },
    },
    server: { proxy: { '/api': 'http://127.0.0.1:8100' } },
    build: { outDir: 'dist', assetsInlineLimit: 0, chunkSizeWarningLimit: 4000 },
});
