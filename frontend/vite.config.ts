// Vite configuration - will be properly configured when dependencies are installed
export default {
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "build",
    sourcemap: true,
  },
};
