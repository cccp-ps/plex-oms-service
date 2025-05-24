import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'path';

// https://vitejs.dev/config/
export default defineConfig(({ command, mode }) => {
  // Load environment variables based on the current mode
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    plugins: [
      react(),
      tailwindcss(),
    ],
    
    // Path resolution for clean imports
    resolve: {
      alias: {
        '@': resolve(__dirname, './src'),
        '@/components': resolve(__dirname, './src/components'),
        '@/hooks': resolve(__dirname, './src/hooks'),
        '@/services': resolve(__dirname, './src/services'),
        '@/types': resolve(__dirname, './src/types'),
        '@/utils': resolve(__dirname, './src/utils'),
        '@/contexts': resolve(__dirname, './src/contexts'),
        '@/assets': resolve(__dirname, './src/assets'),
      },
    },

    // Development server configuration
    server: {
      port: 5173,
      host: true, // Allow external connections
      open: true, // Automatically open browser
      cors: true,
      hmr: {
        port: 5173,
      },
      // Proxy API requests to backend during development
      proxy: {
        '/api': {
          target: env.VITE_API_BASE_URL || 'http://localhost:8000',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/api/, '/api'),
        },
        '/auth': {
          target: env.VITE_API_BASE_URL || 'http://localhost:8000',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/auth/, '/auth'),
        },
      },
    },

    // Preview server configuration for production builds
    preview: {
      port: 4173,
      host: true,
      cors: true,
    },

    // Build configuration for optimization
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      sourcemap: true,
      minify: 'esbuild',
      target: 'es2022',
      
      // Code splitting configuration
      rollupOptions: {
        output: {
          manualChunks: {
            // Vendor chunk for all node_modules
            vendor: ['react', 'react-dom'],
            // UI libraries chunk
            ui: ['@tanstack/react-query', 'zustand'],
            // Utilities chunk
            utils: ['zod', 'clsx', 'tailwind-merge'],
          },
          // Optimize chunk naming for better caching
          chunkFileNames: (chunkInfo) => {
            const facadeModuleId = chunkInfo.facadeModuleId 
              ? chunkInfo.facadeModuleId.split('/').pop()?.replace('.tsx', '').replace('.ts', '')
              : 'chunk';
            return `js/${facadeModuleId}-[hash].js`;
          },
          entryFileNames: 'js/[name]-[hash].js',
          assetFileNames: (assetInfo) => {
            if (assetInfo.name?.endsWith('.css')) {
              return 'css/[name]-[hash][extname]';
            }
            if (assetInfo.name?.match(/\.(png|jpe?g|svg|gif|tiff|bmp|ico)$/i)) {
              return 'images/[name]-[hash][extname]';
            }
            if (assetInfo.name?.match(/\.(woff2?|eot|ttf|otf)$/i)) {
              return 'fonts/[name]-[hash][extname]';
            }
            return 'assets/[name]-[hash][extname]';
          },
        },
      },
      
      // Performance optimizations
      chunkSizeWarningLimit: 1000, // 1MB warning limit
      assetsInlineLimit: 4096, // 4KB inline limit for assets
    },

    // Environment variable configuration
    envPrefix: 'VITE_',
    define: {
      // Global constants available in the app
      __APP_VERSION__: JSON.stringify(process.env.npm_package_version || 'unknown'),
      __BUILD_TIME__: JSON.stringify(new Date().toISOString()),
      __DEV__: JSON.stringify(mode === 'development'),
    },

    // CSS configuration
    css: {
      devSourcemap: true,
      preprocessorOptions: {
        scss: {
          additionalData: `@import "@/styles/variables.scss";`,
        },
      },
    },

    // Testing configuration with Vitest
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: ['./src/__tests__/setup.ts'],
      css: true,
      coverage: {
        provider: 'v8',
        reporter: ['text', 'json', 'html'],
        exclude: [
          'node_modules/',
          'src/__tests__/',
          '**/*.d.ts',
          '**/*.config.*',
          '**/coverage/**',
          '**/dist/**',
        ],
        thresholds: {
          global: {
            branches: 80,
            functions: 80,
            lines: 80,
            statements: 80,
          },
        },
      },
    },

    // Optimization for production builds
    optimizeDeps: {
      include: [
        'react',
        'react-dom',
        'react-router-dom',
        '@tanstack/react-query',
        'zustand',
        'zod',
        'clsx',
        'tailwind-merge',
      ],
      exclude: ['@tailwindcss/vite'],
    },

    // Error overlay configuration
    clearScreen: false,
    logLevel: mode === 'development' ? 'info' : 'warn',
  };
}); 