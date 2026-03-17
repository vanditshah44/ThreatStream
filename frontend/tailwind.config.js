export default {
    content: ["./index.html", "./src/**/*.{ts,tsx}"],
    theme: {
        extend: {
            colors: {
                shell: "#0a0f17",
                panel: "#111926",
                panelAlt: "#182132",
                line: "#243249",
                accent: "#6fd7ff",
                accentMuted: "#1f3b52",
                success: "#4ade80",
                warning: "#fbbf24",
                danger: "#fb7185",
                text: "#e5edf6",
                muted: "#8da0b7",
            },
            boxShadow: {
                panel: "0 20px 80px rgba(0, 0, 0, 0.28)",
            },
            fontFamily: {
                sans: ["IBM Plex Sans", "Segoe UI", "sans-serif"],
                mono: ["IBM Plex Mono", "monospace"],
            },
            gridTemplateColumns: {
                dashboard: "minmax(0, 1.45fr) minmax(320px, 0.95fr)",
            },
        },
    },
    plugins: [],
};
