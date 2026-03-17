# ThreatStream Frontend

ThreatStream's frontend is a Vite + React + Tailwind CSS application built for an analyst-first workflow.

## Local Setup

1. Create `frontend/.env` from `frontend/.env.example`.
2. Install dependencies:

```bash
cd frontend
npm install
```

3. Start the app:

```bash
npm run dev
```

The app expects the backend API at `VITE_API_BASE_URL`.

## Structure

```text
src/
  app/
  components/
  features/
  hooks/
  lib/
  pages/
  styles/
  types/
```
