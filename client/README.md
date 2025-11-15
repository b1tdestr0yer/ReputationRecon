# ReputationRecon Client

This is the TypeScript/React frontend for the ReputationRecon Security Assessment Tool.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the development server (runs on port 5173):
```bash
npm run dev
```

3. Build for production:
```bash
npm run build
```

4. Preview production build:
```bash
npm run preview
```

## Features

- Modern TypeScript/React implementation
- Clean, modular component structure
- Exact visual match with the original HTML/CSS version
- Runs on port 5173 (different from the main server port)
- Fully typed with TypeScript interfaces
- Easy to modify and extend

## Project Structure

```
client/
├── src/
│   ├── components/       # React components
│   │   ├── Header.tsx
│   │   ├── SingleAssessmentForm.tsx
│   │   ├── CompareModeForm.tsx
│   │   ├── LoadingIndicator.tsx
│   │   ├── Results.tsx
│   │   ├── TrustScoreGauge.tsx
│   │   ├── SecurityRecommendation.tsx
│   │   ├── SecurityPostureSection.tsx
│   │   ├── CVEAnalysisSection.tsx
│   │   ├── SpiderChart.tsx
│   │   ├── SourcesSection.tsx
│   │   ├── AlternativesSection.tsx
│   │   ├── ExportButtons.tsx
│   │   └── CacheInfo.tsx
│   ├── services/         # API service layer
│   │   └── api.ts
│   ├── types/            # TypeScript type definitions
│   │   └── index.ts
│   ├── styles/           # CSS styles
│   │   └── App.css
│   ├── App.tsx           # Main app component
│   └── main.tsx          # Entry point
├── index.html
├── package.json
├── tsconfig.json
└── vite.config.ts
```

## API Configuration

The Vite dev server is configured to proxy API requests to `http://localhost:8000` (the main backend server).

Make sure the backend server is running on port 8000 when developing.

