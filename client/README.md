# Secure Your App Health Client

This is the TypeScript/React frontend for the Secure Your App Health Security Assessment Tool. A modern, professional security assessment interface with dark mode, cache browsing, and real-time search capabilities.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the development server (runs on port 5173):
```bash
npm run dev
```

The dev server will be accessible at:
- **Local**: `http://localhost:5173`
- **Network**: `http://<your-ip>:5173` (accessible from other devices on the same network)

3. Build for production:
```bash
npm run build
```

4. Preview production build:
```bash
npm run preview
```

## Features

- **Modern TypeScript/React Implementation**
  - Fully typed with TypeScript interfaces
  - Clean, modular component structure
  - Easy to modify and extend

- **Professional UI/UX**
  - Exact visual match with the original HTML/CSS version
  - Responsive design for all screen sizes
  - Smooth animations and transitions

- **Dark Mode / Light Mode**
  - Professional dark theme (cool but professional)
  - Light theme matching the original design
  - Theme preference persisted in localStorage
  - Seamless theme switching

- **Page Routing**
  - Home page: Single and Compare mode assessments
  - Cache Browser page: Search and filter cached assessments
  - Navigation via top bar and back buttons

- **Cache Browser**
  - Real-time search with 300ms debounce
  - Filter by product name, vendor name, or hash
  - Trust score filtering (All / Good ≥70 / Bad <70)
  - Visual risk indicators with icons
  - Professional cards showing assessment details
  - Click cards to view full assessment details

- **Assessment Features**
  - Single application assessment
  - Compare multiple applications side-by-side
  - Trust score visualization with gauge chart
  - CVE analysis with pagination
  - Security posture breakdown
  - Spider chart for multi-dimensional scoring
  - Export reports (Markdown/PDF)

- **Network Configuration**
  - Runs on port 5173 (different from backend port 8000)
  - Accessible from network IP for team collaboration
  - API requests proxied to backend server

## Project Structure

```
client/
├── src/
│   ├── components/          # React components
│   │   ├── Header.tsx                # Page header
│   │   ├── TopBar.tsx                # Navigation bar with theme toggle
│   │   ├── CacheBrowser.tsx          # Cache browser page component
│   │   ├── CacheBrowser.css          # Cache browser styles
│   │   ├── SingleAssessmentForm.tsx  # Single assessment form
│   │   ├── CompareModeForm.tsx       # Compare mode form
│   │   ├── LoadingIndicator.tsx      # Loading animation
│   │   ├── Results.tsx               # Assessment results display
│   │   ├── TrustScoreGauge.tsx       # Trust score gauge chart
│   │   ├── SecurityRecommendation.tsx # Security recommendation card
│   │   ├── SecurityPostureSection.tsx # Security posture details
│   │   ├── CVEAnalysisSection.tsx    # CVE analysis with pagination
│   │   ├── SpiderChart.tsx           # Multi-dimensional spider chart
│   │   ├── SourcesSection.tsx        # Information sources
│   │   ├── AlternativesSection.tsx   # Safer alternatives
│   │   ├── ExportButtons.tsx         # Export functionality
│   │   └── CacheInfo.tsx             # Cache status and refresh
│   ├── pages/               # Page components
│   │   └── HomePage.tsx              # Home page with assessments
│   ├── contexts/            # React contexts
│   │   └── ThemeContext.tsx          # Theme management (light/dark)
│   ├── services/            # API service layer
│   │   └── api.ts                    # API client functions
│   ├── types/               # TypeScript type definitions
│   │   └── index.ts                  # Type interfaces
│   ├── styles/              # CSS styles
│   │   └── App.css                   # Main application styles
│   ├── App.tsx              # Main app component with routing
│   └── main.tsx             # Entry point
├── index.html
├── package.json
├── tsconfig.json
├── tsconfig.node.json
└── vite.config.ts           # Vite configuration (port, proxy, host)
```

## API Configuration

The Vite dev server is configured to proxy API requests to `http://localhost:8000` (the main backend server).

**Important**: Make sure the backend server is running on port 8000 when developing.

### Network Access

The dev server is configured with `host: true` in `vite.config.ts`, which makes it accessible from your local network. This allows team members on the same Wi-Fi to access the application at `http://<your-ip>:5173`.

**Windows Firewall**: You may need to allow inbound connections on port 5173 through Windows Firewall for network access to work.

## Routing

The application uses React Router for navigation:

- **`/`** - Home page with assessment forms and results
- **`/cache`** - Cache browser page for searching cached assessments

Navigation:
- Click "Browse Cache" in the top bar to go to the cache browser
- Click "Back to Home" or the logo in the cache browser to return home
- Click on result cards in the cache browser to view full assessment details

## Theme System

The application supports light and dark themes:

- **Light Mode**: Matches the original HTML/CSS design
- **Dark Mode**: Professional dark theme with optimized colors
- Theme preference is saved in `localStorage` and persists across sessions
- Toggle theme using the button in the top bar

### Theme Colors

The theme system uses CSS variables for easy customization:
- `--bg-primary`: Background gradient
- `--container-bg`: Container background
- `--text-primary`: Primary text color
- `--text-secondary`: Secondary text color
- `--card-bg`: Card background
- And more...

## Cache Browser

The cache browser allows you to search through cached assessments:

### Search Filters
- **Product Name**: Partial match, case-insensitive
- **Vendor Name**: Partial match, case-insensitive  
- **Hash**: Partial match on MD5, SHA1, or SHA256 hashes
- **Trust Score**: Filter by score range
  - **All**: Show all assessments
  - **Good (≥70)**: Show assessments with trust score ≥ 70
  - **Bad (<70)**: Show assessments with trust score < 70

### Search Features
- Real-time search with 300ms debounce
- Results update automatically as you type
- Maximum 100 results displayed
- Visual risk indicators (Low/Medium/High/Critical)
- Icons showing assessment status
- Click any result card to view full details

### Result Cards Display
Each result card shows:
- Entity name and vendor
- Trust score (0-100)
- Risk level badge
- Category
- CVE counts (total and critical)
- CISA KEV count (if any)
- Hash (if provided)
- Last updated timestamp
- Cached status indicator

## Dependencies

- **react** & **react-dom**: React 18
- **react-router-dom**: Client-side routing
- **chart.js** & **react-chartjs-2**: Chart visualizations
- **typescript**: Type safety
- **vite**: Build tool and dev server
- **@vitejs/plugin-react**: React support for Vite

## Development

### Adding New Components

1. Create component file in `src/components/`
2. Define TypeScript interfaces in `src/types/index.ts`
3. Import and use in `App.tsx` or page components

### Styling

- Main styles: `src/styles/App.css`
- Component-specific styles: Co-located with components (e.g., `CacheBrowser.css`)
- Use CSS variables for theme-aware colors
- Responsive design with media queries

### API Integration

- API functions in `src/services/api.ts`
- All API calls go through the proxy to `http://localhost:8000/api`
- Types defined in `src/types/index.ts`
- Error handling with try-catch blocks

## Production Build

To build for production:

```bash
npm run build
```

The built files will be in the `dist/` directory. You can serve these files with any static file server, or configure the backend server to serve them.

For preview:

```bash
npm run preview
```

This serves the production build locally for testing.

