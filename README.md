# Secure Your App Health - AI-Powered Security Assessment Tool

**AI-Powered Security Assessment Platform for Modern CISOs**

Secure Your App Health is an intelligent security assessment tool that generates comprehensive, CISO-ready trust briefs for applications in minutes. Built for Junction Hackathon 2025, this platform helps security teams make informed decisions by providing accurate, transparent, and source-grounded security assessments.

**👥 Team**: We are a team of 3 students from EPFL (École Polytechnique Fédérale de Lausanne).

## 🎯 The Problem We Solve

Security teams and CISOs face an overwhelming challenge: evaluating the security posture of new applications quickly and accurately. Traditional methods are time-consuming, require extensive manual research, and often lack transparency in their scoring methodologies. Secure Your App Health solves this by combining AI-powered synthesis with real-time threat intelligence to deliver actionable security assessments in minutes.

## ✨ Key Features

### 🔍 **Intelligent Entity Resolution**
Automatically resolves product and vendor information from minimal input—just provide a product name, vendor, URL, or even a file hash, and we'll do the rest.

### 📊 **Transparent Trust Scoring**
Every assessment includes a clear 0-100 trust score with detailed rationale, confidence levels, and a complete breakdown of contributing factors. No black boxes—you can see exactly why an application received its score.

### 🛡️ **Comprehensive Security Analysis**
- **CVE Analysis**: Real-time vulnerability tracking with CISA KEV integration
- **VirusTotal Integration**: Deep file hash analysis with multi-engine detection
- **Security Posture**: Vendor reputation, data handling, compliance, and incident tracking
- **Risk Assessment**: AI-powered analysis of security signals and threat patterns

### 🤖 **Dual AI Modes**
- **Classic Mode**: Fast, efficient assessments using standard AI models
- **PRO Mode**: Enhanced analysis using Gemini 2.5 Pro for deeper insights and higher quality synthesis

### 📚 **Source-Grounded Claims**
Every security claim is backed by proper citations. We distinguish between vendor-stated information and independent security research, giving you the full picture.

### 💾 **Smart Caching System**
All assessments are cached locally with metadata, including AI mode used. Classic and PRO mode assessments are stored separately, ensuring accurate results. Cache browser lets you search, filter, and revisit previous assessments.

### 📄 **Professional Export Options**
Export assessment reports in multiple formats:
- **Markdown**: Clean, structured reports for documentation
- **PDF**: Print-ready HTML that opens in your browser for easy PDF generation

### 🎨 **Modern Web Interface**
Beautiful, intuitive UI with:
- Dark mode by default for comfortable viewing
- Interactive trust score visualizations
- Collapsible sections for detailed information
- Real-time progress indicators
- Visual CVE and security factor breakdowns

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (3.9+ recommended)
- **Node.js 16+** (for the frontend)
- **VirusTotal API Key** (optional but recommended for hash analysis)
- **Google Gemini API Key** (optional, enables PRO mode features)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd ReputationRecon
   ```

2. **Set up the backend:**
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Set up the frontend:**
   ```bash
   cd client
   npm install
   ```

4. **Configure API keys (optional):**
   
   Create a `.env` file in the project root:
   ```bash
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   GEMINI_API_KEY=your_gemini_api_key_here
   ```
   
   Or set them as environment variables:
   ```bash
   # Windows PowerShell
   $env:VIRUSTOTAL_API_KEY="your_key_here"
   $env:GEMINI_API_KEY="your_key_here"
   
   # macOS/Linux
   export VIRUSTOTAL_API_KEY="your_key_here"
   export GEMINI_API_KEY="your_key_here"
   ```

5. **Start the backend server:**
   ```bash
   # From project root
   python main.py
   ```
   
   Or use the startup script:
   ```bash
   # Linux/Mac
   chmod +x run_server.sh
   ./run_server.sh
   ```

6. **Start the frontend development server:**
   ```bash
   cd client
   npm run dev
   ```

The application will be available at:
- **Frontend**: http://localhost:5173 (or the port Vite assigns)
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 📖 Usage

### Web Interface

1. Navigate to the web interface
2. Enter a product name and vendor (or just a URL)
3. Optionally provide a file hash for deeper analysis
4. Toggle PRO Mode for enhanced AI analysis (slower but higher quality)
5. Click "Assess Application" to generate a comprehensive security report

The interface provides:
- Visual trust score gauge with color-coded risk levels
- Interactive security posture sections
- CVE analysis with severity breakdowns
- VirusTotal analysis results (if hash provided)
- Safer alternative suggestions
- Complete source citations
- Export options for reports

### API Usage

#### Basic Assessment

```bash
curl -X POST http://localhost:8000/api/assess \
  -H "Content-Type: application/json" \
  -d '{
    "product_name": "Slack",
    "vendor_name": "Salesforce",
    "pro_mode": false
  }'
```

#### Assessment with Hash

```bash
curl -X POST http://localhost:8000/api/assess \
  -H "Content-Type: application/json" \
  -d '{
    "product_name": "MyApp",
    "vendor_name": "Vendor Inc",
    "hash": "abc123def456...",
    "pro_mode": true
  }'
```

#### Cache Search

```bash
curl "http://localhost:8000/api/cache/search?product_name=Slack&limit=10"
```

## 🔬 How It Works

### Assessment Pipeline

1. **Entity Resolution**: AI resolves product and vendor information from minimal input
2. **Data Collection**: Aggregates data from multiple security sources:
   - CVE databases (NVD API)
   - CISA KEV catalog
   - VirusTotal (for hash analysis)
   - Vendor security pages
   - Security advisories
   - Bug bounty platforms
3. **AI Synthesis**: Analyzes collected data using Gemini AI to generate comprehensive security posture
4. **Trust Scoring**: Calculates transparent 0-100 trust score with detailed factor breakdown
5. **Alternative Suggestions**: Identifies safer alternatives when risks are detected
6. **Caching**: Stores results with full metadata for reproducibility

### Trust Score Calculation

The trust score is calculated using a transparent algorithm:
- **Starting Score**: 50/100 (neutral baseline)
- **CVE Penalties**: Based on total CVEs, version-specific CVEs, critical severity, and CISA KEV entries
- **VirusTotal Analysis**: Weighted by confidence, considers detection counts, reputation, and trusted vendor signals
- **Positive Factors**: Bonuses for transparency, data handling compliance, deployment controls
- **Vendor Bonus**: Adjustments for established vendors with strong security track records
- **Confidence Score**: Reflects data quality and completeness

All values are fine-tuned by AI training on real datasets. See the Help page in the web interface for complete methodology.

## 📊 Data Sources

Secure Your App Health aggregates information from trusted security sources:

- **National Vulnerability Database (NVD)**: CVE data and CVSS scores
- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **VirusTotal v3 API**: Multi-engine malware detection and reputation scoring
- **Vendor Security Pages**: Official PSIRT pages and security documentation
- **Security Advisories**: CERT notices and vendor advisories
- **Bug Bounty Platforms**: Public vulnerability disclosures
- **CIRCL Hashlookup**: File hash and metadata information

All assessments are data-driven—no hardcoded vendor lists or predetermined scores.

## 🏗️ Architecture

```
ReputationRecon/
├── main.py                      # FastAPI application entry point
├── cli.py                       # Command-line interface
├── config.py                    # Configuration management
├── requirements.txt             # Python dependencies
├── run_server.sh               # Server startup script (Linux/Mac)
├── setup_env.sh                # Environment setup script
├── setup_env.ps1               # Environment setup script (Windows)
├── SETUP_API_KEYS.md           # API key setup instructions
├── static/
│   ├── index.html              # Web UI
│   └── styles.css              # CSS styles (separated from HTML)
├── server/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── routing.py          # API routes and endpoints
│   ├── dtos/
│   │   ├── __init__.py
│   │   ├── AppDetails.py       # Legacy DTO
│   │   ├── AssessmentRequest.py
│   │   └── AssessmentResponse.py
│   └── services/
│       ├── __init__.py
│       ├── cache.py            # SQLite cache implementation
│       ├── data_collectors.py   # Data collection from various sources
│       ├── classifier.py        # Software taxonomy classification
│       ├── ai_synthesizer.py    # AI-powered synthesis engine
│       ├── assessment_service.py # Main assessment orchestration
│       └── export_service.py    # Report export functionality
├── client/                      # React + TypeScript frontend
│   └── src/
│       ├── components/          # UI components
│       ├── pages/               # Page components
│       └── services/            # API client
├── assessments_cache.db         # Local SQLite cache
└── README.md
```

## 🎨 Features Deep Dive

### PRO Mode vs Classic Mode

- **Classic Mode**: Fast assessments using efficient AI models. Perfect for quick evaluations.
- **PRO Mode**: Enhanced analysis using Gemini 2.5 Pro. Slower but provides:
  - Deeper security insights
  - More comprehensive threat analysis
  - Enhanced context understanding
  - Higher quality synthesis

Both modes are cached separately, so you can compare results for the same application.

### Cache Browser

Browse and search previous assessments:
- Filter by product name, vendor, or hash
- Filter by trust score range
- See AI mode used for each assessment
- Click any result to reload it instantly

### Export Functionality

- **Markdown**: Clean, structured format perfect for documentation
- **PDF**: Print-ready HTML that opens in browser. Use Ctrl+P / Cmd+P to save as PDF

All exports include:
- Complete assessment data
- All security factors and scores
- Full source citations
- Metadata including AI mode and cache information

## 🛠️ Development

### Running in Development Mode

**Backend with auto-reload:**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend with hot-reload:**
```bash
cd client
npm run dev
```

### Testing the API

Visit http://localhost:8000/docs for interactive API documentation with Swagger UI.

### Project Dependencies

**Backend:**
- FastAPI - Modern web framework
- Google Gemini AI - AI synthesis engine
- SQLite - Local caching
- httpx - HTTP client for API calls

**Frontend:**
- React 18 - UI framework
- TypeScript - Type safety
- Vite - Fast build tool
- React Router - Navigation

See `requirements.txt` and `client/package.json` for complete dependency lists.

## 🐛 Troubleshooting

**Port already in use:**
```bash
# Change port in main.py or use:
uvicorn main:app --reload --port 8001
```

**API key errors:**
- Verify environment variables are set correctly
- Check `/api/config/status` endpoint for configuration status
- Some features work without API keys, but hash analysis requires VirusTotal

**Cache issues:**
- Delete `assessments_cache.db` to reset cache
- Cache automatically migrates old entries on server restart

**Frontend not loading:**
- Ensure backend is running on port 8000
- Check browser console for errors
- Verify Vite dev server is running on correct port

## 📝 API Documentation

Full API documentation is available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Main Endpoints

- `POST /api/assess` - Perform security assessment
- `GET /api/cache/search` - Search cached assessments
- `POST /api/export/{format}` - Export reports (markdown, pdf)
- `GET /api/config/status` - Check API key configuration

All endpoints include rate limiting. See API docs for details.

## 🤝 Contributing

This project was developed for Junction Hackathon 2025. We welcome feedback and improvements!

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Junction Hackathon 2025

Secure Your App Health was built for Junction Hackathon 2025 by a team of 3 students from EPFL (École Polytechnique Fédérale de Lausanne), focusing on solving real-world security assessment challenges with AI-powered solutions.

## 🙏 Acknowledgments

- Google Gemini AI for powerful synthesis capabilities
- VirusTotal for comprehensive file analysis
- NVD and CISA for vulnerability intelligence
- All the security researchers and organizations that maintain public security data

---

**Built with ❤️ for Junction Hackathon 2025**
