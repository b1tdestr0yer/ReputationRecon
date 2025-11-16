# Secure Your App Health - AI-Powered Security Assessment Tool

A comprehensive security assessment platform that generates CISO-ready trust briefs for applications in minutes. Built for security teams and CISOs who need accurate, concise, and source-grounded snapshots of a product's security posture.

## Features

- ✅ **Entity Resolution** - Automatically resolves product and vendor identity from minimal input
- ✅ **Software Classification** - Categorizes applications into clear taxonomy (File Sharing, GenAI, SaaS CRM, etc.)
- ✅ **Security Posture Analysis** - Comprehensive assessment including:
  - Product description and usage
  - Vendor reputation
  - CVE trend summaries (with CISA KEV integration)
  - Security incidents and abuse signals
  - Data handling and compliance information
  - Deployment and admin controls
- ✅ **Trust Score** - Transparent 0-100 trust/risk score with rationale and confidence
- ✅ **Safer Alternatives** - Suggests 1-2 safer alternatives with rationale
- ✅ **Evidence & Citations** - All claims are source-grounded with proper citations
- ✅ **Local Caching** - SQLite-based cache with timestamps for reproducibility
- ✅ **Multiple Interfaces** - REST API, CLI, and Web UI with compare-view
- ✅ **VirusTotal Integration** - Hash-based file analysis using v3 API with enhanced risk assessment
- ✅ **Data-Driven Analysis** - No hardcoded vendor/tool lists; all assessments based on real-time data
- ✅ **Enhanced Risk Detection** - Advanced false positive detection and abuse pattern recognition

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- (Optional) VirusTotal API key for hash analysis (v3 API)
- (Optional) Google Gemini API key for enhanced AI synthesis

## Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd Secure Your App Health
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   
   On Windows:
   ```bash
   venv\Scripts\activate
   ```
   
   On macOS/Linux:
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Set environment variables (optional):**
   
   You can set environment variables directly or use a `.env` file in the project root:
   ```bash
   # .env file format
   VIRUSTOTAL_API_KEY=your_api_key_here
   GEMINI_API_KEY=your_api_key_here
   ```
   
   Or set them directly:
   ```bash
   # Windows PowerShell
   $env:VIRUSTOTAL_API_KEY="your_api_key_here"
   $env:GEMINI_API_KEY="your_api_key_here"  # Optional, for enhanced AI
   
   # Linux/Mac
   export VIRUSTOTAL_API_KEY="your_api_key_here"
   export GEMINI_API_KEY="your_api_key_here"
   ```
   
   See `SETUP_API_KEYS.md` for detailed setup instructions.

## Running the Server

### Option 1: Using the shell script (Linux/Mac)
```bash
chmod +x run_server.sh
./run_server.sh
```

This script will:
- Create a virtual environment if it doesn't exist
- Install dependencies automatically
- Start the server with auto-reload

### Option 2: Using Python directly
```bash
python main.py
```

### Option 3: Using uvicorn directly
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The server will start on `http://localhost:8000`

## Usage

### Web UI

Access the web interface at: `http://localhost:8000/static/index.html`

Features:
- **Single Application Assessment** - Assess individual applications with product name, vendor, and optional hash
- **Side-by-Side Comparison** - Compare multiple applications simultaneously
- **Interactive Trust Score Gauge** - Circular gauge visualization with color-coded risk levels
- **Key Factors Display** - Card-based grid showing top contributing factors to the trust score
- **Collapsible Security Posture Cards** - Expandable sections for:
  - Description
  - Usage
  - Vendor Reputation
  - Data Handling
  - Deployment Controls
  - Incidents & Abuse
- **CVE Analysis** - Visual breakdown of Common Vulnerabilities and Exposures
- **Professional Loading Animation** - Step-by-step progress indicators during assessment
- **Citations and Evidence** - Source-grounded claims with proper attribution
- **Export Functionality** - Export reports in multiple formats

### CLI

```bash
# Assess by product name
python cli.py --product "Slack" --vendor "Salesforce"

# Assess by URL
python cli.py --url "https://slack.com"

# Assess with hash
python cli.py --product "MyApp" --hash "abc123..."

# Output as JSON
python cli.py --product "Slack" --json

# Compare multiple applications
python cli.py --compare --product "Slack" --product "Teams"
```

### API Endpoints

#### Assess Application
- **POST** `/api/assess` - Perform security assessment
  - **Rate Limit:** 10 requests per minute
  - **Request Body:**
    ```json
    {
      "product_name": "Slack",
      "vendor_name": "Salesforce",
      "url": "https://slack.com",
      "hash": "optional_hash_here"
    }
    ```
  - **Example using curl:**
    ```bash
    curl -X POST http://localhost:8000/api/assess \
      -H "Content-Type: application/json" \
      -d '{
        "product_name": "Slack",
        "vendor_name": "Salesforce",
        "url": "https://slack.com"
      }'
    ```

#### Compare Applications
- **POST** `/api/compare` - Compare multiple applications
  - **Rate Limit:** 5 requests per minute
  - **Request Body:** Array of assessment requests
    ```json
    [
      {
        "product_name": "Slack",
        "vendor_name": "Salesforce"
      },
      {
        "product_name": "Microsoft Teams",
        "vendor_name": "Microsoft"
      }
    ]
    ```

#### VirusTotal Hash Search
- **GET** `/api/virustotal/{hash}` - Search VirusTotal v3 API by hash (MD5, SHA1, or SHA256)
  - **Rate Limit:** 4 requests per minute
  - **Returns:** Enhanced risk data including:
    - Detection statistics
    - Reputation scores
    - Threat classifications
    - Community votes
    - False positive indicators
    - Abuse pattern detection
  - **Example:**
    ```bash
    curl http://localhost:8000/api/virustotal/44d88612fea8a8f36de82e1278abb02f
    ```

#### Export Reports
- **POST** `/api/export/{format}` - Export assessment reports
  - **Formats:** `json`, `pdf`, `html`
  - **Rate Limit:** 10 requests per minute

#### Configuration Status
- **GET** `/api/config/status` - Check API key configuration status

## Response Format

### Assessment Response

```json
{
  "entity_name": "Slack",
  "vendor_name": "Salesforce",
  "category": "Collaboration",
  "security_posture": {
    "description": "Product information...",
    "usage": "Primary use case: Collaboration...",
    "vendor_reputation": "Vendor reputation summary...",
    "cve_summary": {
      "total_cves": 5,
      "critical_count": 1,
      "high_count": 2,
      "recent_trend": "stable",
      "cisa_kev_count": 0,
      "recent_cves": []
    },
    "incidents_abuse": "No significant incidents found...",
    "data_handling": "Data handling information...",
    "deployment_controls": "Deployment information...",
    "citations": [
      {
        "source": "https://slack.com/security",
        "source_type": "vendor",
        "claim": "Vendor security information",
        "is_vendor_stated": true,
        "timestamp": "2024-01-01T00:00:00"
      }
    ]
  },
  "trust_score": {
    "score": 75,
    "risk_level": "Low",
    "confidence": 0.8,
    "rationale": "Trust Score: 75/100 (Low Risk)...",
    "factors": {
      "vendor_transparency": 10,
      "data_handling": 5
    }
  },
  "alternatives": [
    {
      "name": "Element",
      "vendor": "Element",
      "rationale": "Open-source, end-to-end encrypted...",
      "trust_score": 80
    }
  ],
  "assessment_timestamp": "2024-01-01T00:00:00",
  "data_quality": "sufficient",
  "cache_key": "abc123..."
}
```

## Data Sources

The system collects data from multiple high-signal sources:

- **Vendor Security Pages** - PSIRT pages, security overviews
- **Terms of Service** - Data Processing Agreements, privacy policies
- **CVE Databases** - Common Vulnerabilities and Exposures (NVD API v2)
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **VirusTotal v3 API** - Comprehensive file hash analysis with:
  - Multi-engine detection statistics
  - Reputation scoring
  - Threat classification
  - Community insights
  - Sandbox verdicts
  - Behavioral analysis
- **Security Advisories** - CERT notices, vendor advisories
- **CIRCL Hashlookup** - File information based on hash

**Note:** All assessments are data-driven. The system does not rely on hardcoded vendor or tool lists, ensuring assessments are based on real-time threat intelligence and security signals.

## Project Structure

```
Secure Your App Health/
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
└── README.md
```

## Judging Criteria Alignment

This implementation addresses all judging criteria:

- **Entity Resolution & Categorization (20%)** ✅
  - Automatic entity and vendor resolution
  - Software taxonomy classification

- **Evidence & Citation Quality (24%)** ✅
  - All claims are source-grounded
  - Vendor-stated vs. independent claim labeling
  - Multiple high-signal sources

- **Security Posture Synthesis (12%)** ✅
  - Comprehensive security analysis
  - CVE trends, incidents, data handling, deployment controls

- **Trust/Risk Score Transparency (8%)** ✅
  - 0-100 score with detailed rationale
  - Confidence levels
  - Factor breakdown

- **Alternatives & Quick Compare (6%)** ✅
  - Safer alternative suggestions
  - Side-by-side comparison endpoint and UI

- **Technical Execution & Resilience (15%)** ✅
  - Local caching with timestamps
  - Error handling
  - Rate limiting
  - Reproducibility

- **Problem Fit & Clarity (15%)** ✅
  - CISO-ready brief format
  - Clear, concise output
  - Multiple interfaces (API, CLI, Web UI)

## Interactive API Documentation

FastAPI provides automatic interactive API documentation:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## Caching

Assessments are cached in a local SQLite database (`assessments_cache.db`) with timestamps. This enables:
- Faster repeated assessments
- Reproducibility
- Offline access to previous assessments

Cache can be cleared programmatically or by deleting the database file.

## Development

To run in development mode with auto-reload:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Troubleshooting

- **Port already in use:** Change the port in `main.py` or use `--port` flag with uvicorn
- **Import errors:** Make sure you've activated your virtual environment and installed all dependencies
- **Rate limit errors:** The API has rate limits per endpoint (see endpoint documentation)
- **API key errors:** 
  - Ensure environment variables are set if using VirusTotal or Gemini features
  - Check `SETUP_API_KEYS.md` for detailed setup instructions
  - Use `/api/config/status` endpoint to verify API key configuration
- **Cache issues:** Delete `assessments_cache.db` to clear the cache
- **Web UI not loading:** Ensure the server is running and access via `http://localhost:8000/static/index.html`
- **CSS not loading:** Verify that `static/styles.css` exists and the server is serving static files correctly

## License

This project is part of a security assessment challenge.

## Contributing

This is a challenge submission. For questions or issues, please refer to the challenge guidelines.
