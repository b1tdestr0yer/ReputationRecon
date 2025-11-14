# ReputationRecon API

A FastAPI-based REST API server with rate limiting capabilities.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd ReputationRecon
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

## Running the Server

### Option 1: Using Python directly
```bash
python main.py
```

### Option 2: Using uvicorn directly
```bash
uvicorn main:app --reload
```

The `--reload` flag enables auto-reload on code changes (useful for development).

The server will start on `http://localhost:8000`

## API Endpoints

### Health Check
- **GET** `/` - Returns API status
  ```bash
  curl http://localhost:8000/
  ```

### Main API Endpoint
- **POST** `/api/` - Process application details
  - **Rate Limit:** 10 requests per second
  - **Request Body:**
    ```json
    {
      "company_name": "Example Corp",
      "product_name": "Example Product",
      "sha1": "abc123def456..."
    }
    ```
  - **Example using curl:**
    ```bash
    curl -X POST http://localhost:8000/api/ \
      -H "Content-Type: application/json" \
      -d '{
        "company_name": "Example Corp",
        "product_name": "Example Product",
        "sha1": "abc123def456"
      }'
    ```

## Interactive API Documentation

FastAPI provides automatic interactive API documentation:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

You can test the API directly from these pages.

## Project Structure

```
ReputationRecon/
├── main.py                 # FastAPI application entry point
├── requirements.txt        # Python dependencies
├── server/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── routing.py     # API routes and endpoints
│   └── dtos/
│       ├── __init__.py
│       └── AppDetails.py  # Pydantic models
└── README.md
```

## Features

- ✅ FastAPI framework for high performance
- ✅ Rate limiting (10 requests/second)
- ✅ CORS middleware enabled
- ✅ Automatic API documentation
- ✅ Pydantic validation for request/response models

## Development

To run in development mode with auto-reload:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Troubleshooting

- **Port already in use:** Change the port in `main.py` or use `--port` flag with uvicorn
- **Import errors:** Make sure you've activated your virtual environment and installed all dependencies
- **Rate limit errors:** The API limits to 10 requests per second per IP address

