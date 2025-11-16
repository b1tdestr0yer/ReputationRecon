#!/bin/bash

# Secure Your App Health API Server Startup Script

echo "🚀 Starting Secure Your App Health API Server..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Virtual environment not found. Creating one..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment. Trying with 'python' instead..."
        python -m venv venv
        if [ $? -ne 0 ]; then
            echo "❌ Error: Could not create virtual environment. Please install Python 3.8+"
            exit 1
        fi
    fi
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check if dependencies are installed
if ! python -c "import fastapi" 2>/dev/null; then
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies"
        exit 1
    fi
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi

# Run the server
echo ""
echo "🌟 Starting server on http://localhost:8000"
echo "📚 API Documentation: http://localhost:8000/docs"
echo "🛑 Press Ctrl+C to stop the server"
echo ""

uvicorn main:app --reload --host 0.0.0.0 --port 8000

