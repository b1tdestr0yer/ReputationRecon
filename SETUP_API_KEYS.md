# Setting Up API Keys

Secure Your App Health supports multiple methods for setting API keys. Choose the method that works best for you.

## Method 1: Using Setup Scripts (Recommended)

### Windows (PowerShell)

Run the PowerShell setup script:

```powershell
.\setup_env.ps1
```

The script will:
- Prompt you for your API keys
- Create a `.env` file automatically
- Optionally set environment variables for your current session

### Linux/Mac (Bash)

Run the bash setup script:

```bash
chmod +x setup_env.sh
./setup_env.sh
```

The script will:
- Prompt you for your API keys
- Create a `.env` file automatically
- Optionally export environment variables for your current session

## Method 2: Manual .env File

1. Copy the example file:
   ```bash
   # Windows
   copy .env.example .env
   
   # Linux/Mac
   cp .env.example .env
   ```

2. Edit `.env` and add your API keys:
   ```env
   VIRUSTOTAL_API_KEY=your_actual_key_here
   OPENAI_API_KEY=your_actual_key_here
   ```

The `.env` file is automatically loaded when you run the application.

## Method 3: Environment Variables

### Windows PowerShell

```powershell
$env:VIRUSTOTAL_API_KEY="your_key_here"
$env:OPENAI_API_KEY="your_key_here"
```

### Windows CMD

```cmd
set VIRUSTOTAL_API_KEY=your_key_here
set OPENAI_API_KEY=your_key_here
```

### Linux/Mac

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export OPENAI_API_KEY="your_key_here"
```

To make these permanent, add them to your shell profile:
- **Bash**: `~/.bashrc` or `~/.bash_profile`
- **Zsh**: `~/.zshrc`
- **PowerShell**: Add to your PowerShell profile

## Getting API Keys

### VirusTotal API Key

1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for a free account
3. Navigate to your API key in account settings
4. Copy your API key

**Note**: Free tier allows 4 requests per minute.

### Google Gemini API Key (REQUIRED)

1. Go to https://makersuite.google.com/app/apikey
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy your API key

**Note**: This is REQUIRED for AI-powered classification and analysis. The system will use fallback methods if not configured, but results will be less accurate.

## Verify Configuration

After setting up your API keys, you can verify they're loaded correctly:

### Via API

```bash
curl http://localhost:8000/api/config/status
```

### Via Python

```python
from config import Config

status = Config.get_status()
print(status)
```

## Security Notes

- **Never commit `.env` files to version control** - They're already in `.gitignore`
- The `.env` file contains sensitive information - keep it secure
- Use environment variables in production environments
- Rotate API keys regularly

## Troubleshooting

### Keys not loading?

1. Make sure `.env` file is in the project root directory
2. Check that the file is named exactly `.env` (not `.env.txt`)
3. Verify the format: `KEY=value` (no spaces around `=`)
4. Restart your application after creating/modifying `.env`

### Still having issues?

Check the configuration status endpoint:
```bash
curl http://localhost:8000/api/config/status
```

This will show which keys are configured and which are missing.

