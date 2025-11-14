from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from server.dtos.AppDetails import AppDetails
from server.dtos.AssessmentRequest import AssessmentRequest
from server.dtos.AssessmentResponse import AssessmentResponse
from server.services.assessment_service import AssessmentService
from server.services.export_service import ExportService
import httpx
import os
from typing import List
import config
import json



router = APIRouter()

limiter = Limiter(key_func=get_remote_address)

# Initialize assessment service
assessment_service = AssessmentService()



@router.post(
    "/api/",
    summary="",
    description="""
""",
    responses={
        200: {"description": "hacked"},
    }
)
@limiter.limit("10/second")
async def ask_sth(payload: AppDetails, request: Request) -> JSONResponse:
    return JSONResponse(
                status_code=200,
                content={
                    "are you hacked": True
                }
            )


@router.get(
    "/api/virustotal/{hash}",
    summary="Search VirusTotal by hash",
    description="""
    Search VirusTotal for information about a file hash (MD5, SHA1, or SHA256).
    Requires VIRUSTOTAL_API_KEY environment variable to be set.
    """,
    responses={
        200: {"description": "VirusTotal search results"},
        400: {"description": "Invalid hash format"},
        401: {"description": "VirusTotal API key not configured"},
        404: {"description": "Hash not found in VirusTotal"},
        429: {"description": "VirusTotal API rate limit exceeded"},
        500: {"description": "Error querying VirusTotal API"},
    }
)
@limiter.limit("4/minute")  # VirusTotal free tier: 4 requests per minute
async def virustotal_search(hash: str, request: Request) -> JSONResponse:
    """
    Search VirusTotal for a file hash.
    
    Args:
        hash: MD5, SHA1, or SHA256 hash of the file
        
    Returns:
        JSONResponse with VirusTotal scan results
    """
    # Validate hash format (basic check)
    hash = hash.strip().lower()
    if not hash or len(hash) not in [32, 40, 64]:  # MD5=32, SHA1=40, SHA256=64
        raise HTTPException(
            status_code=400,
            detail="Invalid hash format. Must be MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars)"
        )
    
    # Get API key from environment
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable."
        )
    
    # VirusTotal API endpoint
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        "apikey": api_key,
        "resource": hash
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                # VirusTotal returns response_code 0 when hash not found
                if data.get("response_code") == 0:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Hash not found in VirusTotal database"
                    )
                
                return JSONResponse(
                    status_code=200,
                    content=data
                )
            elif response.status_code == 204:
                # Rate limit exceeded
                raise HTTPException(
                    status_code=429,
                    detail="VirusTotal API rate limit exceeded. Please try again later."
                )
            elif response.status_code == 403:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid VirusTotal API key or insufficient privileges"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"VirusTotal API returned status {response.status_code}"
                )
                
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=500,
            detail="Timeout while querying VirusTotal API"
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error connecting to VirusTotal API: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )


@router.post(
    "/api/assess",
    summary="Assess application security posture",
    description="""
    Perform a comprehensive security assessment of an application.
    Returns a CISO-ready trust brief with security posture, trust score, and safer alternatives.
    """,
    response_model=AssessmentResponse,
    responses={
        200: {"description": "Assessment completed successfully"},
        400: {"description": "Invalid request"},
        500: {"description": "Assessment error"},
    }
)
@limiter.limit("10/minute")
async def assess_application(assessment_request: AssessmentRequest, request: Request) -> AssessmentResponse:
    """
    Assess an application's security posture.
    
    Requires at least one of: product_name, vendor_name, or url.
    """
    print(f"\n[API] POST /api/assess - Request received from {request.client.host if request.client else 'unknown'}")
    print(f"[API] Request data: {assessment_request.model_dump()}")
    
    if not assessment_request.product_name and not assessment_request.vendor_name and not assessment_request.url:
        print("[API] ✗ Validation failed: Missing required fields")
        raise HTTPException(
            status_code=400,
            detail="At least one of product_name, vendor_name, or url must be provided"
        )
    
    try:
        print("[API] Starting assessment...")
        assessment = await assessment_service.assess(assessment_request)
        print(f"[API] ✓ Assessment complete, returning response")
        return assessment
    except Exception as e:
        print(f"[API] ✗ ERROR during assessment: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Error during assessment: {str(e)}"
        )


@router.post(
    "/api/compare",
    summary="Compare multiple applications",
    description="""
    Compare security postures of multiple applications side-by-side.
    Useful for evaluating alternatives.
    """,
    responses={
        200: {"description": "Comparison completed"},
        400: {"description": "Invalid request"},
        500: {"description": "Comparison error"},
    }
)
@limiter.limit("5/minute")
async def compare_applications(requests: List[AssessmentRequest], request: Request) -> JSONResponse:
    """
    Compare multiple applications.
    
    Accepts a list of assessment requests and returns a side-by-side comparison.
    """
    print(f"\n[API] POST /api/compare - Request received from {request.client.host if request.client else 'unknown'}")
    print(f"[API] Comparing {len(requests)} applications")
    
    if not requests or len(requests) < 2:
        print("[API] ✗ Validation failed: Need at least 2 applications")
        raise HTTPException(
            status_code=400,
            detail="At least 2 applications required for comparison"
        )
    
    if len(requests) > 10:
        print("[API] ✗ Validation failed: Too many applications")
        raise HTTPException(
            status_code=400,
            detail="Maximum 10 applications allowed for comparison"
        )
    
    try:
        print("[API] Starting comparison...")
        comparison = await assessment_service.compare(requests)
        print(f"[API] ✓ Comparison complete")
        return JSONResponse(status_code=200, content=comparison)
    except Exception as e:
        print(f"[API] ✗ ERROR during comparison: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Error during comparison: {str(e)}"
        )


@router.get(
    "/api/config/status",
    summary="Get configuration status",
    description="Check which API keys are configured",
    responses={
        200: {"description": "Configuration status"},
    }
)
async def get_config_status() -> JSONResponse:
    """Get the current configuration status"""
    status = config.Config.get_status()
    return JSONResponse(status_code=200, content=status)


@router.post(
    "/api/export/{format}",
    summary="Export assessment report",
    description="Export assessment to Markdown or PDF format",
    responses={
        200: {"description": "Export file"},
        400: {"description": "Invalid format"},
    }
)
@limiter.limit("10/minute")
async def export_assessment(format: str, assessment_data: dict, request: Request) -> Response:
    """
    Export assessment to specified format.
    
    Formats: markdown, pdf
    """
    print(f"\n[API] POST /api/export/{format} - Request received")
    print(f"[API] Exporting assessment for: {assessment_data.get('entity_name', 'Unknown')}")
    
    export_service = ExportService()
    
    if format.lower() == "markdown":
        print(f"[Export Service] Generating Markdown export...")
        md_content = export_service.export_to_markdown(assessment_data)
        print(f"[Export Service] ✓ Markdown export generated ({len(md_content)} characters)")
        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="assessment_{assessment_data.get("entity_name", "report")}.md"'
            }
        )
    elif format.lower() == "pdf":
        print(f"[Export Service] Generating PDF/HTML export...")
        html_content = export_service.export_to_pdf_html(assessment_data)
        print(f"[Export Service] ✓ HTML export generated ({len(html_content)} characters)")
        # For PDF, we'll return HTML that can be printed to PDF by the browser
        # In production, you'd use weasyprint or similar
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="assessment_{assessment_data.get("entity_name", "report")}.html"'
            }
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Supported formats: markdown, pdf"
        )