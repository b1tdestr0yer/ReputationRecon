from fastapi import APIRouter, Request, HTTPException, Query
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
from typing import List, Optional
import config
import json



router = APIRouter()

limiter = Limiter(key_func=get_remote_address)


@router.get("/health")
async def health_check():
    """Health check endpoint to verify routing is working"""
    return {"status": "ok", "message": "API router is working"}

# Initialize assessment service
assessment_service = AssessmentService()



@router.post(
    "/",
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
    "/virustotal/{hash}",
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
    "/assess",
    summary="Assess application security posture",
    description="""
    Perform a comprehensive security assessment of an application.
    Returns a CISO-ready trust brief with security posture, trust score, and safer alternatives.
    Supports caching - results are cached for 7 days by default.
    """,
    response_model=AssessmentResponse,
    responses={
        200: {"description": "Assessment completed successfully"},
        400: {"description": "Invalid request"},
        500: {"description": "Assessment error"},
    }
)
@limiter.limit("10/minute")
async def assess_application(
    assessment_request: AssessmentRequest, 
    request: Request,
    force_refresh: bool = Query(False, description="Bypass cache and generate fresh assessment")
) -> AssessmentResponse:
    """
    Assess an application's security posture.
    
    Requires at least one of: product_name, vendor_name, or url.
    
    Query parameters:
    - force_refresh: If True, bypass cache and generate fresh assessment
    """
    print(f"\n[API] POST /api/assess - Request received from {request.client.host if request.client else 'unknown'}")
    print(f"[API] Request data: {assessment_request.model_dump()}")
    print(f"[API] Force refresh: {force_refresh}")
    
    # Validate input lengths
    if assessment_request.product_name and len(assessment_request.product_name) > 128:
        raise HTTPException(
            status_code=400,
            detail="product_name must be 128 characters or less"
        )
    if assessment_request.vendor_name and len(assessment_request.vendor_name) > 128:
        raise HTTPException(
            status_code=400,
            detail="vendor_name must be 128 characters or less"
        )
    if assessment_request.url and len(assessment_request.url) > 128:
        raise HTTPException(
            status_code=400,
            detail="url must be 128 characters or less"
        )
    if assessment_request.hash and len(assessment_request.hash) > 128:
        raise HTTPException(
            status_code=400,
            detail="hash must be 128 characters or less"
        )
    
    if not assessment_request.product_name and not assessment_request.vendor_name and not assessment_request.url:
        print("[API] ✗ Validation failed: Missing required fields")
        raise HTTPException(
            status_code=400,
            detail="At least one of product_name, vendor_name, or url must be provided"
        )
    
    try:
        print("[API] Starting assessment...")
        assessment = await assessment_service.assess(assessment_request, force_refresh=force_refresh)
        print(f"[API] ✓ Assessment complete, returning response (Cached: {assessment.is_cached})")
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
    "/compare",
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
    
    # Validate input lengths for all requests
    for i, req in enumerate(requests):
        if req.product_name and len(req.product_name) > 128:
            raise HTTPException(
                status_code=400,
                detail=f"Request {i+1}: product_name must be 128 characters or less"
            )
        if req.vendor_name and len(req.vendor_name) > 128:
            raise HTTPException(
                status_code=400,
                detail=f"Request {i+1}: vendor_name must be 128 characters or less"
            )
        if req.url and len(req.url) > 128:
            raise HTTPException(
                status_code=400,
                detail=f"Request {i+1}: url must be 128 characters or less"
            )
        if req.hash and len(req.hash) > 128:
            raise HTTPException(
                status_code=400,
                detail=f"Request {i+1}: hash must be 128 characters or less"
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
    "/cache/search",
    summary="Search cached assessments",
    description="Search through cached assessment data by product name, vendor, hash, or trust score",
    responses={
        200: {"description": "Search results"},
        500: {"description": "Search error"},
    }
)
@limiter.limit("20/minute")
async def search_cache(
    request: Request,
    product_name: Optional[str] = Query(None, description="Search by product name (partial match)"),
    vendor_name: Optional[str] = Query(None, description="Search by vendor name (partial match)"),
    hash: Optional[str] = Query(None, description="Search by hash (partial match)"),
    min_trust_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum trust score (0-100)"),
    max_trust_score: Optional[int] = Query(None, ge=0, le=100, description="Maximum trust score (0-100)"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of results")
) -> JSONResponse:
    """
    Search cached assessments.
    
    Supports searching by product name, vendor name, hash, and filtering by trust score range.
    """
    print(f"\n[API] GET /api/cache/search - Request from {request.client.host if request else 'unknown'}")
    print(f"[API] Search params: product={product_name}, vendor={vendor_name}, hash={hash}, score_range={min_trust_score}-{max_trust_score}")
    
    try:
        from server.services.cache import AssessmentCache
        cache = AssessmentCache()
        results = cache.search(
            product_name=product_name,
            vendor_name=vendor_name,
            hash=hash,
            min_trust_score=min_trust_score,
            max_trust_score=max_trust_score,
            limit=limit
        )
        print(f"[API] ✓ Search complete, found {len(results)} results")
        return JSONResponse(status_code=200, content={'results': results, 'count': len(results)})
    except Exception as e:
        print(f"[API] ✗ ERROR during search: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Error during search: {str(e)}"
        )


@router.get(
    "/config/status",
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
    "/export/{format}",
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


@router.post(
    "/chat",
    summary="Chat with AI about assessment",
    description="Ask questions about a security assessment using AI",
    responses={
        200: {"description": "AI response"},
        400: {"description": "Invalid request"},
        500: {"description": "Chat error"},
    }
)
@limiter.limit("20/minute")
async def chat_about_assessment(request: Request, payload: dict) -> JSONResponse:
    """
    Chat with AI about a security assessment.
    
    Requires assessment_data and message in the request body.
    """
    print(f"\n[API] POST /api/chat - Request received from {request.client.host if request.client else 'unknown'}")
    
    assessment_data = payload.get("assessment_data")
    message = payload.get("message")
    
    if not assessment_data:
        raise HTTPException(
            status_code=400,
            detail="assessment_data is required"
        )
    
    if not message or not isinstance(message, str) or not message.strip():
        raise HTTPException(
            status_code=400,
            detail="message is required and must be a non-empty string"
        )
    
    try:
        from server.services.ai_synthesizer import AISynthesizer
        ai_synthesizer = AISynthesizer()
        
        # Build comprehensive context from assessment data
        entity_name = assessment_data.get("entity_name", "Unknown")
        vendor_name = assessment_data.get("vendor_name", "Unknown")
        category = assessment_data.get("category", "Unknown")
        
        # Build context string with all assessment information
        context_parts = []
        context_parts.append(f"Security Assessment for: {entity_name}")
        context_parts.append(f"Vendor: {vendor_name}")
        context_parts.append(f"Category: {category}")
        context_parts.append("")
        
        # Trust score information
        trust_score = assessment_data.get("trust_score", {})
        if trust_score:
            context_parts.append("Trust Score Information:")
            context_parts.append(f"- Score: {trust_score.get('score', 'N/A')}/100")
            context_parts.append(f"- Risk Level: {trust_score.get('risk_level', 'N/A')}")
            context_parts.append(f"- Confidence: {trust_score.get('confidence', 0) * 100:.1f}%")
            if trust_score.get('rationale'):
                context_parts.append(f"- Rationale: {trust_score.get('rationale')}")
            context_parts.append("")
        
        # Security recommendation
        suggestion = assessment_data.get("suggestion", "")
        if suggestion:
            context_parts.append("Security Recommendation:")
            context_parts.append(suggestion)
            context_parts.append("")
        
        # Security posture
        security_posture = assessment_data.get("security_posture", {})
        if security_posture:
            context_parts.append("Security Posture:")
            if security_posture.get("summary"):
                context_parts.append(f"Summary: {security_posture.get('summary')}")
            if security_posture.get("description"):
                context_parts.append(f"Description: {security_posture.get('description')}")
            if security_posture.get("usage"):
                context_parts.append(f"Usage: {security_posture.get('usage')}")
            if security_posture.get("vendor_reputation"):
                context_parts.append(f"Vendor Reputation: {security_posture.get('vendor_reputation')}")
            if security_posture.get("data_handling"):
                context_parts.append(f"Data Handling: {security_posture.get('data_handling')}")
            if security_posture.get("deployment_controls"):
                context_parts.append(f"Deployment Controls: {security_posture.get('deployment_controls')}")
            if security_posture.get("incidents_abuse"):
                context_parts.append(f"Incidents/Abuse: {security_posture.get('incidents_abuse')}")
            context_parts.append("")
            
            # CVE Summary
            cve_summary = security_posture.get("cve_summary", {})
            if cve_summary:
                context_parts.append("CVE Information:")
                context_parts.append(f"- Total CVEs: {cve_summary.get('total_cves', 0)}")
                context_parts.append(f"- Critical CVEs: {cve_summary.get('critical_count', 0)}")
                context_parts.append(f"- High CVEs: {cve_summary.get('high_count', 0)}")
                context_parts.append(f"- CISA KEV entries: {cve_summary.get('cisa_kev_count', 0)}")
                if cve_summary.get("detected_version"):
                    context_parts.append(f"- Detected Version: {cve_summary.get('detected_version')}")
                    context_parts.append(f"- Version-specific CVEs: {cve_summary.get('version_specific_cves', 0)}")
                context_parts.append("")
            
            # Citations
            citations = security_posture.get("citations", [])
            if citations:
                context_parts.append(f"Data Sources: {len(citations)} citations available")
                context_parts.append("")
        
        # Alternatives
        alternatives = assessment_data.get("alternatives", [])
        if alternatives:
            context_parts.append("Safer Alternatives:")
            for alt in alternatives[:3]:
                context_parts.append(f"- {alt.get('name', 'Unknown')} by {alt.get('vendor', 'Unknown')}: {alt.get('rationale', '')}")
            context_parts.append("")
        
        context = "\n".join(context_parts)
        
        # Build the prompt for the AI
        prompt = f"""You are a helpful security analyst AI assistant. You have access to a comprehensive security assessment for a software application. Answer the user's question based on the assessment data provided below.

Assessment Context:
{context}

User Question: {message}

Instructions:
- Answer the question based on the assessment data provided
- Be specific and reference actual numbers, scores, and findings from the assessment
- If the question asks about something not in the assessment, say so clearly
- Use a professional but friendly tone
- Keep responses concise but informative
- Focus on security-related aspects

Answer:"""
        
        # Use gemini-2.5-flash-lite as specified
        response_text = await ai_synthesizer._call_vertex_ai(prompt, model_name="gemini-2.5-flash-lite")
        
        if not response_text:
            raise HTTPException(
                status_code=500,
                detail="Failed to get response from AI"
            )
        
        print(f"[API] ✓ Chat response generated for {entity_name}")
        return JSONResponse(
            status_code=200,
            content={"message": response_text.strip()}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API] ✗ ERROR during chat: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Error during chat: {str(e)}"
        )