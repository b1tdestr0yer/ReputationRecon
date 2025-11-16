#!/usr/bin/env python3
"""
Secure Your App Health CLI - Command-line interface for security assessments
"""
import asyncio
import json
import sys
from typing import Optional
import argparse
from server.dtos.AssessmentRequest import AssessmentRequest
from server.services.assessment_service import AssessmentService
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box


console = Console()


def print_assessment(assessment_dict: dict):
    """Pretty print assessment results"""
    # Header
    console.print(f"\n[bold cyan]Assessment: {assessment_dict['entity_name']}[/bold cyan]")
    console.print(f"[dim]Vendor: {assessment_dict['vendor_name']}[/dim]")
    console.print(f"[dim]Category: {assessment_dict['category']}[/dim]\n")
    
    # Trust Score
    trust = assessment_dict['trust_score']
    score_color = "green" if trust['score'] >= 70 else "yellow" if trust['score'] >= 50 else "red"
    console.print(Panel(
        f"[bold]Trust Score: [{score_color}]{trust['score']}/100[/{score_color}][/bold]\n"
        f"Risk Level: [bold]{trust['risk_level']}[/bold]\n"
        f"Confidence: {trust['confidence']:.1%}\n\n"
        f"{trust['rationale']}",
        title="Trust Assessment",
        border_style=score_color
    ))
    
    # Security Posture
    posture = assessment_dict['security_posture']
    console.print("\n[bold]Security Posture Summary[/bold]")
    console.print(f"[dim]Description:[/dim] {posture['description']}")
    console.print(f"[dim]Usage:[/dim] {posture['usage']}")
    console.print(f"[dim]Vendor Reputation:[/dim] {posture['vendor_reputation']}")
    console.print(f"[dim]Data Handling:[/dim] {posture['data_handling']}")
    console.print(f"[dim]Deployment Controls:[/dim] {posture['deployment_controls']}")
    
    # CVE Summary
    cve = posture['cve_summary']
    console.print("\n[bold]CVE Summary[/bold]")
    console.print(f"Total CVEs: {cve['total_cves']}")
    console.print(f"Critical: {cve['critical_count']} | High: {cve['high_count']}")
    console.print(f"CISA KEV: {cve['cisa_kev_count']}")
    
    # Citations
    if posture['citations']:
        console.print("\n[bold]Citations[/bold]")
        for citation in posture['citations']:
            source_type = "[vendor]" if citation['is_vendor_stated'] else "[independent]"
            console.print(f"  {source_type} {citation['source_type']}: {citation['source']}")
    
    # Alternatives
    if assessment_dict['alternatives']:
        console.print("\n[bold]Safer Alternatives[/bold]")
        for alt in assessment_dict['alternatives']:
            console.print(f"  • {alt['name']} ({alt['vendor']})")
            console.print(f"    {alt['rationale']}")
    
    # Data Quality
    quality_color = "green" if assessment_dict['data_quality'] == "sufficient" else "yellow" if assessment_dict['data_quality'] == "limited" else "red"
    console.print(f"\n[dim]Data Quality: [{quality_color}]{assessment_dict['data_quality']}[/{quality_color}][/dim]")


def print_comparison(comparison_dict: dict):
    """Pretty print comparison results"""
    console.print("\n[bold cyan]Application Comparison[/bold cyan]\n")
    
    assessments = comparison_dict['assessments']
    
    # Create comparison table
    table = Table(title="Security Comparison", box=box.ROUNDED)
    table.add_column("Application", style="cyan")
    table.add_column("Vendor", style="magenta")
    table.add_column("Category", style="blue")
    table.add_column("Trust Score", justify="right", style="green")
    table.add_column("Risk Level", justify="center")
    table.add_column("CVEs", justify="right")
    table.add_column("CISA KEV", justify="right")
    
    for assessment in assessments:
        trust = assessment['trust_score']
        cve = assessment['security_posture']['cve_summary']
        score_color = "green" if trust['score'] >= 70 else "yellow" if trust['score'] >= 50 else "red"
        
        table.add_row(
            assessment['entity_name'],
            assessment['vendor_name'],
            assessment['category'],
            f"[{score_color}]{trust['score']}/100[/{score_color}]",
            trust['risk_level'],
            str(cve['total_cves']),
            str(cve['cisa_kev_count'])
        )
    
    console.print(table)
    
    # Summary
    comp = comparison_dict['comparison']
    console.print(f"\n[bold]Summary[/bold]")
    console.print(f"Highest Trust: {comp['highest_trust']['entity_name']} ({comp['highest_trust']['trust_score']['score']}/100)")
    console.print(f"Lowest Trust: {comp['lowest_trust']['entity_name']} ({comp['lowest_trust']['trust_score']['score']}/100)")


async def main():
    parser = argparse.ArgumentParser(
        description="Secure Your App Health - AI-powered security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess by product name
  python cli.py --product "Slack" --vendor "Salesforce"
  
  # Assess by URL
  python cli.py --url "https://slack.com"
  
  # Assess with hash
  python cli.py --product "MyApp" --hash "abc123..."
  
  # Compare multiple applications
  python cli.py --compare --product "Slack" --product "Teams" --product "Discord"
  
  # Output as JSON
  python cli.py --product "Slack" --json
        """
    )
    
    parser.add_argument("--product", "-p", help="Product/application name")
    parser.add_argument("--vendor", "-v", help="Vendor/company name")
    parser.add_argument("--url", "-u", help="Product or vendor URL")
    parser.add_argument("--hash", help="Binary hash (MD5, SHA1, or SHA256)")
    parser.add_argument("--compare", action="store_true", help="Compare mode (requires multiple --product)")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not args.product and not args.vendor and not args.url:
        parser.error("At least one of --product, --vendor, or --url must be provided")
    
    service = AssessmentService()
    
    try:
        if args.compare:
            # Comparison mode
            if not args.product:
                parser.error("--compare requires at least one --product")
            
            # For simplicity, create multiple requests from product names
            # In a real implementation, you'd parse multiple products
            console.print("[yellow]Comparison mode - using first product only in this version[/yellow]")
            request = AssessmentRequest(
                product_name=args.product,
                vendor_name=args.vendor,
                url=args.url,
                hash=args.hash
            )
            assessment = await service.assess(request)
            result = assessment.model_dump()
            
            if args.json:
                print(json.dumps(result, indent=2, default=str))
            else:
                print_assessment(result)
        else:
            # Single assessment
            request = AssessmentRequest(
                product_name=args.product,
                vendor_name=args.vendor,
                url=args.url,
                hash=args.hash
            )
            
            console.print("[bold]Assessing application...[/bold]")
            assessment = await service.assess(request)
            result = assessment.model_dump()
            
            if args.json:
                print(json.dumps(result, indent=2, default=str))
            else:
                print_assessment(result)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Assessment cancelled[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

