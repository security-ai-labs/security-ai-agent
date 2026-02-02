#!/usr/bin/env python3
"""
Universal AI Security Agent CLI
Supports Web2 (Python, JS, Go) and Web3 (Solidity, Rust)
"""

import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

from src.core.analyzer import UniversalSecurityAnalyzer

console = Console()

LANGUAGE_ICONS = {
    'solidity': '⚡',
    'python': '🐍',
    'javascript': '📜',
    'typescript': '📘',
    'rust': '🦀',
    'go': '🐹',
}

CATEGORY_ICONS = {
    'web2': '🌐',
    'web3': '⛓️',
}

def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║   🛡️  Universal AI Security Agent                    🛡️   ║
    ║   📊 Web2 (Python, JS, Go) + Web3 (Solidity, Rust)      ║
    ╚══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def severity_color(severity: str) -> str:
    """Get color for severity level"""
    colors = {
        'CRITICAL': 'red',
        'HIGH': 'orange1',
        'MEDIUM': 'yellow',
        'LOW': 'blue'
    }
    return colors.get(severity, 'white')


def print_vulnerabilities(vulns: list):
    """Print vulnerabilities in a table"""
    if not vulns:
        console.print("\n✅ [green bold]No vulnerabilities found![/green bold]\n")
        return
    
    table = Table(
        title="🚨 Security Vulnerabilities Detected",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Issue", width=50)
    table.add_column("Line", width=6)
    
    for i, vuln in enumerate(vulns, 1):
        severity = vuln.get('severity', 'UNKNOWN')
        color = severity_color(severity)
        
        table.add_row(
            str(i),
            f"[{color}]{severity}[/{color}]",
            vuln.get('title', 'Unknown'),
            str(vuln.get('line_number', '?'))
        )
    
    console.print()
    console.print(table)


def print_vulnerability_details(vuln: dict, index: int):
    """Print detailed vulnerability information"""
    severity = vuln.get('severity', 'UNKNOWN')
    color = severity_color(severity)
    
    content = f"""
**Line:** {vuln.get('line_number', '?')}

**Description:**
{vuln.get('description', 'No description available')}

**Exploit Scenario:**
{vuln.get('exploit_scenario', 'No exploit scenario provided')}

**Recommendation:**
{vuln.get('recommendation', 'No recommendation provided')}

**CWE:** {vuln.get('cwe', 'Not specified')}
    """
    
    panel = Panel(
        Markdown(content),
        title=f"🔍 Vulnerability #{index}: {vuln.get('title', 'Unknown')}",
        subtitle=f"[{color}]{severity}[/{color}]",
        border_style=color,
        padding=(1, 2)
    )
    
    console.print(panel)


def analyze_file(filepath: str, language: str = None, model: str = None, detailed: bool = False):
    """Analyze a single file"""
    print_banner()
    
    console.print(f"📄 Analyzing file: [cyan]{filepath}[/cyan]\n")
    
    # Initialize analyzer
    try:
        analyzer = UniversalSecurityAnalyzer()
    except Exception as e:
        console.print(f"[red]❌ Error initializing analyzer: {e}[/red]")
        console.print("\n[yellow]💡 Make sure you have set OPENAI_API_KEY in your .env file[/yellow]")
        sys.exit(1)
    
    # Run analysis
    with console.status("[bold green]🤖 Running AI security analysis...", spinner="dots"):
        try:
            result = analyzer.analyze_file(filepath, language=language, model=model)
        except Exception as e:
            console.print(f"[red]❌ Analysis failed: {e}[/red]")
            sys.exit(1)
    
    # Display metadata
    metadata = result.get('metadata', {})
    lang = metadata.get('language', 'unknown')
    category = metadata.get('category', 'unknown')
    icon = LANGUAGE_ICONS.get(lang, '📄')
    cat_icon = CATEGORY_ICONS.get(category, '📊')
    
    console.print()
    console.print(Panel(
        f"{icon} Language: [cyan]{lang.upper()}[/cyan]\n"
        f"{cat_icon} Category: [yellow]{category.upper()}[/yellow]\n"
        f"📏 Lines of Code: {metadata.get('lines_of_code', '?')}\n"
        f"💰 Cost: [green]${metadata.get('cost_usd', 0):.4f}[/green]\n"
        f"🤖 Model: {metadata.get('model', 'unknown')}",
        title="📊 Analysis Info",
        border_style="blue"
    ))
    
    # Display vulnerabilities
    vulnerabilities = result.get('vulnerabilities', [])
    print_vulnerabilities(vulnerabilities)
    
    # Display summary
    summary = result.get('summary', {})
    console.print()
    console.print(Panel(
        f"Total Issues: {summary.get('total_issues', 0)}\n\n"
        f"[red]● Critical: {summary.get('critical', 0)}[/red]  "
        f"[orange1]● High: {summary.get('high', 0)}[/orange1]  "
        f"[yellow]● Medium: {summary.get('medium', 0)}[/yellow]  "
        f"[blue]● Low: {summary.get('low', 0)}[/blue]",
        title="📈 Summary",
        border_style="green"
    ))
    
    # Display overall assessment
    assessment = result.get('overall_assessment', '')
    if assessment:
        console.print()
        console.print(Panel(
            assessment,
            title="🎯 Overall Security Assessment",
            border_style="cyan"
        ))
    
    # Detailed view
    if detailed and vulnerabilities:
        console.print()
        console.print("[bold cyan]📋 Detailed Vulnerability Report:[/bold cyan]\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print_vulnerability_details(vuln, i)
            console.print()
    
    # Save report
    output_file = Path(filepath).stem + "_security_report.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        console.print(f"💾 Full report saved to: [cyan]{output_file}[/cyan]")
    except Exception as e:
        console.print(f"[yellow]⚠️  Could not save report: {e}[/yellow]")
    
    # Cache status
    if metadata.get('from_cache'):
        console.print("\n⚡ [yellow]Result from cache (no API cost)[/yellow]")
    
    console.print()


def print_usage():
    """Print usage information"""
    usage = """
[bold cyan]Usage:[/bold cyan]
  python cli.py <file> [options]

[bold cyan]Options:[/bold cyan]
  --language <lang>    Force specific language (python, javascript, solidity, etc.)
  --model <model>      Use specific model (gpt-4o-mini, gpt-4o)
  --detailed           Show detailed vulnerability information

[bold cyan]Examples:[/bold cyan]
  python cli.py examples/python/vulnerable_api.py
  python cli.py contract.sol --model gpt-4o
  python cli.py app.js --detailed

[bold cyan]Supported Languages:[/bold cyan]
  🌐 Web2: Python (.py), JavaScript (.js), TypeScript (.ts), Go (.go)
  ⛓️  Web3: Solidity (.sol), Rust (.rs)
    """
    console.print(Panel(usage, title="🛡️ AI Security Agent", border_style="cyan"))
def test_all_examples():
    """Test all example files"""
    from pathlib import Path
    
    console.print("[bold cyan]🧪 Testing All Examples[/bold cyan]\n")
    
    examples_dir = Path("examples")
    files = list(examples_dir.rglob("*.sol")) + \
            list(examples_dir.rglob("*.py")) + \
            list(examples_dir.rglob("*.js"))
    
    results = []
    for filepath in files:
        console.print(f"\n📄 Testing: [cyan]{filepath}[/cyan]")
        try:
            result = analyze_file(str(filepath))
            results.append({'file': str(filepath), 'success': True})
        except Exception as e:
            console.print(f"[red]❌ Failed: {e}[/red]")
            results.append({'file': str(filepath), 'success': False})
    
    # Summary
    passed = sum(1 for r in results if r['success'])
    console.print(f"\n\n✅ Passed: {passed}/{len(results)}")

def main():
    """Main CLI entry point"""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    # Add test flag
    if sys.argv[1] == '--test-examples':
        test_all_examples()
        return
    
    filepath = sys.argv[1]
    
    # Check if file exists
    if not Path(filepath).exists():
        console.print(f"[red]❌ Error: File not found: {filepath}[/red]")
        sys.exit(1)
    
    # Parse optional arguments
    language = None
    model = None
    detailed = False
    
    if '--language' in sys.argv:
        idx = sys.argv.index('--language')
        if idx + 1 < len(sys.argv):
            language = sys.argv[idx + 1]
    
    if '--model' in sys.argv:
        idx = sys.argv.index('--model')
        if idx + 1 < len(sys.argv):
            model = sys.argv[idx + 1]
    
    if '--detailed' in sys.argv:
        detailed = True
    
    # Run analysis
    try:
        analyze_file(filepath, language=language, model=model, detailed=detailed)
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Analysis interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Unexpected error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()