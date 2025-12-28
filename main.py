import os
import re
import datetime
from concurrent.futures import ThreadPoolExecutor
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import questionary

console = Console()

# --- THE "NO COUNTER" BANNER ---
ASCII_ART = """
[bold #7dcfff]
███████╗ ██████╗    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██║         ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     ███████╗██║     ███████║██╔██╗ ██║
╚════██║██║         ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      ╚════██║██║     ██╔══██║██║╚██╗██║
███████║╚██████╗    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                                                        
[/bold #7dcfff]
[bold #bb9af7]  > Laravel Security Code Scan - Yuichiro  <[/bold #bb9af7]
[bold #565f89]       [ EXPERT MODE: SEMANTIC & REMEDIATION ACTIVE ] [/bold #565f89]
"""

# --- SEMANTIC RULES & DATABASE ---
RULES = {
    "SQL Injection (Critical)": {
        "patterns": [r"DB::raw\(", r"whereRaw\(", r"orderByRaw\(", r"DB::select\("],
        "severity": "CRITICAL",
        "desc": "Raw query detected. Potential SQLi if variables are not bound.",
        "fix": "Use parameter binding: whereRaw('id = ?', [$id])",
        "remediation": "1. Never concatenate user input directly into queries.\n2. Use Eloquent methods where possible.\n3. If raw SQL is needed, use '?' placeholders."
    },
    "Remote Code Execution (Critical)": {
        "patterns": [r"eval\(", r"shell_exec\(", r"unserialize\(", r"system\("],
        "severity": "CRITICAL",
        "desc": "Dangerous PHP function execution detected.",
        "fix": "Avoid these functions or use strict allow-lists.",
        "remediation": "1. Use built-in Laravel APIs instead of system calls.\n2. Never pass user input to unserialize(). Use JSON instead."
    },
    "Mass Assignment (High)": {
        "patterns": [r"\$guarded\s*=\s*\[\s*\]"],
        "severity": "HIGH",
        "desc": "Empty $guarded allows all fields to be written (Overposting).",
        "fix": "Use $fillable to whitelist fields.",
        "remediation": "1. Switch from $guarded to $fillable.\n2. If using $guarded, ensure it contains sensitive fields like 'is_admin'."
    },
    "Broken Access Control (High)": {
        "patterns": [r"public\s+function\s+\w+\(.*\)\s*\{"],
        "severity": "HIGH",
        "desc": "Semantic Check: Method lacks $this->authorize() call.",
        "fix": "Add Policy check inside the method.",
        "remediation": "1. Implement Laravel Policies.\n2. Call $this->authorize('update', $model) at the start of controller methods."
    },
    "Sensitive Data Leakage (High)": {
        "patterns": [r"APP_DEBUG=true", r"DB_PASSWORD=\w+", r"AWS_SECRET"],
        "severity": "HIGH",
        "desc": "Credentials or Debug mode exposed in config.",
        "fix": "Set APP_DEBUG=false and use Environment Variables.",
        "remediation": "1. Ensure .env is in .gitignore.\n2. Use Laravel Vault or Secret Manager for production."
    }
}

# --- REMEDIATION CHEATSHEET DATA ---
# --- REMEDIATION CHEATSHEET DATA (SAFE TEXT VERSION) ---
CHEATSHEET = [
    ("XSS Prevention", "Gunakan {{ $data }} sebagai ganti {!! $data !!}. Gunakan Blade components untuk auto-escaping."),
    ("CSRF Protection", "Selalu gunakan @csrf di dalam form. Jangan matikan middleware VerifyCsrfToken secara global."),
    ("Session Security", "Atur SESSION_SECURE_COOKIE=true dan SESSION_HTTP_ONLY=true di file .env."),
    ("Mass Assignment", "Lebih baik gunakan $fillable daripada $guarded. Hindari Request::all() pada method create."),
    ("API Security", "Gunakan Sanctum atau Passport. Jangan ekspos ID internal; gunakan UUID untuk resource publik.")
]
class PDFReport(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 16)
        self.set_text_color(33, 150, 243)
        self.write(10, 'YUICHIRO ADVANCED SECURITY AUDIT\n')
        self.set_font('helvetica', 'I', 10)
        self.set_text_color(100, 100, 100)
        self.write(5, 'Strict Semantic Analysis & Remediation Report\n')
        self.write(5, '=' * 95 + '\n')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.write(10, f'Confidential - Yuichiro Security | Page {self.page_no()}')

def generate_pdf(results, target_dir):
    pdf = PDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # 1. SCAN SUMMARY
    pdf.set_font("helvetica", 'B', 14)
    pdf.write(10, "1. SCAN SUMMARY\n")
    pdf.set_font("helvetica", '', 10)
    pdf.write(7, f"Project Target  : {target_dir}\n")
    pdf.write(7, f"Timestamp       : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    pdf.write(7, f"Total Findings  : {len(results)} issues detected\n")
    pdf.write(7, "-" * 50 + "\n\n")

    # 2. DETAILED FINDINGS
    pdf.set_font("helvetica", 'B', 14)
    pdf.write(10, "2. DETAILED FINDINGS AND ANALYSIS\n\n")

    for i, item in enumerate(results, 1):
        # Header Masalah
        pdf.set_font("helvetica", 'B', 11)
        # Warna teks manual untuk Severity
        if item['severity'] == "CRITICAL": pdf.set_text_color(200, 0, 0)
        elif item['severity'] == "HIGH": pdf.set_text_color(255, 69, 0)
        else: pdf.set_text_color(0, 0, 0)
        
        pdf.write(8, f"FINDING #{i}: [{item['severity']}] {item['type']}\n")
        
        # Detail Tanpa Tabel
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("helvetica", '', 10)
        pdf.write(6, f"   Location    : {item['file']} (Line {item['line']})\n")
        pdf.write(6, f"   Description : {item['desc']}\n")
        
        # Remediation
        pdf.set_font("helvetica", 'B', 10)
        pdf.set_text_color(0, 100, 0)
        pdf.write(6, "   REMEDIATION STEPS:\n")
        pdf.set_font("helvetica", '', 9)
        # Pastikan teks pembersihan tidak mengandung karakter non-ascii
        pdf.write(5, f"   {item['remediation']}\n")
        
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)
        pdf.write(5, "=" * 80 + "\n\n")

    # 3. EXPERT CHEATSHEET (SAFE SYMBOLS)
    pdf.add_page()
    pdf.set_font("helvetica", 'B', 14)
    pdf.set_text_color(33, 150, 243)
    pdf.write(10, "3. SECURITY RESEARCHER CHEATSHEET\n")
    pdf.ln(5)
    
    pdf.set_text_color(0, 0, 0)
    for title, content in CHEATSHEET:
        pdf.set_font("helvetica", 'B', 11)
        # Menggunakan '-' sebagai pengganti bullet point agar tidak error encoding
        pdf.write(8, f"- {title}\n")
        pdf.set_font("helvetica", '', 10)
        pdf.write(6, f"  {content}\n\n")

    report_name = f"Audit_Report_{datetime.datetime.now().strftime('%H%M%S')}.pdf"
    pdf.output(report_name)
    return report_name

def scan_file(file_info):
    file_path, target_dir = file_info
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            content_full = "".join(lines)
            
            for rule_name, data in RULES.items():
                for pattern in data['patterns']:
                    for match in re.finditer(pattern, content_full, re.IGNORECASE | re.MULTILINE):
                        line_num = content_full.count('\n', 0, match.start()) + 1
                        
                        # --- SEMANTIC LOGIC: PROXIMITY CHECK ---
                        # Jika ini method controller, cek apakah ada 'authorize' dalam 5 baris kedepan
                        is_false_positive = False
                        if "public function" in pattern:
                            context = "".join(lines[line_num:line_num+5])
                            if "authorize" in context or "Gate::" in context:
                                is_false_positive = True
                        
                        if not is_false_positive:
                            line_content = lines[line_num-1].strip() if line_num <= len(lines) else "N/A"
                            findings.append({
                                "file": os.path.relpath(file_path, target_dir),
                                "line": line_num,
                                "type": rule_name,
                                "severity": data['severity'],
                                "content": line_content,
                                "desc": data['desc'],
                                "remediation": data['remediation']
                            })
    except: pass
    return findings

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel(ASCII_ART, border_style="#7aa2f7", expand=False))
    
    target_dir = questionary.path("Target Laravel Directory:").ask()
    if not target_dir: return

    files_to_scan = []
    exclude = ["vendor", "node_modules", "storage", ".git", "public", "tests"]
    for root, _, files in os.walk(target_dir):
        if any(x in root for x in exclude): continue
        for file in files:
            if file.endswith(('.php', '.blade.php', '.env')):
                files_to_scan.append((os.path.join(root, file), target_dir))

    all_findings = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]Deep Semantic Audit...", total=len(files_to_scan))
        
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = [executor.submit(scan_file, f) for f in files_to_scan]
            for future in futures:
                res = future.result()
                if res: all_findings.extend(res)
                progress.update(task, advance=1)

    if not all_findings:
        console.print(Panel("[bold green]✅ SYSTEM SECURE: No critical semantic flaws found.[/bold green]"))
    else:
        table = Table(title="Critical Semantic Issues Found", show_lines=True)
        table.add_column("Severity", justify="center")
        table.add_column("Issue Type")
        table.add_column("Location")
        
        for f in all_findings:
            color = "red" if f['severity'] in ['CRITICAL', 'HIGH'] else "yellow"
            table.add_row(f"[{color}]{f['severity']}[/{color}]", f['type'], f"{f['file']}:{f['line']}")
        
        console.print(table)

        if questionary.confirm("Generate Expert PDF Report with Remediation?").ask():
            report_path = generate_pdf(all_findings, target_dir)
            console.print(f"[bold green]✔ Report Generated: {report_path}[/bold green]")

if __name__ == "__main__":
    main()