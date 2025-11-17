#!/usr/bin/env python3
"""
Drana-Infinity Code Audit Script
Performs comprehensive security, performance, and scalability checks
"""

import ast
import re
import os
from pathlib import Path

class CodeAuditor:
    def __init__(self):
        self.issues = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

    def add_issue(self, severity, category, description, line=None, recommendation=None):
        issue = {
            'category': category,
            'description': description,
            'line': line,
            'recommendation': recommendation
        }
        self.issues[severity].append(issue)

    def audit_file(self, filepath):
        with open(filepath, 'r') as f:
            content = f.read()
            lines = content.split('\n')

        print(f"\n{'='*80}")
        print(f"AUDITING: {filepath}")
        print(f"{'='*80}\n")

        # Security checks
        self.check_sql_injection(content, lines)
        self.check_command_injection(content, lines)
        self.check_path_traversal(content, lines)
        self.check_xss(content, lines)
        self.check_secrets(content, lines)

        # Concurrency checks
        self.check_race_conditions(content, lines)
        self.check_thread_safety(content, lines)

        # Error handling
        self.check_error_handling(content, lines)

        # Resource management
        self.check_resource_leaks(content, lines)

        # Scalability
        self.check_scalability_issues(content, lines)

        # Best practices
        self.check_best_practices(content, lines)

    def check_sql_injection(self, content, lines):
        """Check for SQL injection vulnerabilities"""
        print("[SECURITY] Checking SQL injection vulnerabilities...")

        # Check for string formatting in SQL
        sql_format_patterns = [
            r'execute\(["\'].*%s.*["\']',
            r'execute\(["\'].*\+.*["\']',
            r'execute\(f["\'].*{.*}.*["\']'
        ]

        for i, line in enumerate(lines, 1):
            for pattern in sql_format_patterns:
                if re.search(pattern, line):
                    self.add_issue(
                        'critical',
                        'SQL Injection',
                        f'Potential SQL injection vulnerability',
                        i,
                        'Use parameterized queries with ? placeholders'
                    )

        # Check for proper parameterization
        safe_patterns = r'execute\([^,]+,\s*\([^)]+\)\)'
        param_count = len(re.findall(safe_patterns, content))
        print(f"  ✓ Found {param_count} parameterized queries")

    def check_command_injection(self, content, lines):
        """Check for command injection vulnerabilities"""
        print("[SECURITY] Checking command injection vulnerabilities...")

        for i, line in enumerate(lines, 1):
            if 'subprocess.Popen' in line and 'shell=True' in line:
                # Check if user input is used
                if 'request.' in line or 'input(' in line:
                    self.add_issue(
                        'critical',
                        'Command Injection',
                        f'subprocess with shell=True and user input',
                        i,
                        'Sanitize input or use shell=False with list arguments'
                    )
                else:
                    self.add_issue(
                        'medium',
                        'Command Injection',
                        f'subprocess with shell=True (verify input is safe)',
                        i,
                        'Consider using shell=False if possible'
                    )

    def check_path_traversal(self, content, lines):
        """Check for path traversal vulnerabilities"""
        print("[SECURITY] Checking path traversal vulnerabilities...")

        for i, line in enumerate(lines, 1):
            if 'send_from_directory' in line:
                # Check if secure_filename is used
                if 'secure_filename' not in content[:content.index(line) + len(line)]:
                    self.add_issue(
                        'high',
                        'Path Traversal',
                        f'File serving without secure_filename validation',
                        i,
                        'Use werkzeug.utils.secure_filename() on all user-provided filenames'
                    )

    def check_xss(self, content, lines):
        """Check for XSS vulnerabilities"""
        print("[SECURITY] Checking XSS vulnerabilities...")

        # Flask auto-escapes templates by default, but check for render_template_string
        for i, line in enumerate(lines, 1):
            if 'render_template_string' in line:
                self.add_issue(
                    'high',
                    'XSS',
                    f'render_template_string can lead to XSS if not careful',
                    i,
                    'Ensure all user input is escaped'
                )

    def check_secrets(self, content, lines):
        """Check for hardcoded secrets"""
        print("[SECURITY] Checking for hardcoded secrets...")

        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
            (r'secret_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret key'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded token'),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_issue(
                        'high',
                        'Hardcoded Secrets',
                        f'{desc} found',
                        i,
                        'Use environment variables or config files (not in git)'
                    )

    def check_race_conditions(self, content, lines):
        """Check for potential race conditions"""
        print("[CONCURRENCY] Checking race conditions...")

        # Check for TOCTOU issues
        for i, line in enumerate(lines, 1):
            if 'os.path.exists' in line:
                # Check if file operation follows
                if i < len(lines):
                    next_lines = '\n'.join(lines[i:min(i+5, len(lines))])
                    if 'open(' in next_lines or 'os.makedirs' in next_lines:
                        self.add_issue(
                            'medium',
                            'Race Condition',
                            f'Potential TOCTOU (Time-of-check-time-of-use) issue',
                            i,
                            'Use try/except instead of exists() check'
                        )

    def check_thread_safety(self, content, lines):
        """Check thread safety issues"""
        print("[CONCURRENCY] Checking thread safety...")

        # Check for global mutable state without locks
        global_vars = []
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('_') and '=' in line and 'Lock' not in line:
                var_name = line.split('=')[0].strip()
                if var_name not in ['_db_lock']:
                    global_vars.append((var_name, i))

        # Check if these globals are modified without locks
        for var_name, var_line in global_vars:
            for i, line in enumerate(lines, 1):
                if i > var_line and var_name in line and '=' in line:
                    if 'with' not in line and '_lock' not in line:
                        self.add_issue(
                            'high',
                            'Thread Safety',
                            f'Global variable {var_name} modified without lock',
                            i,
                            'Use threading.Lock() for all shared mutable state'
                        )

    def check_error_handling(self, content, lines):
        """Check error handling"""
        print("[ERROR HANDLING] Checking error handling...")

        # Check for bare except
        for i, line in enumerate(lines, 1):
            if re.match(r'\s*except\s*:', line):
                self.add_issue(
                    'medium',
                    'Error Handling',
                    f'Bare except clause catches all exceptions',
                    i,
                    'Catch specific exceptions instead of bare except:'
                )

        # Check for pass in except
        for i, line in enumerate(lines, 1):
            if 'except' in line and i < len(lines):
                if 'pass' in lines[i].strip():
                    self.add_issue(
                        'low',
                        'Error Handling',
                        f'Silent exception handling',
                        i,
                        'Log errors instead of silently passing'
                    )

    def check_resource_leaks(self, content, lines):
        """Check for resource leaks"""
        print("[RESOURCES] Checking resource leaks...")

        # Check for file opens without with statement
        for i, line in enumerate(lines, 1):
            if 'open(' in line and 'with' not in line:
                self.add_issue(
                    'medium',
                    'Resource Leak',
                    f'File opened without context manager',
                    i,
                    'Use "with open(...) as f:" to ensure file is closed'
                )

    def check_scalability_issues(self, content, lines):
        """Check for scalability issues"""
        print("[SCALABILITY] Checking scalability issues...")

        # Check for fetchall() on potentially large result sets
        for i, line in enumerate(lines, 1):
            if 'fetchall()' in line:
                self.add_issue(
                    'low',
                    'Scalability',
                    f'fetchall() loads all results into memory',
                    i,
                    'Consider pagination for large result sets'
                )

        # Check for N+1 query patterns
        for i, line in enumerate(lines, 1):
            if 'for' in line and 'in' in line:
                if i < len(lines) - 2:
                    next_lines = '\n'.join(lines[i:i+3])
                    if 'execute(' in next_lines and 'SELECT' in next_lines.upper():
                        self.add_issue(
                            'medium',
                            'Scalability',
                            f'Potential N+1 query problem',
                            i,
                            'Consider using JOINs or batch queries'
                        )

    def check_best_practices(self, content, lines):
        """Check for best practices"""
        print("[BEST PRACTICES] Checking code quality...")

        # Check for print() statements (should use logging)
        print_count = 0
        for i, line in enumerate(lines, 1):
            if re.match(r'\s*print\s*\(', line) and 'if __name__' not in content[max(0, content.index(line)-200):content.index(line)]:
                print_count += 1

        if print_count > 5:
            self.add_issue(
                'low',
                'Best Practices',
                f'Using print() instead of logging ({print_count} instances)',
                None,
                'Use Python logging module for production code'
            )

    def generate_report(self):
        """Generate audit report"""
        print(f"\n\n{'='*80}")
        print("AUDIT REPORT")
        print(f"{'='*80}\n")

        total_issues = sum(len(issues) for issues in self.issues.values())

        print(f"Total Issues Found: {total_issues}\n")

        severity_colors = {
            'critical': '🔴 CRITICAL',
            'high': '🟠 HIGH',
            'medium': '🟡 MEDIUM',
            'low': '🔵 LOW',
            'info': '⚪ INFO'
        }

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            issues = self.issues[severity]
            if issues:
                print(f"\n{severity_colors[severity]} ({len(issues)} issues)")
                print("-" * 80)

                for issue in issues:
                    print(f"\n  Category: {issue['category']}")
                    if issue['line']:
                        print(f"  Line: {issue['line']}")
                    print(f"  Issue: {issue['description']}")
                    if issue['recommendation']:
                        print(f"  Fix: {issue['recommendation']}")

        # Overall assessment
        print(f"\n\n{'='*80}")
        print("OVERALL ASSESSMENT")
        print(f"{'='*80}\n")

        critical = len(self.issues['critical'])
        high = len(self.issues['high'])
        medium = len(self.issues['medium'])

        if critical > 0:
            grade = "F - CRITICAL ISSUES MUST BE FIXED"
            status = "❌ NOT PRODUCTION READY"
        elif high > 3:
            grade = "D - MULTIPLE HIGH SEVERITY ISSUES"
            status = "⚠️  NOT RECOMMENDED FOR PRODUCTION"
        elif high > 0 or medium > 5:
            grade = "C - NEEDS IMPROVEMENTS"
            status = "⚠️  PRODUCTION USE WITH CAUTION"
        elif medium > 0:
            grade = "B - GOOD WITH MINOR ISSUES"
            status = "✅ PRODUCTION READY WITH MONITORING"
        else:
            grade = "A - EXCELLENT"
            status = "✅ PRODUCTION READY"

        print(f"Grade: {grade}")
        print(f"Status: {status}")

        print(f"\n{'='*80}\n")

        return total_issues

def main():
    auditor = CodeAuditor()

    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║         DRANA-INFINITY CODE AUDIT & SECURITY ANALYSIS         ║
    ╚════════════════════════════════════════════════════════════════╝
    """)

    filepath = '/home/user/Drana-Infinity/drana_infinity.py'

    if os.path.exists(filepath):
        auditor.audit_file(filepath)
        total_issues = auditor.generate_report()

        print("\nRECOMMENDATIONS:")
        print("1. Address all CRITICAL issues immediately")
        print("2. Fix HIGH severity issues before production deployment")
        print("3. Plan to resolve MEDIUM issues in next iteration")
        print("4. Monitor LOW issues for future improvements")
        print("\nFor detailed fixes, see SECURITY_AUDIT.md")

        return total_issues
    else:
        print(f"Error: {filepath} not found")
        return -1

if __name__ == '__main__':
    exit(main())
