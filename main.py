#!/usr/bin/env python3

import argparse
import sys
import subprocess
import tempfile
import shutil
import re
from pathlib import Path
from parsers.makefile_parser import MakefileParser
from parsers.requirements_parser import RequirementsParser
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.cve_checker import CVEChecker

def analyze_makefile(filepath, verbose=False, patterns_file=None):
    print(f" Analyzing Makefile: {filepath}\n")
    parser = MakefileParser(filepath)
    parsed_data = parser.parse()
    analyzer = SecurityAnalyzer(patterns_file=patterns_file)
    results = analyzer.analyze(parsed_data)
    print("="*60)
    print("MAKEFILE SECURITY SCAN REPORT")
    print("="*60)
    print(f"\n[Summary]")
    print(f"   Targets found: {len(parsed_data.get('targets', []))}")
    print(f"   Commands analyzed: {parsed_data.get('total_commands', 0)}")
    print(f"   Security issues: {len(results['issues'])}")
    if results['issues']:
        print(f"\n[Security Issues Found: {len(results['issues'])}]")
        for i, issue in enumerate(results['issues'], 1):
            severity_marker = "[CRITICAL]" if issue['severity'] == 'critical' else "[HIGH]" if issue['severity'] == 'high' else "[MEDIUM]" if issue['severity'] == 'medium' else "[LOW]"
            print(f"\n   Issue #{i} {severity_marker}")
            print(f"   Type: {issue['type']}")
            print(f"   Description: {issue['description']}")
            print(f"   Location: Target '{issue['target']}', Line {issue['line_number']}")
            print(f"   Command: {issue['command'][:80]}...")
    else:
        print("\n[No suspicious patterns detected in Makefile]")
    if verbose:
        print(f"\n[All Targets]")
        for target_name, target_info in parsed_data.get('targets', {}).items():
            print(f"\n   Target: {target_name}")
            if target_info['dependencies']:
                print(f"   Dependencies: {', '.join(target_info['dependencies'])}")
            print(f"   Commands: {len(target_info['commands'])}")

def analyze_requirements(filepath, verbose=False):
    print(f" Analyzing requirements.txt: {filepath}\n")
    parser = RequirementsParser(filepath)
    parsed_data = parser.parse()
    if 'error' in parsed_data:
        print(f"Error: {parsed_data['error']}")
        return
    dependencies = parsed_data['dependencies']
    print(" Checking for known vulnerabilities...")
    cve_checker = CVEChecker()
    cve_results = cve_checker.check_all_packages(dependencies)
    print("="*60)
    print("REQUIREMENTS.TXT SECURITY SCAN REPORT")
    print("="*60)
    print(f"\n[Summary]")
    print(f"   Total packages: {parsed_data['total_packages']}")
    print(f"   Packages checked for CVEs: {cve_results['total_checked']}")
    print(f"   Vulnerable packages: {len(cve_results['vulnerable_packages'])}")
    print(f"   Total vulnerabilities: {cve_results['total_vulnerabilities']}")
    typosquatting_map = {
        'request': 'requests',
        'requets': 'requests',
        'pythonrequest': 'requests',
        'urlib3': 'urllib3',
        'urllib': 'urllib3',
        'beautifulsoup': 'beautifulsoup4',
        'bs': 'beautifulsoup4',
        'nump': 'numpy',
        'numpi': 'numpy',
        'panda': 'pandas',
        'pandsa': 'pandas',
        'pillow': 'PIL',
        'matplot': 'matplotlib',
        'javascrip': 'javascript',
        'telnetlib': 'DANGEROUS',
    }
    issues = []
    for vuln_pkg in cve_results['vulnerable_packages']:
        for vuln in vuln_pkg['vulnerabilities']:
            issues.append({
                'severity': 'critical',
                'type': 'Known Vulnerability (CVE)',
                'package': vuln_pkg['package'],
                'line_number': vuln_pkg.get('line_number', 'N/A'),
                'description': f"{vuln['cve_id']}: {vuln['description']}"
            })
    for dep in dependencies:
        if dep['is_editable']:
            continue
        package = dep['package'].lower()
        if package in typosquatting_map:
            issues.append({
                'severity': 'high',
                'type': 'Possible Typosquatting',
                'package': dep['package'],
                'line_number': dep['line_number'],
                'description': f"'{dep['package']}' looks like a typo of '{typosquatting_map[package]}'"
            })
        if not dep['version_spec']:
            issues.append({
                'severity': 'low',
                'type': 'Unpinned Version',
                'package': dep['package'],
                'line_number': dep['line_number'],
                'description': f"Package '{dep['package']}' has no version specified"
            })
    if issues:
        print(f"\n[Security Issues Found: {len(issues)}]")
        for i, issue in enumerate(issues, 1):
            severity_marker = "[CRITICAL]" if issue['severity'] == 'critical' else "[HIGH]" if issue['severity'] == 'high' else "[MEDIUM]" if issue['severity'] == 'medium' else "[LOW]"
            print(f"\n   Issue #{i} {severity_marker}")
            print(f"   Type: {issue['type']}")
            print(f"   Package: {issue['package']} (Line {issue['line_number']})")
            print(f"   Description: {issue['description']}")
    else:
        print("\n[No security issues detected]")
    if verbose:
        print(f"\n[All Dependencies]")
        for dep in dependencies:
            if dep['is_editable']:
                print(f"\n   {dep['package']}: {dep['version_spec']}")
            else:
                version = dep['version_spec'] if dep['version_spec'] else "any version"
                print(f"\n   {dep['package']}: {version}")

def is_github_url(url):
    github_pattern = r'https?://github\.com/[\w\-]+/[\w\-\.]+'
    return re.match(github_pattern, url) is not None

def clone_github_repo(repo_url, target_dir):
    print(f" Cloning repository: {repo_url}")
    try:
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, target_dir],
            check=True,
            capture_output=True,
            text=True
        )
        print(f" Repository cloned successfully\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f" Failed to clone repository: {e.stderr}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print(" Error: git is not installed. Please install git first.", file=sys.stderr)
        return False

def find_build_files(directory):
    directory = Path(directory)
    makefiles = []
    requirements = []
    for pattern in ['**/Makefile', '**/makefile', '**/GNUmakefile']:
        makefiles.extend(directory.glob(pattern))
    requirements.extend(directory.glob('**/requirements*.txt'))
    return makefiles, requirements

def scan_github_repo(repo_url, verbose=False, patterns_file=None):
    print("="*60)
    print("GITHUB REPOSITORY SECURITY SCAN")
    print("="*60)
    print(f"Repository: {repo_url}\n")
    temp_dir = tempfile.mkdtemp(prefix='file-analyzer-')
    try:
        if not clone_github_repo(repo_url, temp_dir):
            return
        makefiles, requirements = find_build_files(temp_dir)
        print(f" Found {len(makefiles)} Makefile(s) and {len(requirements)} requirements.txt file(s)\n")
        if not makefiles and not requirements:
            print("[!] No build files found in repository")
            return
        total_issues = 0
        if makefiles:
            print("="*60)
            print("SCANNING MAKEFILES")
            print("="*60 + "\n")
            for i, makefile in enumerate(makefiles, 1):
                rel_path = makefile.relative_to(temp_dir)
                print(f"[{i}/{len(makefiles)}] {rel_path}")
                print("-" * 60)
                parser = MakefileParser(makefile)
                parsed_data = parser.parse()
                analyzer = SecurityAnalyzer(patterns_file=patterns_file)
                results = analyzer.analyze(parsed_data)
                if results['issues']:
                    total_issues += len(results['issues'])
                    print(f"    {len(results['issues'])} issue(s) found:")
                    for issue in results['issues']:
                        severity = issue['severity'].upper()
                        print(f"      [{severity}] {issue['type']}: {issue['description']}")
                        print(f"      Target: {issue['target']}, Line: {issue['line_number']}")
                    print()
                else:
                    print(f"   No issues found\n")
        if requirements:
            print("="*60)
            print("SCANNING REQUIREMENTS.TXT FILES")
            print("="*60 + "\n")
            for i, req_file in enumerate(requirements, 1):
                rel_path = req_file.relative_to(temp_dir)
                print(f"[{i}/{len(requirements)}] {rel_path}")
                print("-" * 60)
                parser = RequirementsParser(req_file)
                parsed_data = parser.parse()
                if 'error' in parsed_data:
                    print(f"  Error: {parsed_data['error']}\n")
                    continue
                dependencies = parsed_data['dependencies']
                cve_checker = CVEChecker()
                cve_results = cve_checker.check_all_packages(dependencies)
                typosquatting_map = {
                    'request': 'requests', 'requets': 'requests', 'pythonrequest': 'requests',
                    'urlib3': 'urllib3', 'urllib': 'urllib3',
                    'beautifulsoup': 'beautifulsoup4', 'bs': 'beautifulsoup4',
                    'nump': 'numpy', 'numpi': 'numpy',
                    'panda': 'pandas', 'pandsa': 'pandas',
                }
                file_issues = 0
                for vuln_pkg in cve_results['vulnerable_packages']:
                    for vuln in vuln_pkg['vulnerabilities']:
                        file_issues += 1
                        total_issues += 1
                        print(f"    [CRITICAL] CVE: {vuln_pkg['package']}")
                        print(f"      {vuln['cve_id']}: {vuln['description']}")
                for dep in dependencies:
                    if not dep['is_editable'] and dep['package'].lower() in typosquatting_map:
                        file_issues += 1
                        total_issues += 1
                        print(f"     [HIGH] Typosquatting: {dep['package']}")
                        print(f"      Looks like '{typosquatting_map[dep['package'].lower()]}'")
                if file_issues == 0:
                    print(f"  No issues found")
                print(f"   Packages: {len(dependencies)}, Issues: {file_issues}\n")
        print("="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"   Total files scanned: {len(makefiles) + len(requirements)}")
        print(f"   Total security issues: {total_issues}")
        if total_issues > 0:
            print(f"\n    Repository has security concerns!")
        else:
            print(f"\n   No security issues detected")
    finally:
        print(f"\n Cleaning up temporary files...")
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(" Done\n")

def main():
    parser = argparse.ArgumentParser(
        description='Scan build files for security issues',
        epilog='Examples:\n'
               '  %(prog)s test/Makefile\n'
               '  %(prog)s test/requirements.txt\n'
               '  %(prog)s https://github.com/user/repo\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('file', help='Path to build file or GitHub repository URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--patterns-file', help='Path to JSON file with security patterns')
    args = parser.parse_args()
    if is_github_url(args.file):
        scan_github_repo(args.file, args.verbose, patterns_file=args.patterns_file)
        return
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File '{args.file}' not found", file=sys.stderr)
        sys.exit(1)
    filename = file_path.name.lower()
    if 'makefile' in filename or filename == 'gnumakefile':
        analyze_makefile(file_path, args.verbose, patterns_file=args.patterns_file)
    elif 'requirements' in filename and filename.endswith('.txt'):
        analyze_requirements(file_path, args.verbose)
    else:
        print(f"Error: Unsupported file type '{filename}'", file=sys.stderr)
        print("Supported: Makefile, requirements.txt, or GitHub URL", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()