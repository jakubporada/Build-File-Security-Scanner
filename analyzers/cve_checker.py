"""
CVE Checker
Checks packages against known vulnerability databases
"""

import subprocess
import json
import re

class CVEChecker:
    def __init__(self):
        self.known_vulnerable = {
            # Hardcoded list of known vulnerable packages for offline checking
            # Format: package_name: [(vulnerable_versions, cve_id, description)]
            'flask': [
                (['2.2.0', '2.2.1', '2.2.2'], 'CVE-2023-30861', 'Cookie parsing vulnerability'),
                (['0.12.0', '0.12.1', '0.12.2'], 'CVE-2018-1000656', 'Denial of service in JSON decoder')
            ],
            'requests': [
                (['2.3.0'], 'CVE-2014-1829', 'Cookie handling vulnerability'),
                (['2.6.0', '2.5.3'], 'CVE-2015-2296', 'Header injection vulnerability')
            ],
            'django': [
                (['2.2.0', '2.2.1', '2.2.2'], 'CVE-2019-12781', 'SQL injection vulnerability'),
                (['3.0.0', '3.0.1'], 'CVE-2020-9402', 'Potential SQL injection')
            ],
            'pyyaml': [
                (['3.12', '3.13', '5.1', '5.2'], 'CVE-2020-1747', 'Arbitrary code execution via yaml.load')
            ],
            'jinja2': [
                (['2.10', '2.10.1'], 'CVE-2019-10906', 'Sandbox escape vulnerability')
            ],
            'pillow': [
                (['8.1.0', '8.1.1'], 'CVE-2021-25287', 'Out-of-bounds write in libImaging')
            ],
            'urllib3': [
                (['1.24.1'], 'CVE-2019-11324', 'Certificate verification bypass')
            ],
            'cryptography': [
                (['3.3', '3.3.1'], 'CVE-2020-36242', 'Improper input validation')
            ]
        }
    
    def check_package(self, package_name, version):
        """
        Check if a specific package version has known vulnerabilities
        Returns list of CVE issues found
        """
        issues = []
        package_lower = package_name.lower()
        
        if package_lower not in self.known_vulnerable:
            return issues
        
        # Check against known vulnerable versions
        for vuln_versions, cve_id, description in self.known_vulnerable[package_lower]:
            if version and version in vuln_versions:
                issues.append({
                    'cve_id': cve_id,
                    'description': description,
                    'vulnerable_version': version,
                    'package': package_name
                })
        
        return issues
    
    def check_all_packages(self, dependencies):
        """
        Check all packages in a dependency list
        Returns dictionary with vulnerability info
        """
        results = {
            'total_checked': 0,
            'vulnerable_packages': [],
            'total_vulnerabilities': 0
        }
        
        for dep in dependencies:
            if dep.get('is_editable'):
                continue
            
            package = dep['package']
            version = dep.get('version', '').strip() if dep.get('version') else None
            
            results['total_checked'] += 1
            
            if not version:
                continue
            
            # Check for vulnerabilities
            vulns = self.check_package(package, version)
            
            if vulns:
                results['vulnerable_packages'].append({
                    'package': package,
                    'version': version,
                    'line_number': dep['line_number'],
                    'vulnerabilities': vulns
                })
                results['total_vulnerabilities'] += len(vulns)
        
        return results
    
    def try_safety_check(self, requirements_file):
        """
        Try to use 'safety' CLI tool if available for real-time CVE checking
        Falls back to hardcoded database if safety is not installed
        """
        try:
            result = subprocess.run(
                ['safety', 'check', '--file', requirements_file, '--json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 or result.returncode == 64:  # 64 means vulnerabilities found
                try:
                    safety_data = json.loads(result.stdout)
                    return self._parse_safety_output(safety_data)
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _parse_safety_output(self, safety_data):
        """Parse the JSON output from safety CLI"""
        results = {
            'total_checked': 0,
            'vulnerable_packages': [],
            'total_vulnerabilities': 0
        }
        
        if isinstance(safety_data, list):
            for vuln in safety_data:
                pkg_name = vuln.get('package', 'unknown')
                version = vuln.get('installed_version', 'unknown')
                cve = vuln.get('cve', 'N/A')
                description = vuln.get('advisory', 'No description')
                
                results['vulnerable_packages'].append({
                    'package': pkg_name,
                    'version': version,
                    'vulnerabilities': [{
                        'cve_id': cve,
                        'description': description,
                        'vulnerable_version': version
                    }]
                })
                results['total_vulnerabilities'] += 1
        
        return results