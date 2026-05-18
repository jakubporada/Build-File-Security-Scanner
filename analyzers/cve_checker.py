import subprocess
import json
import re

class CVEChecker:
    def __init__(self):
        self.known_vulnerable = {
            'flask': [
                (['2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4', '2.2.5'], 'CVE-2023-30861', 'Cookie parsing vulnerability leading to possible session hijacking'),
                (['0.12.0', '0.12.1', '0.12.2', '0.12.3'], 'CVE-2018-1000656', 'Denial of service in JSON decoder'),
                (['0.10.0', '0.10.1'], 'CVE-2019-1010083', 'Improper input validation in development server')
            ],
            'requests': [
                (['2.3.0'], 'CVE-2014-1829', 'Cookie handling vulnerability allowing session fixation'),
                (['2.6.0', '2.5.3', '2.5.2', '2.5.1'], 'CVE-2015-2296', 'Header injection vulnerability'),
                (['2.25.0', '2.25.1'], 'CVE-2021-33503', 'CRLF injection in HTTP headers')
            ],
            'django': [
                (['2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4'], 'CVE-2019-12781', 'SQL injection vulnerability in Query.order_by()'),
                (['3.0.0', '3.0.1', '3.0.2'], 'CVE-2020-9402', 'Potential SQL injection via tolerance parameter'),
                (['2.2.13', '3.0.7'], 'CVE-2020-13596', 'XSS vulnerability in admin ForeignKeyRawIdWidget'),
                (['3.1.0', '3.1.1'], 'CVE-2020-24583', 'Incorrect permission checking in file uploads')
            ],
            'pyyaml': [
                (['3.12', '3.13', '5.1', '5.1.1', '5.1.2', '5.2'], 'CVE-2020-1747', 'Arbitrary code execution via yaml.load()'),
                (['5.3', '5.3.1'], 'CVE-2020-14343', 'Arbitrary command execution via FullLoader')
            ],
            'jinja2': [
                (['2.10', '2.10.1', '2.10.2', '2.10.3'], 'CVE-2019-10906', 'Sandbox escape vulnerability'),
                (['2.11.0', '2.11.1', '2.11.2', '2.11.3'], 'CVE-2020-28493', 'ReDoS vulnerability in urlize filter')
            ],
            'pillow': [
                (['8.1.0', '8.1.1', '8.1.2'], 'CVE-2021-25287', 'Out-of-bounds write in libImaging'),
                (['8.2.0'], 'CVE-2021-25288', 'Buffer overflow in Convert.c'),
                (['7.1.0', '7.1.1', '7.1.2'], 'CVE-2020-10177', 'Multiple buffer overflows in libImaging')
            ],
            'urllib3': [
                (['1.24.1', '1.24.2'], 'CVE-2019-11324', 'Certificate verification bypass'),
                (['1.25.2', '1.25.3'], 'CVE-2019-11236', 'CRLF injection in request parameter'),
                (['1.26.0', '1.26.1', '1.26.2', '1.26.3', '1.26.4'], 'CVE-2021-33503', 'Catastrophic backtracking in URL parsing')
            ],
            'cryptography': [
                (['3.3', '3.3.1', '3.3.2'], 'CVE-2020-36242', 'Improper input validation in Fernet symmetric encryption'),
                (['2.9', '2.9.1', '2.9.2'], 'CVE-2020-25659', 'Bleichenbacher timing attack in RSA decryption')
            ],
            'numpy': [
                (['1.19.0', '1.19.1', '1.19.2'], 'CVE-2021-33430', 'Buffer overflow in PyArray_NewFromDescr_int'),
                (['1.16.0', '1.16.1', '1.16.2', '1.16.3', '1.16.4'], 'CVE-2019-6446', 'Crafted serialized object causes excessive memory allocation')
            ],
            'tensorflow': [
                (['2.5.0', '2.5.1'], 'CVE-2021-37678', 'Heap buffer overflow in QuantizedResizeBilinear'),
                (['2.4.0', '2.4.1', '2.4.2'], 'CVE-2021-29512', 'Division by zero in TFLite operations')
            ],
            'pycryptodome': [
                (['3.9.0', '3.9.1', '3.9.2', '3.9.3', '3.9.4'], 'CVE-2018-15560', 'Timing attack vulnerability in RSA decryption')
            ],
            'ansible': [
                (['2.9.0', '2.9.1', '2.9.2'], 'CVE-2020-1733', 'Insecure temporary file creation'),
                (['2.8.0', '2.8.1', '2.8.2'], 'CVE-2019-10156', 'Unsafe variable substitution')
            ],
            'sqlalchemy': [
                (['1.4.0', '1.4.1', '1.4.2'], 'CVE-2019-7164', 'SQL injection via group_by parameter'),
                (['1.3.0', '1.3.1'], 'CVE-2019-7548', 'SQL injection in order_by clause')
            ],
            'werkzeug': [
                (['0.15.0', '0.15.1', '0.15.2', '0.15.3'], 'CVE-2019-14806', 'Insufficient debugger PIN security'),
                (['1.0.0', '1.0.1'], 'CVE-2020-28724', 'Directory traversal via SharedDataMiddleware')
            ],
            'twisted': [
                (['20.3.0'], 'CVE-2020-10108', 'HTTP request smuggling'),
                (['19.10.0'], 'CVE-2020-10109', 'Cookie and authorization headers exposed')
            ],
            'paramiko': [
                (['2.6.0', '2.7.0', '2.7.1'], 'CVE-2022-24302', 'Race condition in SSH authentication'),
                (['2.4.0', '2.4.1'], 'CVE-2018-1000805', 'Authentication bypass vulnerability')
            ],
            'scrapy': [
                (['2.4.0', '2.4.1'], 'CVE-2021-41125', 'Cookie exposure vulnerability'),
                (['2.3.0'], 'CVE-2020-24583', 'Path traversal in file downloads')
            ],
            'httplib2': [
                (['0.18.0', '0.18.1'], 'CVE-2021-21240', 'CRLF injection vulnerability'),
                (['0.17.0', '0.17.1', '0.17.2'], 'CVE-2020-11078', 'Improper certificate validation')
            ],
            'aiohttp': [
                (['3.7.0', '3.7.1', '3.7.2'], 'CVE-2021-21330', 'Open redirect vulnerability'),
                (['3.6.0', '3.6.1', '3.6.2'], 'CVE-2020-15137', 'HTTP header injection')
            ]
        }
    
    def check_package(self, package_name, version):
        issues = []
        package_lower = package_name.lower()
        if package_lower not in self.known_vulnerable:
            return issues
        for vuln_versions, cve_id, description in self.known_vulnerable[package_lower]:
            if version and version in vuln_versions:
                issues.append({
                    'cve_id': cve_id,
                    'description': description,
                    'vulnerable_version': version,
                    'package': package_name
                })
        return issues
    
    def check_version_range(self, package_name, operator, version):
        warnings = []
        package_lower = package_name.lower()
        if package_lower not in self.known_vulnerable:
            return warnings
        if operator in ['>=', '>']:
            issues = self.check_package(package_name, version)
            if issues:
                warnings.append({
                    'type': 'version_range_warning',
                    'package': package_name,
                    'operator': operator,
                    'version': version,
                    'message': f'Version range {operator}{version} may include vulnerable versions'
                })
        return warnings
    
    def check_all_packages(self, dependencies):
        results = {
            'total_checked': 0,
            'vulnerable_packages': [],
            'total_vulnerabilities': 0,
            'warnings': []
        }
        for dep in dependencies:
            if dep.get('is_editable'):
                continue
            package = dep['package']
            version = dep.get('version', '').strip() if dep.get('version') else None
            operator = dep.get('operator')
            results['total_checked'] += 1
            if not version:
                continue
            vulns = self.check_package(package, version)
            if vulns:
                results['vulnerable_packages'].append({
                    'package': package,
                    'version': version,
                    'line_number': dep['line_number'],
                    'vulnerabilities': vulns
                })
                results['total_vulnerabilities'] += len(vulns)
            if operator:
                warnings = self.check_version_range(package, operator, version)
                results['warnings'].extend(warnings)
        return results
    
    def try_safety_check(self, requirements_file):
        try:
            result = subprocess.run(
                ['safety', 'check', '--file', requirements_file, '--json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 or result.returncode == 64:
                try:
                    safety_data = json.loads(result.stdout)
                    return self._parse_safety_output(safety_data)
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
    
    def _parse_safety_output(self, safety_data):
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
    
    def get_database_stats(self):
        total_packages = len(self.known_vulnerable)
        total_cves = sum(len(vulns) for vulns in self.known_vulnerable.values())
        return {
            'total_packages_tracked': total_packages,
            'total_cves': total_cves,
            'packages': list(self.known_vulnerable.keys())
        }