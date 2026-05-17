"""
Security Analyzer
Detects suspicious patterns and security issues in build files
"""

import re

class SecurityAnalyzer:
    def __init__(self):
        self.patterns = {
            'shell_injection': {
                'regex': r'curl.*\|.*sh|wget.*\|.*sh',
                'description': 'Command pipes downloaded content directly to shell',
                'severity': 'critical'
            },
            'stealth_download': {
                'regex': r'wget.*&&.*chmod\s+\+x|curl.*&&.*chmod\s+\+x',
                'description': 'Downloads file and makes it executable',
                'severity': 'high'
            },
            'obfuscation': {
                'regex': r'base64.*-d|base64.*--decode|eval\s*\(',
                'description': 'Uses obfuscation techniques (base64 decode or eval)',
                'severity': 'high'
            },
            'tmp_execution': {
                'regex': r'/tmp/[^\s]*&&.*chmod|/tmp/[^\s]*&&.*\./|mktemp.*&&.*chmod',
                'description': 'Creates and executes files in /tmp directory',
                'severity': 'medium'
            },
            'remote_exec': {
                'regex': r'bash\s*<\s*\(curl|sh\s*<\s*\(wget',
                'description': 'Executes remote script without saving locally',
                'severity': 'critical'
            },
            'suspicious_download': {
                'regex': r'curl.*-s.*http[s]?://|wget.*-q.*http[s]?://',
                'description': 'Silent download from remote URL (may hide activity)',
                'severity': 'medium'
            },
            'hidden_file': {
                'regex': r'\s\.[a-zA-Z0-9_]+=|>>\s*\.[a-zA-Z0-9_]+|>\s*\.[a-zA-Z0-9_]+',
                'description': 'Writes to hidden file (starts with dot)',
                'severity': 'low'
            },
            'network_access': {
                'regex': r'nc\s+-|ncat\s|netcat\s',
                'description': 'Uses netcat for network connections',
                'severity': 'medium'
            }
        }

    def analyze(self, parsed_data):
        """Analyze parsed build data for security issues"""
        issues = []
        for target_name, target_info in parsed_data.get('targets', {}).items():
            for cmd_idx, cmd_info in enumerate(target_info['commands']):
                command = cmd_info['command']
                for pattern_name, pattern_info in self.patterns.items():
                    if re.search(pattern_info['regex'], command, re.IGNORECASE):
                        issues.append({
                            'type': pattern_name,
                            'severity': pattern_info['severity'],
                            'description': pattern_info['description'],
                            'target': target_name,
                            'command_num': cmd_idx + 1,
                            'command': command,
                            'line_number': cmd_info['line_number']
                        })
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        issues.sort(key=lambda x: severity_order.get(x['severity'], 999))
        return {
            'issues': issues,
            'total_issues': len(issues),
            'critical_count': sum(1 for i in issues if i['severity'] == 'critical'),
            'high_count': sum(1 for i in issues if i['severity'] == 'high'),
            'medium_count': sum(1 for i in issues if i['severity'] == 'medium'),
            'low_count': sum(1 for i in issues if i['severity'] == 'low')
        }

    def add_custom_pattern(self, name, regex, description, severity='medium'):
        """Allow users to add their own suspicious patterns"""
        self.patterns[name] = {
            'regex': regex,
            'description': description,
            'severity': severity
        }