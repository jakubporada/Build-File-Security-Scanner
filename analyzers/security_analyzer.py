import json
import re
from pathlib import Path

DEFAULT_PATTERNS = {
    'shell_injection': {
        'regex': r'\b(curl|wget)\b[^|]*\|\s*(sh|bash)\b',
        'description': 'Command pipes downloaded content directly to shell',
        'severity': 'critical'
    },
    'stealth_download': {
        'regex': r'\b(curl|wget)\b[^\n]*&&\s*chmod\s+\+x\b',
        'description': 'Downloads file and makes it executable',
        'severity': 'high'
    },
    'obfuscation': {
        'regex': r'\b(base64\s+(-d|--decode)|eval\s*\()',
        'description': 'Uses obfuscation techniques (base64 decode or eval)',
        'severity': 'high'
    },
    'tmp_execution': {
        'regex': r'/tmp/\S+[^\n]*&&\s*(chmod\s+\+x|\./|/tmp/)',
        'description': 'Creates and executes files in /tmp directory',
        'severity': 'medium'
    },
    'remote_exec': {
        'regex': r'\b(bash|sh)\s*<\s*\(\s*(curl|wget)\b',
        'description': 'Executes remote script without saving locally',
        'severity': 'critical'
    },
    'suspicious_download': {
        'regex': r'\b(curl\s+-s\S*|wget\s+-q\S*)\b[^\n]*https?://',
        'description': 'Silent download from remote URL (may hide activity)',
        'severity': 'medium'
    },
    'hidden_file': {
        'regex': r'(>>|>)\s*\.[\w.-]+|\s\.[\w.-]+=',
        'description': 'Writes to hidden file (starts with dot)',
        'severity': 'low'
    },
    'network_access': {
        'regex': r'\b(nc|ncat|netcat)\b',
        'description': 'Uses netcat for network connections',
        'severity': 'medium'
    }
}

class SecurityAnalyzer:
    def __init__(self, patterns=None, patterns_file=None):
        if patterns is not None:
            self.patterns = self._normalize_patterns(patterns)
        elif patterns_file is not None:
            self.patterns = self._load_patterns_file(patterns_file)
        else:
            self.patterns = self._normalize_patterns(DEFAULT_PATTERNS)

    def _load_patterns_file(self, patterns_file):
        patterns_path = Path(patterns_file)
        data = json.loads(patterns_path.read_text(encoding='utf-8'))
        return self._normalize_patterns(data)

    def _normalize_patterns(self, data):
        if isinstance(data, list):
            normalized = {}
            for item in data:
                name = item.get('name')
                if name:
                    normalized[name] = {
                        'regex': item.get('regex', ''),
                        'description': item.get('description', ''),
                        'severity': item.get('severity', 'medium')
                    }
            return normalized
        if isinstance(data, dict):
            normalized = {}
            for name, item in data.items():
                normalized[name] = {
                    'regex': item.get('regex', ''),
                    'description': item.get('description', ''),
                    'severity': item.get('severity', 'medium')
                }
            return normalized
        return {}

    def analyze(self, parsed_data):
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
        self.patterns[name] = {
            'regex': regex,
            'description': description,
            'severity': severity
        }