"""
Requirements.txt Parser
Extracts Python package dependencies and version specifications
"""

import re
from pathlib import Path

class RequirementsParser:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.pattern = re.compile(r'^([a-zA-Z0-9_\-\.]+)(.*)$')
    
    def parse(self):
        """Parse requirements.txt and extract package information"""
        dependencies = []
        
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            return {
                'dependencies': [],
                'error': f'File not found: {self.filepath}'
            }
        
        for line_num, line in enumerate(lines, 1):
            original_line = line
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('-e') or line.startswith('git+'):
                dependencies.append({
                    'line_number': line_num,
                    'package': 'EDITABLE/GIT',
                    'version_spec': line,
                    'raw_line': original_line.strip(),
                    'is_editable': True
                })
                continue
            
            if line.startswith('-'):
                continue
            
            match = self.pattern.match(line)
            if match:
                package_name = match.group(1)
                version_spec = match.group(2).strip()
                
                dependencies.append({
                    'line_number': line_num,
                    'package': package_name,
                    'version_spec': version_spec if version_spec else '',
                    'raw_line': original_line.strip(),
                    'is_editable': False
                })
        
        return {
            'dependencies': dependencies,
            'total_packages': len(dependencies),
            'file_path': str(self.filepath)
        }
