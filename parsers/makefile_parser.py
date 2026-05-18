import re
from pathlib import Path

class MakefileParser:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.targets = {}
        self.variables = {}

    def parse(self):
        with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        current_target = None
        total_commands = 0
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.strip().startswith('#') or not line.strip():
                i += 1
                continue
            while line.rstrip().endswith('\\') and i + 1 < len(lines):
                line = line.rstrip()[:-1] + ' ' + lines[i + 1].lstrip()
                i += 1
            var_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*[:+?]?=\s*(.*)$', line)
            if var_match:
                var_name = var_match.group(1)
                var_value = var_match.group(2).strip()
                self.variables[var_name] = var_value
                i += 1
                continue
            target_match = re.match(r'^([^:\s]+)\s*:\s*(.*)$', line)
            if target_match and not line.startswith('\t'):
                target_name = target_match.group(1).strip()
                dependencies = target_match.group(2).strip()
                deps = [d.strip() for d in dependencies.split() if d.strip()]
                current_target = target_name
                self.targets[target_name] = {
                    'dependencies': deps,
                    'commands': [],
                    'line_number': i + 1
                }
                i += 1
                continue
            if line.startswith('\t') and current_target:
                command = line[1:].rstrip()
                if command:
                    self.targets[current_target]['commands'].append({
                        'command': command,
                        'line_number': i + 1
                    })
                    total_commands += 1
            i += 1
        return {
            'targets': self.targets,
            'variables': self.variables,
            'total_commands': total_commands,
            'file_path': str(self.filepath)
        }

    def expand_variables(self, text):
        for var_name, var_value in self.variables.items():
            text = text.replace(f'$({var_name})', var_value)
            text = text.replace(f'${{{var_name}}}', var_value)
        return text