"""Reproduce the scenario matrix; writes only synthetic experiment results."""
import json
import platform
from pathlib import Path
from lab import experiment

if __name__ == '__main__':
    output = {'python': platform.python_version(), 'platform': platform.platform(),
              'runs': [experiment(scenario, 120, seed)
                       for scenario in ('mixed', 'mostly-legitimate', 'bot-heavy')
                       for seed in (42, 7, 101)]}
    path = Path(__file__).parent / 'results' / 'scenarios.json'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(output, indent=2) + '\n')
    print(path)
