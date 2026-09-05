#!/usr/bin/env python3
"""Create a source-only publication snapshot; never include Git history or credentials."""
import argparse
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = ('README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'LICENSE', '.gitignore', '.gitattributes', 'prepare-package.command')
DIRECTORIES = ('agent', 'mcp-server', 'rendezvous', 'target-windows', 'scripts', 'docs', '.github')
SKIP_DIRS = {'.git', 'node_modules', 'dist', '.wrangler', '__pycache__', '.relay-session', 'release'}
EXCLUDE = {'operator.json', 'rendezvous.json', 'worker-configuration.d.ts', 'worker-secrets.json', 'mcp-config.json'}
EXTENSIONS = {'.go', '.mod', '.sum', '.sh', '.ts', '.mjs', '.json', '.jsonc', '.yaml', '.yml', '.ps1', '.cmd', '.txt', '.md', '.py'}

def allowed(p):
    n = p.name
    return (n not in EXCLUDE and not n.startswith(('secrets', '.env', '.dev.vars'))
            and '.local.' not in n and (p.suffix in EXTENSIONS or n == '.gitignore'))

def candidates(root=ROOT):
    result = []
    for name in ROOT_FILES:
        p = root / name
        if p.is_symlink():
            raise ValueError('Source symlinks are not exported.')
        if p.is_file():
            result.append(p)
    for name in DIRECTORIES:
        base = root / name
        if base.is_symlink():
            raise ValueError('Source directories must not be symlinks.')
        if not base.exists():
            continue
        for current, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for d in dirs:
                if (Path(current) / d).is_symlink():
                    raise ValueError('Source directory symlinks are not exported.')
            for n in sorted(files):
                p = Path(current) / n
                if allowed(p):
                    if p.is_symlink():
                        raise ValueError('Source symlinks are not exported.')
                    result.append(p)
    return sorted(set(result))

def export(destination, root=ROOT):
    destination = Path(destination).absolute()
    for parent in (destination, *destination.parents):
        if parent.is_symlink():
            raise ValueError('Export paths must not contain symlinks.')
    if destination.exists():
        raise ValueError('The export destination must not already exist.')
    files = candidates(root)
    # Select before creating the destination: the snapshot cannot include itself.
    destination.mkdir(parents=True)
    for source in files:
        target = destination / source.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return len(files)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'release' / 'source' / 'mcp-windows-remote-shell')
    args = parser.parse_args()
    try:
        count = export(args.output)
        print(f'Exported {count} source files to {args.output}')
        print('No Git history, runtime credentials, dependencies, logs, or executables were included.')
        print('Review the snapshot and its license before publishing.')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Source export failed: {error}\n')
