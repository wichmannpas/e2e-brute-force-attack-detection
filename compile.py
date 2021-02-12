#!/usr/bin/env python3
import re
from argparse import ArgumentParser
from pathlib import Path


def main():
    parser = ArgumentParser()
    parser.add_argument('infiles', nargs='+', type=Path)
    parser.add_argument('--out-dir', type=Path, default=Path('compiled'))
    arguments = parser.parse_args()

    for infile in arguments.infiles:
        out_name = infile.as_posix().replace('/', '_')
        compile_file(infile, arguments.out_dir / out_name)


IMPORT_PATTERN = re.compile(r'^(@import-static\s+(?P<path>.+))$', re.MULTILINE)
MODULE_PATTERN = re.compile(r'(^module\s+(?P<name>.+)\s*;\s*)$', re.MULTILINE)
EXPORT_PATTERN = re.compile(r'^(\s*export)', re.MULTILINE)


def compile_file(infile: Path, outfile: Path):
    print('Compiling {} to {}'.format(
        infile.as_posix(), outfile.as_posix()))

    result = resolve_imports(infile)
    script_name = infile.name.split('.')[0].upper()
    result = result.replace('###COMPILED_SCRIPT_BASENAME###', script_name)

    # move module declaration up
    modules = MODULE_PATTERN.findall(result)
    if len(modules) != 1:
        print(' Not moving up module name definition, occurs multiple times')
    else:
        module_line, module = modules[0]
        result = result.replace(module_line, '')
        result = EXPORT_PATTERN.sub('module {};\n\g<1>'.format(module), result, count=1)

        result = result.replace('###MODULE_NAME###', module)

    with outfile.open('w') as out:
        out.write(result)


def resolve_imports(script_path: Path) -> str:
    with script_path.open() as file:
        script = file.read()
    imports = set(IMPORT_PATTERN.findall(script))
    for line, imp in imports:
        # based on parent (the directory containing the script)
        if not imp.endswith('.zeek'):
            imp += '.zeek'
        path = script_path.parent / imp
        imported_script = resolve_imports(path)
        script = script.replace(line, imported_script)

    return script


if __name__ == '__main__':
    main()
