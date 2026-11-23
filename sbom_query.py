import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime

from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import InvalidVersion

__version__ = "1.0.0"


def find_sbom_files(directory):
    """
    Recursively scans the target directory for JSON files.

    Args:
        directory (str): Root directory path to begin the search.

    Returns:
        list[str]: Paths to discovered JSON files.
    """
    sbom_files = []
    for root, dirs, files in os.walk(directory):
        for file in sorted(files):
            if file.endswith('.json'):
                sbom_files.append(os.path.join(root, file))
    return sbom_files


def parse_version_rule(rule_str):
    """
    Normalizes a version constraint string into a PEP 440 SpecifierSet object.

    Handles common shorthand notations:
      - Hyphen range: '8.2 - 8.2.35'   -> '>=8.2,<=8.2.35'
      - Comparison operators: '<8.2.35', '>=8.3.0,<8.3.36'
      - Exact version shorthand: '8.2' -> '==8.2'

    If parsing fails (non-standard version schemes), returns the raw string
    so it can be evaluated via exact string equality.

    Args:
        rule_str (str): A single version constraint string.

    Returns:
        SpecifierSet | str: Parsed specifier set or raw fallback string.
    """
    rule_str = rule_str.strip()

    # Convert numeric hyphen ranges (e.g., '8.2 - 8.2.35') without splitting tags like '1.0.0-alpha'
    if not any(rule_str.startswith(op) for op in ['<', '>', '=', '~', '!']):
        range_match = re.match(r'^(\d[^\s-]*)\s*-\s*(\d[^\s-]*)$', rule_str)
        if range_match:
            min_v, max_v = range_match.group(1), range_match.group(2)
            rule_str = f">={min_v},<={max_v}"

    # Default standalone version strings (e.g., '8.2.14') to strict equality '==8.2.14'
    if not any(rule_str.startswith(op) for op in ['<', '>', '=', '~', '!']):
        rule_str = f"=={rule_str}"

    try:
        return SpecifierSet(rule_str)
    except InvalidSpecifier:
        return rule_str


def is_version_match(component_version, rules):
    """
    Evaluates whether a discovered component version satisfies any target query rules.

    Linux container packages (Debian, Ubuntu, Alpine) often append distribution
    metadata and epochs (e.g., '8.3.6-0ubuntu0.24.04.12' or '2:8.2.7'). Because
    packaging.specifiers enforces strict PEP 440 compliance, this function strips
    OS build suffixes and epochs to extract the base semantic version before checking.

    Args:
        component_version (str): Version string extracted from the SBOM component.
        rules (list | None): List of SpecifierSet/str rules. If None, any version
                             of the package is considered a match.

    Returns:
        bool: True if the component version matches any rule constraint, otherwise False.
    """
    if rules is None:
        return True

    if not component_version or component_version == 'N/A':
        return False

    # Normalize OS package versions to standard semantic versioning:
    # 1. Strip distro release metadata: '8.3.6-0ubuntu0.24.04.12' -> '8.3.6'
    # 2. Strip Debian/Ubuntu build revisions: '8.3.6+deb12u1' -> '8.3.6'
    clean_version = component_version.split('-')[0].split('+')[0].strip()

    # 3. Strip package manager epoch prefix: '2:8.2.7' -> '8.2.7'
    if ':' in clean_version:
        clean_version = clean_version.split(':', 1)[1].strip()

    for rule in rules:
        if isinstance(rule, SpecifierSet):
            try:
                if clean_version and rule.contains(clean_version, prereleases=True):
                    return True
            except InvalidVersion:
                pass

            try:
                if rule.contains(component_version, prereleases=True):
                    return True
            except InvalidVersion:
                pass

        elif isinstance(rule, str):
            if component_version == rule or clean_version == rule:
                return True

    return False


def _apply_rule_line(line, target_packages):
    """Parses a single 'package[@version_rule]' entry into the target_packages dict."""
    operators = ('<', '>', '=', '~', '!')

    # Check line[1:] so a leading '@' on scoped names (e.g., '@nestjs/core')
    # isn't mistaken for a version delimiter when no version rule is given.
    if '@' in line[1:]:
        parts = line.rsplit('@', 1)
        raw_name = parts[0].strip()
        rules_str = parts[1].strip()
        if not raw_name:
            return

        key = raw_name.lower()

        # Keep catch-all override if already set
        if key in target_packages and target_packages[key] is None:
            return

        if not rules_str:
            target_packages[key] = None
            return

        if key not in target_packages:
            target_packages[key] = []

        # If all comma-separated clauses start with comparison operators (e.g., '>=8.2,<=8.2.35'),
        # treat them as a single compound AND range; otherwise split into separate OR rules.
        comma_parts = [r.strip() for r in rules_str.split(',') if r.strip()]
        if len(comma_parts) > 1 and all(p.startswith(operators) for p in comma_parts):
            raw_rules = [rules_str]
        else:
            raw_rules = comma_parts

        for raw_rule in raw_rules:
            target_packages[key].append(parse_version_rule(raw_rule))
    else:
        raw_name = line.strip()
        if raw_name:
            target_packages[raw_name.lower()] = None


def load_target_packages(file_path=None, inline_packages=None, quiet=False):
    """
    Loads target package rules from a file, inline CLI arguments, or both.

    Supported rule formats:
      - Match ANY version: 'package_name'
      - Match specific range: 'package_name@>=8.3.0,<8.3.36'
      - Match multiple discrete versions: 'package_name@1.0.0, 2.0.0'

    Args:
        file_path (str | None): Path to the text file containing package query rules.
        inline_packages (list[str] | None): Inline package rules passed via CLI (-p).
        quiet (bool): Suppresses summary statistics output when True.

    Returns:
        tuple[dict, int]:
          - dict: Maps lowercase package names to lists of parsed SpecifierSets (or None).
          - int: Count of unique package targets configured.
    """
    target_packages = {}
    total_lines_read = 0
    total_package_entries = 0

    if file_path:
        if not os.path.isfile(file_path):
            print(f"Error: Package list file not found: {file_path}", file=sys.stderr)
            return {}, 0

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            total_lines_read = len(lines)

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                total_package_entries += 1
                _apply_rule_line(line, target_packages)

    if inline_packages:
        for entry in inline_packages:
            entry = entry.strip()
            if not entry or entry.startswith('#'):
                continue
            total_package_entries += 1
            _apply_rule_line(entry, target_packages)

    unique_names_count = len(target_packages)
    if not quiet:
        print("\n--- Query Target Statistics ---")
        if file_path:
            print(f"Total lines read from file: {total_lines_read}")
        print(f"Total package entries loaded: {total_package_entries}")
        print(f"Unique package names loaded: {unique_names_count}")
        print("-------------------------------")

    return target_packages, unique_names_count


def query_sbom_inventory(
    input_directory,
    packages_file=None,
    inline_packages=None,
    output_csv=None,
    no_csv=False,
    quiet=False,
):
    """
    Queries CycloneDX SBOM JSON files across the target directory for matching
    packages and versions, and writes any findings to a timestamped CSV report.

    Args:
        input_directory (str): Root directory containing SBOM JSON files.
        packages_file (str | None): Path to the file defining target packages and constraints.
        inline_packages (list[str] | None): Inline package rules passed via CLI.
        output_csv (str | None): Custom output CSV path. Defaults to timestamped filename.
        no_csv (bool): If True, prints matches without creating a CSV file.
        quiet (bool): If True, suppresses progress headers and prints only matches/errors.

    Returns:
        list[dict] | None: List of matching component dicts, or None if inputs were invalid.
    """
    if not os.path.isdir(input_directory):
        print(f"Error: Input directory not found: {input_directory}", file=sys.stderr)
        return None

    target_packages, _ = load_target_packages(
        file_path=packages_file,
        inline_packages=inline_packages,
        quiet=quiet,
    )
    if not target_packages:
        return None

    json_files = find_sbom_files(input_directory)
    if not json_files:
        if not quiet:
            print("No JSON files found in the specified directory.")
        return []

    sboms_reviewed = 0
    query_results = []

    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Skip non-CycloneDX JSON files (e.g., package.json, config.json)
            if not isinstance(data, dict) or str(data.get('bomFormat', '')).lower() != 'cyclonedx':
                continue

            sboms_reviewed += 1

            components = data.get('components', [])
            metadata_component = data.get('metadata', {}).get('component', {})
            image_hash = metadata_component.get('name') or 'N/A'
            image_version = metadata_component.get('version') or 'N/A'
            component_type = metadata_component.get('type') or 'N/A'
            rel_sbom_path = os.path.relpath(file_path, input_directory)

            for component in components:
                name = component.get('name')
                version = component.get('version')

                if name and name.lower() in target_packages:
                    rules = target_packages[name.lower()]
                    if is_version_match(version, rules):
                        licenses = component.get('licenses')
                        query_results.append({
                            'Image Hash': image_hash,
                            'Image Version': image_version,
                            'Component Type': component_type,
                            'Package': name,
                            'Version': version,
                            'PURL': component.get('purl') or 'N/A',
                            'Author': component.get('author') or 'N/A',
                            'Licenses': json.dumps(licenses) if licenses else 'N/A',
                            'SBOM File': rel_sbom_path,
                        })
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Skipping file '{file_path}' due to an error: {e}", file=sys.stderr)

    if not quiet:
        print(f"Number of SBOMs reviewed: {sboms_reviewed}")

    if query_results:
        if not quiet:
            print("\n--- Matching Packages Found ---")
        for match in query_results:
            print(f"  File: {match['SBOM File']}")
            print(f"  Image: {match['Image Hash']} ({match['Image Version']})")
            print(f"  Package: {match['Package']}@{match['Version']}")
            print(f"  PURL: {match['PURL']}\n")

        if not no_csv:
            output_csv_path = output_csv or f'sbom_query_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            try:
                with open(output_csv_path, 'w', newline='', encoding='utf-8') as csv_file:
                    fieldnames = [
                        'Image Hash', 'Image Version', 'Component Type', 'Package',
                        'Version', 'PURL', 'SBOM File', 'Author', 'Licenses'
                    ]
                    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(query_results)
                if not quiet:
                    print(f"Details saved to {output_csv_path}")
            except Exception as e:
                print(f"An unexpected error occurred while writing to CSV: {e}", file=sys.stderr)
    else:
        if not quiet:
            print("\nNo matching packages were found in the inventory.")

    return query_results


def parse_cli_args():
    """Configures and parses command-line interface arguments."""
    parser = argparse.ArgumentParser(
        prog='sbom_query.py',
        description='Query CycloneDX JSON SBOM files for specific packages and version constraints.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sbom_query.py -d ./exports -l packages.txt
  python3 sbom_query.py -d ./exports -p "openssl@<3.0.13" -p "curl"
  python3 sbom_query.py -d ./exports -l baseline.txt -p "php8.3@<8.3.36"
  python3 sbom_query.py -d ./sboms -l packages.txt -o results.csv --fail-on-match
        """,
    )
    parser.add_argument(
        '-d', '--directory',
        required=True,
        help='Root directory to search recursively for CycloneDX SBOM JSON files.',
    )
    parser.add_argument(
        '-l', '--list',
        dest='list_file',
        default=None,
        help='Path to a text file containing target packages and version rules.',
    )
    parser.add_argument(
        '-p', '--package',
        dest='packages',
        action='append',
        default=None,
        help="Inline target package rule (e.g., 'curl' or 'php8.3@<8.3.36'). Repeatable.",
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Custom output CSV file path (default: sbom_query_results_YYYYMMDD_HHMMSS.csv).',
    )
    parser.add_argument(
        '--no-csv',
        action='store_true',
        help='Print results to stdout without generating a CSV report.',
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress summary banners and progress messages.',
    )
    parser.add_argument(
        '--fail-on-match',
        action='store_true',
        help='Exit with status code 1 if any matching packages are found (useful for CI/CD gates).',
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=__version__,
    )

    args = parser.parse_args()
    if not args.list_file and not args.packages:
        parser.error('at least one of -l/--list or -p/--package is required.')

    return args


if __name__ == '__main__':
    args = parse_cli_args()
    matches = query_sbom_inventory(
        input_directory=args.directory,
        packages_file=args.list_file,
        inline_packages=args.packages,
        output_csv=args.output,
        no_csv=args.no_csv,
        quiet=args.quiet,
    )

    if matches is None:
        sys.exit(1)
    if args.fail_on_match and len(matches) > 0:
        sys.exit(1)
    sys.exit(0)