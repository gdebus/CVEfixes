# Obtaining and processing CVE json **files**
# The code is to download nvdcve zip files from NIST since 2002 to the current year,
# unzip and append all the JSON files together,
# and extracts all the entries from json files of the projects.
#
# Updated for NVD JSON Feed API 2.0 format:
#   - New URL scheme: https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip
#   - New top-level structure: { "vulnerabilities": [ { "cve": { ... } } ] }
#   - CVSS data under metrics.cvssMetricV40 / cvssMetricV31 / cvssMetricV30 / cvssMetricV2
#   - References directly in cve.references[] with "url" key
#   - Weaknesses (CWEs) under cve.weaknesses[].description[].value

import datetime
import json
import os
from io import BytesIO
import pandas as pd
import requests
from pathlib import Path
from zipfile import ZipFile

from extract_cwe_record import add_cwe_class, extract_cwe
import configuration as cf
import database as db

# ---------------------------------------------------------------------------------------------------------------------

urlhead = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-'
urltail = '.json.zip'
initYear = 2002
currentYear = datetime.datetime.now().year

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if cf.SAMPLE_LIMIT > 0:
    initYear = currentYear

ordered_cve_columns = [
    'cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
    'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
    'user_interaction_required',
    'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
    'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
    'cvss2_base_score',
    'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
    'cvss3_privileges_required',
    'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
    'cvss3_integrity_impact',
    'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
    'exploitability_score', 'impact_score', 'ac_insuf_info',
    # CVSSv4.0 fields (new in NVD 2.0, absent for older CVEs)
    'cvss4_vector_string', 'cvss4_base_score', 'cvss4_base_severity',
    'cvss4_attack_vector', 'cvss4_attack_complexity', 'cvss4_attack_requirements',
    'cvss4_privileges_required', 'cvss4_user_interaction',
    'cvss4_vuln_confidentiality_impact', 'cvss4_vuln_integrity_impact', 'cvss4_vuln_availability_impact',
    'cvss4_sub_confidentiality_impact', 'cvss4_sub_integrity_impact', 'cvss4_sub_availability_impact',
    'reference_json', 'problemtype_json',
]

cwe_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

# ---------------------------------------------------------------------------------------------------------------------


def _get(d: dict, *keys, default=''):
    """Safe nested dict accessor."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d if d is not None else default


def _parse_description(descriptions: list) -> str:
    """Return the English description text from a descriptions list."""
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get('lang') == 'en':
            return entry.get('value', '')
    return ''


def _parse_references(references: list) -> str:
    """
    Convert the NVD 2.0 references list into a string that matches
    the format expected by collect_commits.extract_project_links(), i.e.
    a list of dicts each containing at least a 'url' key.
    """
    ref_list = [{'url': r.get('url', ''), 'tags': r.get('tags', [])}
                for r in references if isinstance(r, dict)]
    return str(ref_list)


def _parse_weaknesses(weaknesses: list) -> str:
    """
    Convert the NVD 2.0 weaknesses list into a problemtype_json string
    compatible with extract_cwe_record.add_cwe_class().
    """
    if not weaknesses:
        return str([{'description': []}])

    all_descriptions = []
    for weakness in weaknesses:
        for desc in weakness.get('description', []):
            if isinstance(desc, dict):
                all_descriptions.append({'value': desc.get('value', 'unknown')})

    if not all_descriptions:
        all_descriptions = [{'value': 'unknown'}]

    return str([{'description': all_descriptions}])


def _extract_cvss2(metrics: dict) -> dict:
    """Extract CVSSv2 fields from the NVD 2.0 metrics dict."""
    entries = metrics.get('cvssMetricV2', [])
    if not entries:
        return {}
    entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
    cvss = entry.get('cvssData', {})
    return {
        'cvss2_vector_string':          _get(cvss, 'vectorString'),
        'cvss2_access_vector':          _get(cvss, 'accessVector'),
        'cvss2_access_complexity':      _get(cvss, 'accessComplexity'),
        'cvss2_authentication':         _get(cvss, 'authentication'),
        'cvss2_confidentiality_impact': _get(cvss, 'confidentialityImpact'),
        'cvss2_integrity_impact':       _get(cvss, 'integrityImpact'),
        'cvss2_availability_impact':    _get(cvss, 'availabilityImpact'),
        'cvss2_base_score':             _get(cvss, 'baseScore'),
        'severity':                     _get(entry, 'baseSeverity'),
        'exploitability_score':         _get(entry, 'exploitabilityScore'),
        'impact_score':                 _get(entry, 'impactScore'),
        'ac_insuf_info':                _get(entry, 'acInsufInfo'),
        'obtain_all_privilege':         _get(entry, 'obtainAllPrivilege'),
        'obtain_user_privilege':        _get(entry, 'obtainUserPrivilege'),
        'obtain_other_privilege':       _get(entry, 'obtainOtherPrivilege'),
        'user_interaction_required':    _get(entry, 'userInteractionRequired'),
    }


def _extract_cvss3(metrics: dict) -> dict:
    """Extract CVSSv3 fields from the NVD 2.0 metrics dict (prefers v3.1 over v3.0)."""
    entries = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
    if not entries:
        return {}
    entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
    cvss = entry.get('cvssData', {})
    result = {
        'cvss3_vector_string':          _get(cvss, 'vectorString'),
        'cvss3_attack_vector':          _get(cvss, 'attackVector'),
        'cvss3_attack_complexity':      _get(cvss, 'attackComplexity'),
        'cvss3_privileges_required':    _get(cvss, 'privilegesRequired'),
        'cvss3_user_interaction':       _get(cvss, 'userInteraction'),
        'cvss3_scope':                  _get(cvss, 'scope'),
        'cvss3_confidentiality_impact': _get(cvss, 'confidentialityImpact'),
        'cvss3_integrity_impact':       _get(cvss, 'integrityImpact'),
        'cvss3_availability_impact':    _get(cvss, 'availabilityImpact'),
        'cvss3_base_score':             _get(cvss, 'baseScore'),
        'cvss3_base_severity':          _get(cvss, 'baseSeverity'),
        'exploitability_score':         _get(entry, 'exploitabilityScore'),
        'impact_score':                 _get(entry, 'impactScore'),
    }
    return result


def _extract_cvss4(metrics: dict) -> dict:
    """Extract CVSSv4.0 fields from the NVD 2.0 metrics dict.
    Values of 'NOT_DEFINED' are treated as absent and stored as empty string.
    """
    entries = metrics.get('cvssMetricV40', [])
    if not entries:
        return {}
    entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
    cvss = entry.get('cvssData', {})

    def _get4(field):
        val = cvss.get(field, '')
        if val is None or str(val).upper() == 'NOT_DEFINED':
            return ''
        return val

    return {
        'cvss4_vector_string':               _get4('vectorString'),
        'cvss4_base_score':                  _get4('baseScore'),
        'cvss4_base_severity':               _get4('baseSeverity'),
        'cvss4_attack_vector':               _get4('attackVector'),
        'cvss4_attack_complexity':           _get4('attackComplexity'),
        'cvss4_attack_requirements':         _get4('attackRequirements'),
        'cvss4_privileges_required':         _get4('privilegesRequired'),
        'cvss4_user_interaction':            _get4('userInteraction'),
        'cvss4_vuln_confidentiality_impact': _get4('vulnConfidentialityImpact'),
        'cvss4_vuln_integrity_impact':       _get4('vulnIntegrityImpact'),
        'cvss4_vuln_availability_impact':    _get4('vulnAvailabilityImpact'),
        'cvss4_sub_confidentiality_impact':  _get4('subConfidentialityImpact'),
        'cvss4_sub_integrity_impact':        _get4('subIntegrityImpact'),
        'cvss4_sub_availability_impact':     _get4('subAvailabilityImpact'),
    }


def _parse_nodes(configurations: list) -> str:
    if not configurations:
        return ''
    return str(configurations)


def parse_vulnerability(vuln: dict) -> dict:
    """
    Parse a single entry from the NVD 2.0 'vulnerabilities' array into a
    flat dict that matches ordered_cve_columns.
    """
    cve = vuln.get('cve', {})
    metrics = cve.get('metrics', {})

    row = {col: '' for col in ordered_cve_columns}

    row['cve_id']             = cve.get('id', '')
    row['published_date']     = cve.get('published', '')
    row['last_modified_date'] = cve.get('lastModified', '')
    row['description']        = _parse_description(cve.get('descriptions', []))
    row['nodes']              = _parse_nodes(cve.get('configurations', []))
    row['reference_json']     = _parse_references(cve.get('references', []))
    row['problemtype_json']   = _parse_weaknesses(cve.get('weaknesses', []))

    cvss2 = _extract_cvss2(metrics)
    cvss3 = _extract_cvss3(metrics)
    cvss4 = _extract_cvss4(metrics)

    for k, v in cvss2.items():
        row[k] = v
    for k, v in cvss3.items():
        if k in ('exploitability_score', 'impact_score') and row.get(k):
            continue
        row[k] = v
    for k, v in cvss4.items():
        row[k] = v

    # severity fallback priority: CVSSv2 -> CVSSv3 -> CVSSv4
    if not row.get('severity'):
        row['severity'] = row.get('cvss3_base_severity') or row.get('cvss4_base_severity', '')

    return row


def preprocess_jsons(vulnerabilities) -> pd.DataFrame:
    """
    Parse a list of NVD 2.0 vulnerability dicts into a clean DataFrame.
    Accepts either a list of vulnerability dicts or a legacy DataFrame.
    """
    if isinstance(vulnerabilities, pd.DataFrame):
        if 'CVE_Items' in vulnerabilities.columns:
            vulnerabilities = list(vulnerabilities['CVE_Items'])
        elif 'vulnerabilities' in vulnerabilities.columns:
            vulnerabilities = [item for sublist in vulnerabilities['vulnerabilities']
                               for item in (sublist if isinstance(sublist, list) else [sublist])]
        else:
            raise ValueError('Unexpected DataFrame structure passed to preprocess_jsons()')

    cf.logger.info('Flattening CVE items and removing the duplicates...')
    rows = [parse_vulnerability(v) for v in vulnerabilities if isinstance(v, dict)]
    df_cve = pd.DataFrame(rows, columns=ordered_cve_columns)
    cf.logger.info(f'Parsed {len(df_cve)} CVE entries, filtering out entries without references...')

    # Drop entries without any references
    df_cve = df_cve[df_cve['reference_json'].str.len() > 2].reset_index(drop=True)
    df_cve = df_cve.drop_duplicates(subset=['cve_id']).reset_index(drop=True)
    cf.logger.info(f'{len(df_cve)} CVE entries remaining after filtering')

    return df_cve


def assign_cwes_to_cves(df_cve: pd.DataFrame):
    cf.logger.info('Extracting CWE definitions from XML...')
    df_cwes = extract_cwe()
    cf.logger.info(f'Loaded {len(df_cwes)} CWE definitions')
    cf.logger.info(f'Assigning CWE classifications to {len(df_cve)} CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = add_cwe_class(df_cwes_class['problemtype_json'].tolist())

    # Explode multiple CWEs per CVE into individual rows
    df_cwes_class = (df_cwes_class
                     .assign(cwe_id=df_cwes_class.cwe_id)
                     .explode('cwe_id')
                     .reset_index()[['cve_id', 'cwe_id']])
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')
    cf.logger.info(f'Found {len(df_cwes_class)} CVE-CWE associations across {df_cwes_class.cwe_id.nunique()} unique CWEs')

    no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
    if no_ref_cwes:
        cf.logger.warning(
            f'{len(no_ref_cwes)} CWE(s) from CVE records are not present in the cwe table '
            f'and will be dropped (likely newly assigned IDs not yet in the CWE XML): {no_ref_cwes}'
        )
        # Filter out unknown CWEs instead of crashing -- handles newly assigned CWE IDs
        # not yet listed in the official CWE XML file.
        df_cwes_class = df_cwes_class[
            df_cwes_class.cwe_id.isin(set(df_cwes.cwe_id))
        ].reset_index(drop=True)

    assert df_cwes.cwe_id.is_unique, 'Primary keys are not unique in cwe records!'
    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'
    # Foreign key integrity is guaranteed by the filter above, no assertion needed.

    df_cwes = df_cwes[cwe_columns].reset_index()
    cf.logger.info(f'Saving {len(df_cwes)} CWE definitions to database...')
    df_cwes.to_sql(name='cwe', con=db.conn, if_exists='replace', index=False)
    cf.logger.info(f'Saving {len(df_cwes_class)} CVE-CWE classifications to database...')
    df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='replace', index=False)
    cf.logger.info('Successfully saved cwe and cwe_classification tables')


def _load_year(year: int) -> list:
    """
    Download (or reuse a cached copy of) the NVD 2.0 JSON feed for *year*
    and return the raw list of vulnerability dicts.
    """
    filename = f'nvdcve-2.0-{year}.json'
    cached = Path(cf.DATA_PATH) / 'json' / filename

    if cached.is_file():
        cf.logger.info(f'  Reusing cached file: {filename}')
        with open(cached, encoding='utf-8') as f:
            data = json.load(f)
    else:
        zip_url = f'{urlhead}{year}{urltail}'
        cf.logger.info(f'  Downloading {zip_url} ...')
        r = requests.get(zip_url, timeout=120)
        r.raise_for_status()
        z = ZipFile(BytesIO(r.content))
        json_file = z.extract(filename, Path(cf.DATA_PATH) / 'json')
        with open(json_file, encoding='utf-8') as f:
            data = json.load(f)

    return data.get('vulnerabilities', [])


def import_cves():
    """
    Gather CVE records by downloading and processing NVD 2.0 JSON feeds.
    """
    cf.logger.info('-' * 70)
    if db.table_exists('cve'):
        cf.logger.warning('The cve table already exists, loading and continuing extraction...')
        return

    all_vulnerabilities = []
    years = list(range(initYear, currentYear + 1))
    cf.logger.info(f'Downloading CVE data for {len(years)} year(s): {years[0]} to {years[-1]}')
    for year in years:
        try:
            cf.logger.info(f'  Loading CVE data for {year}...')
            vulns = _load_year(year)
            all_vulnerabilities.extend(vulns)
            cf.logger.info(f'  [{year}] Loaded {len(vulns)} entries (running total: {len(all_vulnerabilities)})')
        except Exception as e:
            cf.logger.warning(f'  Could not load CVE data for {year}: {e}')

    cf.logger.info(f'Processing {len(all_vulnerabilities)} total CVE entries...')
    df_cve = preprocess_jsons(all_vulnerabilities)
    df_cve = df_cve.applymap(str)
    assert df_cve.cve_id.is_unique, 'Primary keys are not unique in cve records!'
    cf.logger.info(f'Saving {len(df_cve)} CVEs to database...')
    df_cve.to_sql(name='cve', con=db.conn, if_exists='replace', index=False)
    cf.logger.info(f'All CVEs have been merged into the cve table ({len(df_cve)} entries)')
    cf.logger.info('-' * 70)

    assign_cwes_to_cves(df_cve=df_cve)