import os
import json
from datetime import date
from pathlib import Path

import pandas as pd

import configuration as cf
import database as db

output_dir = 'Output'  # path to save all the compressed output files


def make_timestamp(json_path):
    """
    Generates timestamp by picking the latest timestamp from the CVE JSON files.
    """
    date_list = []
    for file in json_path.glob('*.json'):
        with open(file, 'r') as jsonfile:
            x = json.load(jsonfile)
            date_list.append(date.fromisoformat(x['CVE_data_timestamp'].split('T')[0]))
    return str(max(date_list))


def create_zip_files():
    timestamp = make_timestamp(Path(cf.DATA_PATH) / "json")
    cwe_xml_gz = Path(output_dir, 'cwe-' + timestamp + '.xml.gz')
    jsonl_gz = Path(output_dir, 'nvd-' + timestamp + '.jsonl.gz')
    db_sql_gz = Path(output_dir, cf.DATABASE_NAME.split('.')[0] + '-' + timestamp + '.sql.gz')

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if os.system('gzip -c Data/cwec_v4.4.xml > ' + str(cwe_xml_gz)) == 0:
        cf.logger.info(f'CWE XML file is saved to {cwe_xml_gz}')
    if os.system('jq -c "." Data/json/*.json | gzip > ' + str(jsonl_gz)) == 0:
        cf.logger.info(f'JSON files are zipped to {jsonl_gz}')
    if os.system('sqlite3 ' + str(cf.DATABASE) + ' .dump | gzip > ' + str(db_sql_gz)) == 0:
        cf.logger.info(f'The sql dump of the database file is zipped to {db_sql_gz}')


def add_tbd_repos(tbd_repos):
    """Return dummy entries for repos whose metadata could not be fetched."""
    tbd_rows = []
    for repo_url in tbd_repos:
        if '/' in repo_url:
            tbd_rows.append({
                'repo_url': repo_url,
                'repo_name': 'visit repo url',
                'description': 'visit repo url',
                'date_created': 'visit repo url',
                'date_last_push': 'visit repo url',
                'homepage': 'visit repo url',
                'repo_language': 'visit repo url',
                'forks_count': 'visit repo url',
                'stars_count': 'visit repo url',
                'owner': repo_url.split('/')[-2],
            })
    return tbd_rows


def filter_non_textual(df_file):
    """Filter out non-textual files (no added or deleted lines)."""
    mask = (df_file.num_lines_added == '0') & (df_file.num_lines_deleted == '0')
    non_text_ids = df_file.loc[mask, 'file_change_id']
    cf.logger.debug(f'Non-textual files: {len(non_text_ids)}')
    return df_file[~mask].reset_index(drop=True)


def _read_sql_chunked(query, conn, chunksize=50_000):
    """
    Read a potentially large SQL result in chunks and concatenate.
    Falls back to a single read if the result is small.
    """
    chunks = []
    for chunk in pd.read_sql(query, con=conn, chunksize=chunksize):
        chunks.append(chunk)
    if chunks:
        return pd.concat(chunks, ignore_index=True)
    return pd.DataFrame()


def prune_tables(datafile):
    """
    Filter out unlinked data from all tables.

    Memory-optimised: tables are loaded one at a time and freed as soon as
    they are no longer needed. The large tables (file_change, method_change)
    are never in RAM simultaneously — each is loaded, filtered, written back,
    and deleted before the next one is loaded.
    """
    cf.logger.info('-' * 70)
    cf.logger.info('Wait while pruning the data...')

    connf = db.create_connection(datafile)
    CHUNK = 10_000

    def _save(df, name):
        cf.logger.info(f'Saving {name} ({len(df)} rows)...')
        df.to_sql(name=name, con=connf, if_exists='replace', index=False, chunksize=CHUNK)

    # ------------------------------------------------------------------
    # 1. Load small tables and compute valid hash/id sets
    #    These are small enough to keep in RAM throughout.
    # ------------------------------------------------------------------
    cf.logger.info('Loading commits...')
    df_commit = _read_sql_chunked('SELECT * FROM commits', connf)
    df_commit['repo_url'] = df_commit.repo_url.apply(lambda x: x.rsplit('.git')[0])
    df_commit = df_commit.drop_duplicates().reset_index(drop=True)

    cf.logger.info('Loading fixes...')
    df_fixes = _read_sql_chunked('SELECT * FROM fixes', connf)

    # ------------------------------------------------------------------
    # 2. Replace short hashes in fixes with full hashes from commits
    # ------------------------------------------------------------------
    invalid_hashes = set(df_commit.hash.unique()).difference(set(df_fixes.hash.unique()))
    count_replaces = 0
    for full_hash in invalid_hashes:
        url = df_commit.loc[df_commit.hash == full_hash, 'repo_url'].values[0]
        fix_url = df_fixes[df_fixes.repo_url == url]
        for short_hash in fix_url.hash:
            if short_hash.strip()[:4] == full_hash.strip()[:4]:
                df_fixes.loc[df_fixes.hash == short_hash, 'hash'] = full_hash
                count_replaces += 1
    cf.logger.info(f'Short hashes replaced: {count_replaces}')
    del invalid_hashes

    # ------------------------------------------------------------------
    # 3. Compute valid hashes and filter commits + fixes
    # ------------------------------------------------------------------
    incorrect_hashes = set(df_commit.hash.unique()).difference(set(df_fixes.hash.unique()))
    df_commit_filtered = df_commit[~df_commit.hash.isin(incorrect_hashes)].reset_index(drop=True)
    del df_commit, incorrect_hashes

    valid_hashes = set(df_commit_filtered.hash.unique())

    df_fixes_filtered = df_fixes[df_fixes.hash.isin(valid_hashes)].reset_index(drop=True)
    del df_fixes

    valid_cve_ids = set(df_fixes_filtered.cve_id.unique())
    valid_repo_urls = set(df_fixes_filtered.repo_url.unique())

    # Save commits and fixes immediately — free from RAM
    _save(df_commit_filtered, 'commits')
    _save(df_fixes_filtered,  'fixes')
    del df_commit_filtered, df_fixes_filtered

    # ------------------------------------------------------------------
    # 4. Filter file_change — load, filter, save, free
    # ------------------------------------------------------------------
    cf.logger.info('Loading file_change...')
    df_file = _read_sql_chunked('SELECT * FROM file_change', connf)
    df_file = filter_non_textual(df_file)
    df_file_filtered = df_file[df_file.hash.isin(valid_hashes)].reset_index(drop=True)
    del df_file

    valid_file_ids = set(df_file_filtered.file_change_id.unique())
    _save(df_file_filtered, 'file_change')
    del df_file_filtered

    # ------------------------------------------------------------------
    # 5. Filter method_change — load, filter, save, free
    # ------------------------------------------------------------------
    cf.logger.info('Loading method_change...')
    df_method = _read_sql_chunked('SELECT * FROM method_change', connf)
    df_method = df_method[df_method.name != ''].reset_index(drop=True)
    df_method_filtered = df_method[df_method.file_change_id.isin(valid_file_ids)].reset_index(drop=True)
    del df_method, valid_file_ids

    _save(df_method_filtered, 'method_change')
    del df_method_filtered

    # ------------------------------------------------------------------
    # 6. Filter cve — load, filter, save, free
    # ------------------------------------------------------------------
    cf.logger.info('Loading cve...')
    df_cve = _read_sql_chunked('SELECT * FROM cve', connf)
    df_cve_filtered = df_cve[df_cve.cve_id.isin(valid_cve_ids)].reset_index(drop=True)
    del df_cve

    _save(df_cve_filtered, 'cve')
    del df_cve_filtered

    # ------------------------------------------------------------------
    # 7. Filter cwe_classification — load, filter, save, free
    # ------------------------------------------------------------------
    cf.logger.info('Loading cwe_classification...')
    df_cwe_class = _read_sql_chunked('SELECT * FROM cwe_classification', connf)
    df_cwe_class_filtered = df_cwe_class[df_cwe_class.cve_id.isin(valid_cve_ids)].reset_index(drop=True)
    del df_cwe_class, valid_cve_ids

    valid_cwe_ids = set(df_cwe_class_filtered.cwe_id.unique())
    _save(df_cwe_class_filtered, 'cwe_classification')
    del df_cwe_class_filtered

    # ------------------------------------------------------------------
    # 8. Filter cwe — load, filter, save, free
    # ------------------------------------------------------------------
    cf.logger.info('Loading cwe...')
    df_cwe = _read_sql_chunked('SELECT * FROM cwe', connf)
    df_cwe_filtered = df_cwe[df_cwe.cwe_id.isin(valid_cwe_ids)].reset_index(drop=True)
    del df_cwe, valid_cwe_ids

    _save(df_cwe_filtered, 'cwe')
    del df_cwe_filtered

    # ------------------------------------------------------------------
    # 9. Filter repository — load, filter, save, free
    # ------------------------------------------------------------------
    cf.logger.info('Loading repository...')
    df_repo = _read_sql_chunked('SELECT * FROM repository', connf)
    df_repo = df_repo.drop_duplicates().reset_index(drop=True)

    tbd_repos_list = valid_repo_urls.difference(set(df_repo.repo_url.unique()))
    tbd_rows = add_tbd_repos(tbd_repos_list)
    df_repo_with_tbd = pd.concat(
        [df_repo, pd.DataFrame(tbd_rows)], ignore_index=True, sort=False
    ).reset_index(drop=True)
    del df_repo

    df_repo_filtered = df_repo_with_tbd[
        df_repo_with_tbd.repo_url.isin(valid_repo_urls)
    ].reset_index(drop=True)
    del df_repo_with_tbd, valid_repo_urls

    _save(df_repo_filtered, 'repository')
    del df_repo_filtered

    cf.logger.info('Data pruning has been completed successfully')
    cf.logger.info('-' * 70)


def log_commit_urls(repo_url, hashes):
    for hsh in hashes:
        if 'gitlab.' in repo_url:
            cf.logger.debug(f'{repo_url}/-/commit/{hsh}')
        else:
            cf.logger.debug(f'{repo_url}/commit/{hsh}')