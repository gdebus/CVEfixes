import pandas as pd
import requests
import time
from math import floor
from github import Github
from github.GithubException import BadCredentialsException

import configuration as cf
import database as db
from collect_commits import extract_commits, extract_project_links
import cve_importer
from utils import prune_tables

repo_columns = [
    'repo_url',
    'repo_name',
    'description',
    'date_created',
    'date_last_push',
    'homepage',
    'repo_language',
    'owner',
    'forks_count',
    'stars_count'
]


def find_unavailable_urls(urls):
    """
    Returns the unavailable urls (repositories that are removed or made private).
    """
    sleeptime = 0
    unavailable_urls = []
    url_list = list(urls)
    total = len(url_list)
    cf.logger.info(f'Checking availability of {total} unique repository URLs...')
    for i, url in enumerate(url_list, 1):
        cf.logger.info(f'  [{i}/{total}] Checking {url}')
        try:
            response = requests.head(url, timeout=10)
        except requests.exceptions.RequestException as e:
            cf.logger.warning(f'  [{i}/{total}] Timed out or errored ({e}), marking as unavailable: {url}')
            unavailable_urls.append(url)
            continue

        while response.status_code == 429:
            sleeptime += 10
            cf.logger.info(f'  Rate limited, waiting {sleeptime}s before retrying...')
            time.sleep(sleeptime)
            try:
                response = requests.head(url, timeout=10)
            except requests.exceptions.RequestException:
                break
        sleeptime = 0

        if (response.status_code >= 400) or \
                (response.is_redirect and
                 response.headers['location'] == 'https://gitlab.com/users/sign_in'):
            cf.logger.info(f'  [{i}/{total}] Unavailable (HTTP {response.status_code}): {url}')
            unavailable_urls.append(url)
        else:
            cf.logger.info(f'  [{i}/{total}] OK (HTTP {response.status_code}): {url}')

    cf.logger.info(f'URL check complete: {len(unavailable_urls)} of {total} unavailable')
    return unavailable_urls


def convert_runtime(start_time, end_time) -> (int, int, int):
    """Converts runtime to readable (hours, minutes, seconds)."""
    runtime = end_time - start_time
    hours = runtime / 3600
    minutes = (runtime % 3600) / 60
    seconds = (runtime % 3600) % 60
    return floor(hours), floor(minutes), round(seconds)


def get_ref_links():
    """
    Retrieves reference links from CVE records to populate the 'fixes' table.
    """
    if db.table_exists('fixes'):
        if cf.SAMPLE_LIMIT > 0:
            df_fixes = pd.read_sql("SELECT * FROM fixes LIMIT " + str(cf.SAMPLE_LIMIT), con=db.conn)
            df_fixes.to_sql(name='fixes', con=db.conn, if_exists='replace', index=False)
        else:
            df_fixes = pd.read_sql("SELECT * FROM fixes", con=db.conn)
    else:
        df_master = pd.read_sql("SELECT * FROM cve", con=db.conn)
        df_fixes = extract_project_links(df_master)
        del df_master  # free RAM immediately after use

        cf.logger.info('Checking if the references are still accessible...')
        unique_urls = set(list(df_fixes.repo_url))
        cf.logger.info(f'Found {len(df_fixes)} fix references across {len(unique_urls)} unique repositories')

        unavailable_urls = find_unavailable_urls(unique_urls)

        if len(unavailable_urls) > 0:
            cf.logger.info(f'Of {len(unique_urls)} unique references, {len(unavailable_urls)} are not accessible')

        df_fixes = df_fixes[~df_fixes['repo_url'].isin(unavailable_urls)]
        cf.logger.info(
            f'After filtering, {len(df_fixes)} references remain ({len(set(list(df_fixes.repo_url)))} unique repos)')

        if cf.SAMPLE_LIMIT > 0:
            df_fixes = df_fixes[~df_fixes.repo_url.isin([
                'https://github.com/torvalds/linux',
                'https://github.com/ImageMagick/ImageMagick',
                'https://github.com/the-tcpdump-group/tcpdump',
                'https://github.com/phpmyadmin/phpmyadmin',
                'https://github.com/FFmpeg/FFmpeg',
            ])]
            df_fixes = df_fixes.head(int(cf.SAMPLE_LIMIT))

        df_fixes.to_sql(name='fixes', con=db.conn, if_exists='replace', index=False)

    return df_fixes


def get_github_meta(repo_url, username, token):
    """Returns github meta-information of the repo_url."""
    owner, project = repo_url.split('/')[-2], repo_url.split('/')[-1]
    meta_row = {}

    if username == 'None':
        git_link = Github()
    else:
        git_link = Github(login_or_token=token, user_agent=username)

    try:
        git_user = git_link.get_user(owner)
        repo = git_user.get_repo(project)
        meta_row = {
            'repo_url': repo_url,
            'repo_name': repo.full_name,
            'description': repo.description,
            'date_created': repo.created_at,
            'date_last_push': repo.pushed_at,
            'homepage': repo.homepage,
            'repo_language': repo.language,
            'forks_count': repo.forks,
            'stars_count': repo.stargazers_count,
            'owner': owner,
        }
    except BadCredentialsException as e:
        cf.logger.warning(f'Credential problem while accessing GitHub repository {repo_url}: {e}')
    except Exception as e:
        cf.logger.warning(f'Other issues while getting meta-data for GitHub repository {repo_url}: {e}')
    return meta_row


def save_repo_meta(repo_url):
    """Populate repository meta-information in the repository table."""
    if 'github.' in repo_url:
        try:
            meta_dict = get_github_meta(repo_url, cf.USER, cf.TOKEN)
            df_meta = pd.DataFrame([meta_dict], columns=repo_columns)

            if db.table_exists('repository'):
                if db.fetchone_query('repository', 'repo_url', repo_url) is False:
                    df_meta.to_sql(name='repository', con=db.conn, if_exists="append", index=False)
            else:
                df_meta.to_sql(name='repository', con=db.conn, if_exists="replace", index=False)
        except Exception as e:
            cf.logger.warning(f'Problem while fetching repository meta-information: {e}')


def store_tables(df_fixes):
    """
    Fetch commits and save data into commit-, file- and method-level tables.

    Each commit is written to the DB immediately after extraction (via
    extract_commits), so memory consumption is proportional to a single
    commit rather than to the entire repository or dataset.
    """
    if db.table_exists('commits'):
        query_done_hashes = "SELECT x.hash FROM fixes x, commits c WHERE x.hash = c.hash;"
        hash_done = list(pd.read_sql(query_done_hashes, con=db.conn)['hash'])
        df_fixes = df_fixes[~df_fixes.hash.isin(hash_done)]
        cf.logger.info(f'Skipping {len(hash_done)} already collected commits, {len(df_fixes)} remaining')

    repo_urls = df_fixes.repo_url.unique()
    cf.logger.info(f'Starting commit extraction for {len(repo_urls)} repositories')
    pcount = 0

    for repo_url in repo_urls:
        pcount += 1
        try:
            df_single_repo = df_fixes[df_fixes.repo_url == repo_url]
            hashes = list(df_single_repo.hash.unique())
            cf.logger.info('-' * 70)
            cf.logger.info(
                f'Retrieving fixes for repo {pcount} of {len(repo_urls)} '
                f'- {repo_url.rsplit("/")[-1]} ({len(hashes)} hash(es))'
            )

            # extract_commits now writes directly to DB and returns counts only
            n_commits, n_files, n_methods = extract_commits(repo_url, hashes, db.conn)

            if n_commits > 0:
                cf.logger.info(f'  Saved {n_commits} commit(s), {n_files} file change(s), {n_methods} method change(s)')
                save_repo_meta(repo_url)
            else:
                cf.logger.warning(f'Could not retrieve commit information from: {repo_url}')

        except Exception as e:
            cf.logger.warning(f'Problem occurred while retrieving the project: {repo_url}: {e}')

    cf.logger.info('-' * 70)
    cf.logger.info('=== Final database summary ===')
    if db.table_exists('commits'):
        commit_count = pd.read_sql("SELECT count(*) FROM commits", con=db.conn).iloc[0].iloc[0]
        cf.logger.info(f'Total commits in DB:        {commit_count}')
    else:
        cf.logger.warning('The commits table does not exist')

    if db.table_exists('file_change'):
        file_count = pd.read_sql("SELECT count(*) FROM file_change", con=db.conn).iloc[0].iloc[0]
        cf.logger.info(f'Total file changes in DB:   {file_count}')
    else:
        cf.logger.warning('The file_change table does not exist')

    if db.table_exists('method_change'):
        method_count = pd.read_sql("SELECT count(*) FROM method_change", con=db.conn).iloc[0].iloc[0]
        vul_method_count = pd.read_sql(
            'SELECT count(*) FROM method_change WHERE before_change="True"', con=db.conn
        ).iloc[0].iloc[0]
        cf.logger.info(f'Total method changes in DB: {method_count}')
        cf.logger.info(f'Vulnerable methods in DB:   {vul_method_count}')
    else:
        cf.logger.warning('The method_change table does not exist')

    cf.logger.info('-' * 70)


# ---------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    start_time = time.perf_counter()
    # Step (1) save CVEs (cve) and cwe tables
    #cve_importer.import_cves()
    # Step (2) save commit-, file-, and method-level data tables to the database
    #store_tables(get_ref_links())
    # Step (3) pruning the database tables
    if db.table_exists('method_change'):
        prune_tables(cf.DATABASE)
    else:
        cf.logger.warning('Data pruning is not possible because there is no information in method_change table')

    cf.logger.info('The database is up-to-date.')
    cf.logger.info('-' * 70)
    end_time = time.perf_counter()
    hours, minutes, seconds = convert_runtime(start_time, end_time)
    cf.logger.info(f'Time elapsed to pull the data {hours:02.0f}:{minutes:02.0f}:{seconds:02.0f} (hh:mm:ss).')
# ---------------------------------------------------------------------------------------------------------------------