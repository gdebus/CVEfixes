import ast
import os
import re
import signal
import subprocess
import tempfile
import uuid

import pandas as pd
import configuration as cf
from guesslang import Guess
from pydriller import Repository
from utils import log_commit_urls


os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

COMMIT_TIMEOUT_SECONDS = 60  # 5 minutes per commit

fixes_columns = [
    'cve_id',
    'hash',
    'repo_url',
]

commit_columns = [
    'hash',
    'repo_url',
    'author',
    'author_date',
    'author_timezone',
    'committer',
    'committer_date',
    'committer_timezone',
    'msg',
    'merge',
    'parents',
    'num_lines_added',
    'num_lines_deleted'
]

file_columns = [
    'file_change_id',
    'hash',
    'filename',
    'old_path',
    'new_path',
    'change_type',
    'diff',
    'diff_parsed',
    'num_lines_added',
    'num_lines_deleted',
    'code_after',
    'code_before',
    'nloc',
    'complexity',
    'token_count',
    'programming_language'
]

method_columns = [
    'method_change_id',
    'file_change_id',
    'name',
    'signature',
    'parameters',
    'start_line',
    'end_line',
    'code',
    'nloc',
    'complexity',
    'token_count',
    'top_nesting_level',
    'before_change',
]


class CommitTimeoutError(BaseException):
    pass


def _timeout_handler(signum, frame):
    raise CommitTimeoutError()


def extract_project_links(df_master):
    """
    Extracts all the reference urls from CVE records that match to the repo commit urls.
    Processes row-by-row to avoid large intermediate DataFrames.
    """
    rows = []
    git_url = r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)'
    cf.logger.info('-' * 70)
    cf.logger.info('Extracting all reference URLs from CVEs...')
    for i in range(len(df_master)):
        ref_list = ast.literal_eval(df_master['reference_json'].iloc[i])
        if len(ref_list) > 0:
            for ref in ref_list:
                url = dict(ref)['url']
                link = re.search(git_url, url)
                if link:
                    rows.append({
                        'cve_id': df_master['cve_id'].iloc[i],
                        'hash': link.group('hash'),
                        'repo_url': link.group('repo').replace(r'http:', r'https:')
                    })

    df_fixes = pd.DataFrame(rows, columns=fixes_columns).drop_duplicates().reset_index(drop=True)
    cf.logger.info(f'Found {len(df_fixes)} references to vulnerability fixing commits')
    return df_fixes


_HEX_RE = re.compile(r'^[0-9a-f]+$', re.IGNORECASE)


def resolve_hashes(repo_url, hashes):
    """
    Expand short hashes to full 40-char hashes using a temporary bare clone of
    the repository. Only the commit graph is fetched (--filter=blob:none), so
    this is fast even for large repos and does not interfere with the full clone
    that PyDriller performs later.

    Only genuine abbreviated hashes (hex strings shorter than 40 chars) are
    resolved. Branch names, tag names, or any other non-hex strings are passed
    through unchanged.

    :param repo_url: URL of the repository (with or without .git suffix)
    :param hashes: list of commit hashes (may be short or full)
    :return: list of full 40-char hashes (unresolvable ones are kept as-is)
    """
    clone_url = repo_url if repo_url.endswith('.git') else repo_url + '.git'

    short_hashes = [h for h in hashes if len(h) < 40 and _HEX_RE.match(h)]
    if not short_hashes:
        return hashes  # nothing to resolve

    cf.logger.info(f'Resolving {len(short_hashes)} short hash(es) for {repo_url}...')

    with tempfile.TemporaryDirectory() as tmpdir:
        clone_result = subprocess.run(
            ['git', 'clone', '--bare', '--filter=blob:none', clone_url, tmpdir],
            capture_output=True,
            text=True,
        )
        if clone_result.returncode != 0:
            cf.logger.warning(
                f'Could not clone {repo_url} for hash resolution: {clone_result.stderr.strip()}'
            )
            return hashes  # fall back to originals; PyDriller will surface the error

        resolved = []
        for h in hashes:
            if len(h) == 40 or not _HEX_RE.match(h):
                resolved.append(h)
                continue

            result = subprocess.run(
                ['git', '-C', tmpdir, 'rev-parse', h],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                full_hash = result.stdout.strip()
                cf.logger.info(f'  Resolved short hash {h} -> {full_hash}')
                resolved.append(full_hash)
            else:
                cf.logger.warning(
                    f'  Could not resolve hash {h} for {repo_url}, keeping as-is'
                )
                resolved.append(h)

    return resolved


_EXTENSION_MAP = {
    '.py': 'Python', '.c': 'C', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++',
    '.java': 'Java', '.js': 'JavaScript', '.ts': 'TypeScript', '.go': 'Go',
    '.rb': 'Ruby', '.php': 'PHP', '.rs': 'Rust', '.cs': 'C#', '.h': 'C',
    '.hpp': 'C++', '.sh': 'Shell', '.bash': 'Shell', '.swift': 'Swift',
    '.kt': 'Kotlin', '.scala': 'Scala', '.m': 'Objective-C', '.pl': 'Perl',
    '.lua': 'Lua', '.r': 'R', '.R': 'R',
}

# Single TensorFlow session reused for the entire process lifetime.
# Instantiating Guess() per file would load a new TensorFlow model each time,
# causing unbounded RAM growth over large runs.
_guesser = Guess()


def guess_pl(code, filename=''):
    """:returns guessed programming language of the code or filename"""
    ext = os.path.splitext(filename)[-1].lower()
    if ext in _EXTENSION_MAP:
        return _EXTENSION_MAP[ext]
    if code:
        return _guesser.language_name(code.strip())
    return 'unknown'


def clean_string(signature):
    return signature.strip().replace(' ', '')


def get_method_code(source_code, start_line, end_line):
    try:
        if source_code is not None:
            return '\n'.join(source_code.split('\n')[int(start_line) - 1: int(end_line)])
        return None
    except Exception as e:
        cf.logger.warning(f'Problem while extracting method code from the changed file contents: {e}')


def changed_methods_both(file):
    """Return the sets of new and old methods that were changed."""
    new_methods = file.methods
    old_methods = file.methods_before
    added = file.diff_parsed["added"]
    deleted = file.diff_parsed["deleted"]

    methods_changed_new = {
        y for x in added for y in new_methods if y.start_line <= x[0] <= y.end_line
    }
    methods_changed_old = {
        y for x in deleted for y in old_methods if y.start_line <= x[0] <= y.end_line
    }
    return methods_changed_new, methods_changed_old


def get_methods(file, file_change_id):
    """Returns the list of changed methods in the file."""
    file_methods = []
    try:
        if not file.changed_methods:
            return None

        cf.logger.debug('-' * 70)
        cf.logger.debug('methods_after: ')
        for m in file.methods:
            if m.name != '(anonymous)':
                cf.logger.debug(m.long_name)
        cf.logger.debug('- ' * 35)
        cf.logger.debug('methods_before: ')
        for mb in file.methods_before:
            if mb.name != '(anonymous)':
                cf.logger.debug(mb.long_name)
        cf.logger.debug('- ' * 35)
        cf.logger.debug('changed_methods: ')
        for mc in file.changed_methods:
            if mc.name != '(anonymous)':
                cf.logger.debug(mc.long_name)
        cf.logger.debug('-' * 70)

        methods_after, methods_before = changed_methods_both(file)

        if methods_before:
            for mb in methods_before:
                if file.source_code_before is not None and mb.name != '(anonymous)':
                    file_methods.append({
                        'method_change_id': uuid.uuid4().fields[-1],
                        'file_change_id': file_change_id,
                        'name': mb.name,
                        'signature': mb.long_name,
                        'parameters': mb.parameters,
                        'start_line': mb.start_line,
                        'end_line': mb.end_line,
                        'code': get_method_code(file.source_code_before, mb.start_line, mb.end_line),
                        'nloc': mb.nloc,
                        'complexity': mb.complexity,
                        'token_count': mb.token_count,
                        'top_nesting_level': mb.top_nesting_level,
                        'before_change': 'True',
                    })

        if methods_after:
            for mc in methods_after:
                if file.source_code is not None and mc.name != '(anonymous)':
                    file_methods.append({
                        'method_change_id': uuid.uuid4().fields[-1],
                        'file_change_id': file_change_id,
                        'name': mc.name,
                        'signature': mc.long_name,
                        'parameters': mc.parameters,
                        'start_line': mc.start_line,
                        'end_line': mc.end_line,
                        'code': get_method_code(file.source_code, mc.start_line, mc.end_line),
                        'nloc': mc.nloc,
                        'complexity': mc.complexity,
                        'token_count': mc.token_count,
                        'top_nesting_level': mc.top_nesting_level,
                        'before_change': 'False',
                    })

        return file_methods if file_methods else None

    except Exception as e:
        cf.logger.warning(f'Problem while fetching the methods: {e}')
        return None


def get_files(commit):
    """Returns the list of files and methods of the commit."""
    commit_files = []
    commit_methods = []
    try:
        #cf.logger.info(f'Extracting files for {commit.hash}')
        if commit.modified_files:
            for file in commit.modified_files:
                cf.logger.debug(f'Processing file {file.filename} in {commit.hash}')
                programming_language = guess_pl(file.source_code, file.filename)
                file_change_id = uuid.uuid4().fields[-1]

                commit_files.append({
                    'file_change_id': file_change_id,
                    'hash': commit.hash,
                    'filename': file.filename,
                    'old_path': file.old_path,
                    'new_path': file.new_path,
                    'change_type': file.change_type,
                    'diff': file.diff,
                    'diff_parsed': file.diff_parsed,
                    'num_lines_added': file.added_lines,
                    'num_lines_deleted': file.deleted_lines,
                    'code_after': file.source_code,
                    'code_before': file.source_code_before,
                    'nloc': file.nloc,
                    'complexity': file.complexity,
                    'token_count': file.token_count,
                    'programming_language': programming_language,
                })

                file_methods = get_methods(file, file_change_id)
                if file_methods is not None:
                    commit_methods.extend(file_methods)
        else:
            cf.logger.info('The list of modified_files is empty')

        return commit_files, commit_methods

    except Exception as e:
        cf.logger.warning(f'Problem while fetching the files: {e}')
        return [], []


def _flush_to_db(conn, commit_row, commit_files, commit_methods):
    """
    Write one commit's data to the DB immediately and release memory.
    chunksize=500 avoids SQLite parameter limit on large file/method lists.
    """
    df_commit = pd.DataFrame([commit_row])[commit_columns].applymap(str)
    df_commit.to_sql(name='commits', con=conn, if_exists='append', index=False)

    if commit_files:
        df_file = pd.DataFrame(commit_files)[file_columns].applymap(str)
        df_file.to_sql(name='file_change', con=conn, if_exists='append', index=False, chunksize=500)

    if commit_methods:
        df_method = pd.DataFrame(commit_methods)[method_columns].applymap(str)
        df_method.to_sql(name='method_change', con=conn, if_exists='append', index=False, chunksize=500)


def extract_commits(repo_url, hashes, conn):
    """
    Extracts git commit information for the given hashes and writes each commit
    directly to the database as it is processed. RAM usage stays constant
    regardless of repository or commit size — no lists are accumulated.

    Short hashes extracted from CVE reference URLs are resolved to full 40-char
    hashes via a temporary bare clone before being passed to PyDriller, which
    requires full hashes to locate commits reliably. Resolved hashes are also
    written back to the fixes table so the resume logic works correctly on restart.

    Each commit is processed with a timeout of COMMIT_TIMEOUT_SECONDS to avoid
    hanging on commits where lizard's code analysis loops indefinitely (e.g.
    certain Ruby files). The timeout is cancelled before any DB write to prevent
    corrupting the database if the signal fires mid-transaction.

    :param repo_url: URL of the repository
    :param hashes: list of commit hashes to collect (may be short or full)
    :param conn: active sqlite3 database connection
    :return: tuple (num_commits, num_files, num_methods) written to DB
    """
    n_commits = n_files = n_methods = 0

    if 'github' in repo_url:
        repo_url = repo_url + '.git'

    # Resolve any short hashes to full 40-char hashes before passing to PyDriller
    original_hashes = list(hashes)
    hashes = resolve_hashes(repo_url, hashes)

    # Update fixes table with resolved full hashes so resume logic works correctly
    # on restart — without this, short hashes in fixes never match full hashes in commits
    clean_repo_url = repo_url.rsplit('.git')[0]
    for original, resolved in zip(original_hashes, hashes):
        if original != resolved:
            cf.logger.info(f'Updating fixes table: {original} -> {resolved}')
            conn.execute(
                'UPDATE fixes SET hash = ? WHERE hash = ? AND repo_url = ?',
                (resolved, original, clean_repo_url)
            )
            conn.commit()

    cf.logger.debug(
        f'Extracting commits for {repo_url} with {cf.NUM_WORKERS} worker(s), '
        f'looking for {len(hashes)} hash(es):'
    )
    log_commit_urls(repo_url, hashes)

    requested_hashes = set(hashes)

    for commit in Repository(
        path_to_repo=repo_url,
        only_commits=list(requested_hashes),
        num_workers=cf.NUM_WORKERS,
        include_refs=True,
        include_remotes=True
    ).traverse_commits():

        # required since pydriller will include further commits when using include_refs=True and include_remotes=True
        if commit.hash not in requested_hashes:
            cf.logger.debug(f'Skipping unrequested commit {commit.hash}')
            continue

        cf.logger.info(f'Processing {commit.hash}: {len(commit.modified_files)} modified files')
        commit_files = []
        commit_methods = []
        try:
            # Set alarm only around the PyDriller/lizard processing — never during DB writes
            # to prevent SIGALRM from corrupting a mid-transaction SQLite write
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(COMMIT_TIMEOUT_SECONDS)
            try:
                commit_row = {
                    'hash': commit.hash,
                    'repo_url': clean_repo_url,  # store the repo url in original form
                    'author': commit.author.name,
                    'author_date': commit.author_date,
                    'author_timezone': commit.author_timezone,
                    'committer': commit.committer.name,
                    'committer_date': commit.committer_date,
                    'committer_timezone': commit.committer_timezone,
                    'msg': commit.msg,
                    'merge': commit.merge,
                    'parents': commit.parents,
                    'num_lines_added': commit.insertions,
                    'num_lines_deleted': commit.deletions
                }
                commit_files, commit_methods = get_files(commit)

            except CommitTimeoutError:
                cf.logger.warning(
                    f'Timed out processing {commit.hash} after {COMMIT_TIMEOUT_SECONDS}s, skipping'
                )
                continue
            finally:
                # Always cancel alarm before DB write so signal cannot fire mid-transaction
                signal.alarm(0)

            # DB write is now outside the alarm window — cannot be interrupted by SIGALRM
            with conn:
                _flush_to_db(conn, commit_row, commit_files, commit_methods)

            n_commits += 1
            n_files += len(commit_files)
            n_methods += len(commit_methods)

            # Explicitly free large objects each iteration
            del commit_files, commit_methods

        except Exception as e:
            cf.logger.warning(f'Problem while fetching the commits: {e}')

    return n_commits, n_files, n_methods