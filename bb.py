#!/usr/bin/env python3

"""
Usage:
    bb.py (pr|pull_request) next
    bb.py (pr|pull_request) info <pr_id>
    bb.py (pr|pull_request) approve <pr_id>
    bb.py (pr|pull_request) unapprove (updated|all|<pr_id>)
    bb.py (pr|pull_request) comment add <pr_id> <comment>
    bb.py commit set tested <hash>
    bb.py commit set build_status <username> <repo> <revision> <state> <job_url> <build_key>
"""

import datetime
import logging
import os
import sys
from os.path import expanduser

import requests
import yaml
from docopt import docopt

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

CACHE_DIR = '~/.bb_cli_client'


class BitBucket(object):
    """
    Allows to access various feature of the BitBucket cloud API.
    """

    def __init__(self, user, repo, auth_user, auth_pass, key, default_parameters=None):
        self._user = user
        self._repo = repo
        self._base_uri = self._build_base_uri(user, repo)
        self._default_parameters = default_parameters or {'page': 1, 'pagelen': 50}
        self._cachedir = expanduser('{}/bitbucket/{}/{}/{}'
                                    .format(CACHE_DIR, self._user, self._repo, key))
        self._hashfile = '{}/hashes.yml'.format(self._cachedir)

        self._pull_requests_commits_cache = {}

        self._request_session = requests.session()
        self._request_session.auth = (auth_user, auth_pass)

    @staticmethod
    def _build_base_uri(user, repo, v2=True):
        if v2:
            return 'https://api.bitbucket.org/2.0/repositories/{}/{}'.format(user, repo)
        else:
            return 'https://api.bitbucket.org/1.0/repositories/{}/{}'.format(user, repo)

    def _get(self, user, repo, resource):
        base_uri = self._base_uri
        if user and repo:
            base_uri = self._build_base_uri(user, repo)
        return self._request_session.get('{}/{}'.format(base_uri, resource),
                                         params=self._default_parameters)

    def _post(self, resource, data=None, user=None, repo=None, v2=True):
        base_uri = self._base_uri
        if user and repo:
            base_uri = self._build_base_uri(user, repo, v2=v2)
        elif not v2:
            base_uri = self._build_base_uri(self._user, self._repo, False)
        return self._request_session.post('{}/{}'.format(base_uri, resource),
                                          params=self._default_parameters if v2 else None,
                                          data=data)

    def _delete(self, resource, data=None):
        return self._request_session.delete('{}/{}'.format(self._base_uri, resource),
                                            params=self._default_parameters, data=data)

    def get_pull_request(self, pr_id):
        resp = self._get(self._user, self._repo, 'pullrequests/{pr_id}'.format(pr_id=pr_id))
        resp.raise_for_status()

        data = resp.json()
        return data

    def get_pull_requests(self, ignores=None):
        logger.info('Fetching pull requests...')

        resp = self._get(self._user, self._repo, 'pullrequests')
        resp.raise_for_status()

        data = resp.json()

        # TODO retrieve all available data if it's more than "one page"
        assert 'next' not in data

        if ignores:
            data['values'] = [pr for pr in data['values']
                              if not any(ignore.lower() in pr['title'].lower()
                                         for ignore in ignores)]

        return data['values']

    def get_commits_of_pull_request(self, pr_id):
        if pr_id in self._pull_requests_commits_cache:
            return self._pull_requests_commits_cache[pr_id]

        logger.info('Fetching pull request commits...')

        resp = self._get(self._user, self._repo, 'pullrequests/{}/commits'.format(pr_id))
        resp.raise_for_status()

        data = resp.json()

        self._pull_requests_commits_cache[pr_id] = data['values']

        return data['values']

    def add_comment(self, pr_id, comment):
        resp = self._post('pullrequests/{pull_request_id}/comments'.format(pull_request_id=pr_id),
                          v2=False, data={'content': comment})
        resp.raise_for_status()

        return resp

    def approve_pull_request(self, pr_id):
        # https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Busername%7D/%7Brepo_slug%7D/pullrequests/%7Bpull_request_id%7D/approve
        resp = self._post('pullrequests/{pull_request_id}/approve'.format(pull_request_id=pr_id))
        resp.raise_for_status()
        logger.info('Approved PR#{}'.format(pr_id))

        return resp

    def unapprove_pull_request(self, pr_id):
        resp = self._delete('pullrequests/{pull_request_id}/approve'.format(pull_request_id=pr_id))
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            if 'error' in resp.json() and 'message' in resp.json()['error'] and \
                            resp.json()['error']['message'] == \
                            'You haven\'t approved this pull request.':
                pass
            else:
                raise e

        logger.info('Unapproved PR#{}'.format(pr_id))

        return resp

    def set_build_status_of_commit(self, user, repo, revision, state, job_url, build_key):
        iso_date = datetime.datetime.utcnow().isoformat()
        data = {
            'state': state,
            'key': build_key,
            'url': job_url,
            'created_on': iso_date,
            'updated_on': iso_date
        }
        resp = self._post('commit/{revision}/statuses/build'.format(revision=revision), data=data,
                          user=user, repo=repo)
        resp.raise_for_status()

        return resp

    def get_build_status_of_commit(self, user, repo, revision, build_key):
        """
        :param user: The BitBucket username
        :param repo: The name of the BitBucket repository
        :param revision:
        :param build_key: Unique name for a specific kind of test, e.g. "E2E Tests".
        :return:
        """
        resp = self._get(user, repo, 'commit/{revision}/statuses/build/{key}'.format(
            revision=revision, key=build_key))
        resp.raise_for_status()

        return resp

    def store_hashes(self, hashes):
        logger.debug('Storing hashes in {}'.format(self._hashfile))
        if not os.path.isdir(self._cachedir):
            os.makedirs(self._cachedir)
        with open(self._hashfile, 'w') as stream:
            yaml.dump(hashes, stream)

    def load_hashes(self):
        logger.debug('Loading hashes from {}'.format(self._hashfile))
        if not os.path.isdir(self._cachedir):
            return {}
        if not os.access(self._hashfile, os.R_OK):
            return {}

        with open(self._hashfile, 'r') as stream:
            try:
                return yaml.load(stream)
            except yaml.YAMLError:
                return {}

    def get_oldest_untested_pr(self, ignores=None, append_last=None):
        """
        Will return the oldest untested pull requests minus the ignore. The tags given in `latest`
        will be used to parse the titles of the pull requests and returned last.
        :param ignores: Tags to look for in titles to be ignored.
        :param append_last: Tags to look for in titles to be sorted at the end of the list.
        :return:
        """
        pull_requests = reversed(self.get_pull_requests(ignores))
        pull_requests = sorted(pull_requests, key=lambda pr: any(tag.lower() in pr['title'].lower()
                                                                 for tag in append_last))

        for pull_request in pull_requests:
            commits = self.get_commits_of_pull_request(pull_request['id'])
            hashes = {k: v for k, v in self.load_hashes().items() if v['tested']}
            if commits[0]['hash'] not in hashes:
                return {
                    'pull-request': pull_request,
                    'commit': commits[0],
                }

        return {}  # Nothing to test


if __name__ == '__main__':
    config_path = '{}/config.yml'.format(os.path.dirname(os.path.realpath(__file__)))
    if not os.access(config_path, os.R_OK):
        logger.error('File `config.yml` is not accessible')

    with open(config_path, 'r') as f:
        config = yaml.load(f)
        config = config['bitbucket']

    bb_client = BitBucket(config['username'],
                          config['repository'],
                          config['credentials']['username'],
                          config['credentials']['password'],
                          config['key'])

    args = docopt(__doc__)

    if args['pr'] or args['pull_request']:

        if args['next']:
            ignores = config['ignores'] if 'ignores' in config else []
            append_last = config['append_last'] if 'append_last' in config else []
            pr_data = bb_client.get_oldest_untested_pr(ignores, append_last)

            if not pr_data:
                logger.error('No pull request found!')
                sys.exit(1)

            username, repo = pr_data['pull-request']['source']['repository']['full_name'].split(
                '/')
            branch = pr_data['pull-request']['source']['branch']['name']
            fork_url = pr_data['pull-request']['source']['repository']['links']['html']['href']
            revision = pr_data['commit']['hash']
            pr_id = pr_data['pull-request']['id']

            sys.stdout.write('{username} {repo} {fork} {revision} {branch} {pr_id}\n'.format(
                username=username,
                repo=repo,
                fork=fork_url,
                revision=revision,
                branch=branch,
                pr_id=pr_id,
            ))

        elif args['approve']:
            bb_client.approve_pull_request(args['<pr_id>'])

        elif args['unapprove']:

            if args['all']:
                for pr in bb_client.get_pull_requests():
                    bb_client.unapprove_pull_request(pr['id'])

            elif args['updated']:
                for pull_request in bb_client.get_pull_requests():
                    commits = bb_client.get_commits_of_pull_request(pull_request['id'])
                    hashes = bb_client.load_hashes()
                    if commits[0]['hash'] not in hashes:
                        bb_client.unapprove_pull_request(pull_request['id'])

            else:
                bb_client.unapprove_pull_request(args['<pr_id>'])

        elif args['comment'] and args['add']:
            bb_client.add_comment(args['<pr_id>'], args['<comment>'])

        elif args['info']:
            pr = bb_client.get_pull_request(args['<pr_id>'])
            commits = bb_client.get_commits_of_pull_request(pr['id'])

            username, repo = pr['source']['repository']['full_name'].split(
                '/')
            branch = pr['source']['branch']['name']
            fork_url = pr['source']['repository']['links']['html']['href']
            revision = commits[0]['hash']
            pr_id = pr['id']

            sys.stdout.write('{username} {repo} {fork} {revision} {branch} {pr_id}\n'.format(
                username=username,
                repo=repo,
                fork=fork_url,
                revision=revision,
                branch=branch,
                pr_id=pr_id,
            ))

    elif args['commit']:

        if args['set']:

            if args['tested']:
                hashes = bb_client.load_hashes()
                hashes[args['<hash>']] = {
                    'tested': True,
                }
                bb_client.store_hashes(hashes)

            elif args['build_status']:
                bb_client.set_build_status_of_commit(
                    args['<username>'],
                    args['<repo>'],
                    args['<revision>'],
                    args['<state>'],
                    args['<job_url>'],
                    args['<build_key>'])
