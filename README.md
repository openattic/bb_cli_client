# BB CLI Client

This project enables you to connect to Bitbucket using a CLI and retreiving various
information as well as doing some actions like, approving pull requests. 
It's configurable using a YAML configuration file `config.yml` and has been created to work in a
Jenkins job and allow the job to retrieve information about a single pull request and do something
with it, like testing or packaging. 

## Example configuration

See `config.yml.example`.

## Usage

```
bb.py (pr|pull_request) next
bb.py (pr|pull_request) info <pr_id>
bb.py (pr|pull_request) approve <pr_id>
bb.py (pr|pull_request) unapprove (updated|all|<pr_id>)
bb.py (pr|pull_request) comment add <pr_id> <comment>
bb.py commit set tested <hash>
bb.py commit set build_status <username> <repo> <revision> <state> <job_url> <build_key>
```

## Installation

### Dependecies

```bash
pip3 install -r requirements.txt
```

### Jenkins Job

The following script is a working example and may be used inside a Jenkins job to retrieve the 
"next" pull request, do some actions on that pull request (packaging, testing, etc) and store the
information that it has been progressed, so that it won't retreive this pull request
unless the revision at HEAD of this pull request has been changed.

```bash
#!/bin/bash

set -ex

SCRIPT="/srv/bb_cli_client/bb.py"

# If the PR has been approved and the latest commit hash is not in the list of already checked
# hashes, unapprove this PR
python3 $SCRIPT pr unapprove updated

# Get next PR data
result=($(python3 $SCRIPT pr next))

username="${result[0]}"
repo="${result[1]}"
fork="${result[2]}"
revision="${result[3]}"
branch="${result[4]}"
pr_id="${result[5]}"

# Start the test
test_result=0

if [ "$test_result" -eq "0" ]; then
  python3 $SCRIPT pr approve $pr_id
  python3 $SCRIPT pr comment add $pr_id "Testing revision ${revision} has succeeded."
else
  python3 $SCRIPT pr comment add $pr_id "Testing revision ${revision} has failed. Build ID is #${BUILD_NUMBER}"
fi

# Mark the specified revision as being "tested"
python3 $SCRIPT commit set tested $revision
```

## TODO

 * ~~The script should return those pull requests which are WIP if all others have been tested.~~ 
 This is already implemented and may be used by using the `append_last` setting.