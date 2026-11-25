#!/usr/bin/env bash
set -euo pipefail
umask 077

# Bootstrap one public GitHub Actions source on the PathGuard demo instance.
# The connector credential is minted on this instance; no local secret is sent to AWS.
state=/opt/pathguard/cicd-github
image='920235987407.dkr.ecr.ap-southeast-2.amazonaws.com/pathguard/demo-api@sha256:5949d320db883998217e7aa35ae233e249387d60baf1444e92e6a36e46662dad'
registry='920235987407.dkr.ecr.ap-southeast-2.amazonaws.com'
mkdir -p "$state"
chmod 700 "$state"

if [[ ! -s "$state/connector.token" ]]; then
  python3 - <<'PY'
import json
import os
import pathlib
import subprocess
import urllib.parse
import urllib.request

base = 'https://pathguard.parkinguth.sbs'
password = subprocess.check_output([
    'aws', 'ssm', 'get-parameter', '--region', 'ap-southeast-2',
    '--name', '/pathguard/demo/demo-user-password', '--with-decryption',
    '--query', 'Parameter.Value', '--output', 'text'
], text=True).strip()
login_body = urllib.parse.urlencode({
    'grant_type': 'password', 'client_id': 'pathguard-local-cli',
    'username': 'demo-admin', 'password': password,
}).encode()
password = None

def post(path, body, authorization=None, content_type='application/json'):
    headers = {'Content-Type': content_type}
    if authorization:
        headers['Authorization'] = authorization
    request = urllib.request.Request(base + path, data=body, headers=headers, method='POST')
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)

human = post('/auth/realms/pathguard/protocol/openid-connect/token',
             login_body, content_type='application/x-www-form-urlencoded')
enrollment = post('/api/v1/connectors/enrollments', json.dumps({
    'connectorType': 'CI_CD', 'connectionId': 'github-momo-contest-ec2',
    'expiresInSeconds': 300,
}).encode(), 'Bearer ' + human['access_token'])
issued = post('/api/v1/connectors/enroll', json.dumps({
    'enrollmentToken': enrollment['enrollmentToken'],
}).encode())
credential = pathlib.Path('/opt/pathguard/cicd-github/connector.token')
fd = os.open(credential, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as handle:
    handle.write(issued['connectorToken'])
os.chown(credential, 10001, 10001)
print('Created CI_CD connector on demo instance:', issued['connectorId'])
PY
fi

cat > "$state/config.json" <<'JSON'
{
  "schema_version": "pathguard.cicd-connector.v1",
  "connection_id": "github-momo-contest-ec2",
  "provider": "github_actions",
  "repository": "dungdinhhaha/MOMO-CONTEST",
  "service": "pathguard-connector",
  "environment": "ci",
  "workflow_names": ["PathGuard connector CI"],
  "deploy_job_names": [],
  "backend_url": "https://pathguard.parkinguth.sbs",
  "credential_file": "/state/connector.token",
  "state_file": "/state/sync-state.json"
}
JSON
chmod 600 "$state/config.json" "$state/connector.token"
chown -R 10001:10001 "$state"

docker_config="$(mktemp -d /run/pathguard-ecr-XXXXXX)"
chmod 700 "$docker_config"
trap 'rm -rf "$docker_config"' EXIT
aws ecr get-login-password --region ap-southeast-2 |
  docker --config "$docker_config" login --username AWS --password-stdin "$registry" >/dev/null
docker --config "$docker_config" pull "$image" >/dev/null

if docker container inspect pathguard-cicd-github >/dev/null 2>&1; then
  docker rm -f pathguard-cicd-github >/dev/null
fi
docker run -d --name pathguard-cicd-github --restart unless-stopped \
  --network host --add-host pathguard.parkinguth.sbs:127.0.0.1 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 100 --memory 128m --cpus 0.25 \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --volume "$state:/state:rw" "$image" \
  --config /state/config.json --interval 300 >/dev/null

sleep 8
docker inspect pathguard-cicd-github --format '{{.State.Status}}'
docker logs --tail 5 pathguard-cicd-github
