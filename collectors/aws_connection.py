"""Create a short-lived AWS session for a scoped PathGuard connection."""

import re


DEFAULT_ROLE_SESSION_NAME = "PathGuardReadOnly"
ROLE_SESSION_NAME_PATTERN = re.compile(r"^[\w+=,.@-]{2,64}$")
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


def create_aws_session(region, profile=None, role_arn=None, external_id=None,
                       role_session_name=DEFAULT_ROLE_SESSION_NAME):
    """Create a boto3 session from the normal chain or by assuming one role.

    Cross-account mode requires an ExternalId and returns a session containing
    temporary credentials. This is intended for bounded collection runs; if a
    collection can exceed the STS session duration, rerun it in smaller scopes.
    """
    if role_arn and not external_id:
        raise ValueError("ExternalId is required when assuming a customer role")
    if external_id and not role_arn:
        raise ValueError("Role ARN is required when an ExternalId is provided")
    if not ROLE_SESSION_NAME_PATTERN.fullmatch(str(role_session_name)):
        raise ValueError("Role session name must be 2-64 AWS-safe characters")

    import boto3
    from botocore.config import Config

    client_config = Config(
        connect_timeout=5,
        read_timeout=15,
        retries={"mode": "standard", "total_max_attempts": 3},
        max_pool_connections=10,
    )
    source_session = boto3.Session(profile_name=profile, region_name=region)
    if not role_arn:
        return source_session

    sts = source_session.client("sts", config=client_config)
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=role_session_name,
        ExternalId=external_id,
        DurationSeconds=3600,
    )
    credentials = response.get("Credentials") or {}
    required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
    if any(not credentials.get(key) for key in required):
        raise ValueError("STS AssumeRole returned incomplete temporary credentials")

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def verify_caller_identity(session, expected_account_id=None, client=None):
    """Return the identity behind a session and optionally bind it to an account.

    ``connection_id``/account metadata emitted by a local collector is only
    provenance. A future authenticated ingestion service must derive tenant
    ownership from its server-side connection registry, not from this payload.
    """
    if expected_account_id is not None and not ACCOUNT_ID_PATTERN.fullmatch(str(expected_account_id)):
        raise ValueError("Expected AWS account ID must contain exactly 12 digits")

    if client is None:
        from botocore.config import Config

        client = session.client("sts", config=Config(
            connect_timeout=5,
            read_timeout=15,
            retries={"mode": "standard", "total_max_attempts": 3},
            max_pool_connections=10,
        ))
    response = client.get_caller_identity()
    account_id = response.get("Account")
    arn = response.get("Arn")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ValueError("STS GetCallerIdentity returned an invalid AWS account ID")
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        raise ValueError("STS GetCallerIdentity returned an invalid principal ARN")
    if expected_account_id is not None and account_id != expected_account_id:
        raise ValueError("AWS caller account does not match the expected connection account")
    return {"account_id": account_id, "principal_arn": arn}
