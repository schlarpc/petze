import argparse
import base64
import collections
import contextlib
import datetime
import decimal
import email.parser
import email.policy
import functools
import gzip
import hashlib
import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional, Union, cast

import boto3
import boto3.resources.base
import jmespath

from . import storage

JSONType = Union[str, float, int, bool, None, Dict[str, Any], List[Any]]


def extract_probe_name_from_domain(request_domain: str) -> str:
    pattern = r"^([a-z0-9]+)\." + re.escape(os.environ["PETZE_DOMAIN_NAME"]) + r"\.?$"
    if match := re.match(pattern, request_domain):
        return match.group(1)
    return ""


def calculate_event_expiration(timestamp: datetime.datetime) -> datetime.datetime:
    delta = datetime.timedelta(days=int(os.environ["PETZE_EVENT_TTL_DAYS"]))
    return timestamp + delta


@functools.lru_cache(maxsize=1)
def get_storage() -> storage.ProbeStorage:
    return storage.ProbeStorage(
        table=boto3.resource("dynamodb").Table(os.environ["PETZE_STORAGE_TABLE"]),
        bucket=boto3.resource("s3").Bucket(os.environ["PETZE_STORAGE_BUCKET"]),
    )


def lambda_handler(fn):
    @functools.wraps(fn)
    def wrapper(event: JSONType, _context: Optional[Any] = None) -> JSONType:
        if not isinstance(event, dict):
            return None
        return fn(event)

    return wrapper


def hash_event_id(source_event_id: str) -> str:
    return hashlib.sha256(source_event_id.encode("utf-8")).hexdigest()[:32]


def dynamodb_to_json_default(obj) -> JSONType:
    if isinstance(obj, set):
        return sorted(obj)
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    elif isinstance(obj, decimal.Decimal):
        if obj.normalize().as_tuple().exponent >= 0:
            return int(obj)
        return float(obj)
    raise ValueError(f"Unknown data type: {type(obj)}")


def send_cloudformation_response(event: Dict[str, Any], **kwargs):
    response = {
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        **kwargs,
    }
    request = urllib.request.Request(
        url=event["ResponseURL"],
        method="PUT",
        headers={"Content-type": ""},
        data=json.dumps(response).encode("utf-8"),
    )
    return urllib.request.urlopen(request)


@contextlib.contextmanager
def cloudformation_custom_resource_error_catcher(event: Dict[str, Any]):
    try:
        yield
    except Exception as ex:
        send_cloudformation_response(
            event,
            Status="FAILED",
            PhysicalResourceId=event.get("PhysicalResourceId", event["RequestId"]),
            Reason=f"{type(ex).__name__}: {ex}",
        )


@lambda_handler
def api_handler(event: Dict[str, Any]) -> JSONType:
    probe_name = extract_probe_name_from_domain(event["requestContext"]["domainName"])
    timestamp = datetime.datetime.fromtimestamp(
        event["requestContext"]["requestTimeEpoch"] / 1000
    )
    get_storage().events().put(
        probe_name=probe_name,
        event=storage.ProbeEvent(
            type=storage.ProbeEventType.HTTP,
            id=hash_event_id(event["requestContext"]["requestId"]),
            timestamp=timestamp,
            expiration=calculate_event_expiration(timestamp),
            data={
                "method": event["httpMethod"],
                "path": event["path"],
                "parameters": event["multiValueQueryStringParameters"],
                "headers": event["multiValueHeaders"],
            },
            body=base64.b64decode(event["body"]) if event["isBase64Encoded"] else event["body"],
        ),
    )
    if event["httpMethod"] == "GET":
        definition = get_storage().definitions().get(probe_name)
    else:
        definition = get_storage().definitions().get("")
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": definition.payload.type,
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age": "1728000",
        },
        "body": base64.b64encode(definition.payload.content),
        "isBase64Encoded": True,
    }


@lambda_handler
def dns_log_function_handler(event: Dict[str, Any]) -> None:
    logs = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    for log in logs.get("logEvents", []):
        log_fields = log["message"].split(" ")[:10]
        probe_name = extract_probe_name_from_domain(log_fields[3])
        timestamp = datetime.datetime.strptime(log_fields[1], "%Y-%m-%dT%H:%M:%S%z")
        get_storage().events().put(
            probe_name=probe_name,
            event=storage.ProbeEvent(
                type=storage.ProbeEventType.DNS,
                id=hash_event_id(log["id"]),
                timestamp=timestamp,
                expiration=calculate_event_expiration(timestamp),
                data={
                    "query_type": log_fields[4],
                    "resolver_ip": log_fields[8],
                    "client_subnet": log_fields[9] if log_fields[9] != "-" else None,
                },
            ),
        )


@lambda_handler
def email_handler(event: Dict[str, Any]) -> None:
    messages = (json.loads(record["Sns"]["Message"]) for record in event["Records"])
    for message in messages:
        print(json.dumps(message))
        probe_name = extract_probe_name_from_domain(
            message["receipt"]["recipients"][0].rsplit("@", 1)[1]
        )
        timestamp = datetime.datetime.strptime(
            message["receipt"]["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z"
        )
        parser = email.parser.BytesParser(policy=email.policy.default)
        email_body = cast(
            email.message.EmailMessage,
            cast(
                email.message.EmailMessage,
                parser.parsebytes(base64.b64decode(message["content"])),
            ).get_body(),
        )

        get_storage().events().put(
            probe_name=probe_name,
            event=storage.ProbeEvent(
                type=storage.ProbeEventType.EMAIL,
                id=hash_event_id(message["mail"]["messageId"]),
                timestamp=timestamp,
                expiration=calculate_event_expiration(timestamp),
                data={
                    "return_path": message["mail"]["commonHeaders"]["returnPath"],
                    "from": message["mail"]["commonHeaders"]["from"],
                    "to": message["mail"]["commonHeaders"]["to"],
                    "subject": message["mail"]["commonHeaders"]["subject"],
                },
                body=email_body.get_content() if email_body else None,
            ),
        )


def _decode_dynamodb_item(item):
    return {
        "B": base64.b64decode,
        "BOOL": bool,
        "BS": lambda bs: set(_decode_dynamodb_item({"B": i}) for i in bs),
        "L": lambda l: list(_decode_dynamodb_item(i) for i in l),
        "M": lambda m: dict((k, _decode_dynamodb_item(v)) for k, v in m.items()),
        "N": decimal.Decimal,
        "NS": lambda ns: set(_decode_dynamodb_item({"N": i}) for i in ns),
        "NULL": lambda _: None,
        "S": str,
        "NS": lambda ss: set(_decode_dynamodb_item({"S": i}) for i in ss),
    }[next(iter(item.keys()))](next(iter(item.values())))


@lambda_handler
def notification_stream_handler(event: Dict[str, Any]) -> None:
    sns = boto3.client("sns")
    for record in event["Records"]:
        item = _decode_dynamodb_item({"M": record["dynamodb"]["NewImage"]})
        definition = get_storage().definitions().get(item["probe"])
        if definition.notify:
            sns.publish(
                TopicArn=os.environ["PETZE_NOTIFICATION_TOPIC"],
                Message=json.dumps(item, default=dynamodb_to_json_default),
            )


@lambda_handler
def notification_slack_handler(event: Dict[str, Any]) -> None:
    messages = (json.loads(record["Sns"]["Message"]) for record in event["Records"])
    for message in messages:
        urllib.request.urlopen(
            urllib.request.Request(
                os.environ["PETZE_SLACK_WEBHOOK_URL"],
                data=json.dumps(
                    {"text": "```" + json.dumps(message, indent=4) + "```"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
        )


@lambda_handler
def certificate_validator_handler(event: Dict[str, Any]) -> None:
    records = set(
        (record["Name"], record["Type"], record["Value"])
        for record in jmespath.search(
            "Certificate.DomainValidationOptions[].ResourceRecord",
            boto3.client("acm").describe_certificate(
                CertificateArn=event["detail"]["requestParameters"]["certificateArn"],
            ),
        )
    )

    response = boto3.client("route53").change_resource_record_sets(
        HostedZoneId=os.environ["HOSTED_ZONE_ID"],
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": name,
                        "Type": type,
                        "ResourceRecords": [{"Value": value}],
                        "TTL": 300,
                    },
                }
                for name, type, value in records
            ]
        },
    )


@lambda_handler
def log_policy_custom_resource_handler(event: Dict[str, Any]) -> None:
    with cloudformation_custom_resource_error_catcher(event):
        logs = boto3.client("logs")
        if event["RequestType"] in {"Create", "Update"}:
            logs.put_resource_policy(
                policyName=event["ResourceProperties"]["PolicyName"],
                policyDocument=json.dumps(
                    event["ResourceProperties"]["PolicyDocument"]
                ),
            )
            send_cloudformation_response(
                event,
                Status="SUCCESS",
                PhysicalResourceId=event["ResourceProperties"]["PolicyName"],
            )
        elif event["RequestType"] == "Delete":
            logs.delete_resource_policy(policyName=event["PhysicalResourceId"])
            send_cloudformation_response(
                event, Status="SUCCESS", PhysicalResourceId=event["PhysicalResourceId"]
            )


@lambda_handler
def active_receipt_rule_set_custom_resource_handler(event: Dict[str, Any]) -> None:
    with cloudformation_custom_resource_error_catcher(event):
        ses = boto3.client("ses")
        if event["RequestType"] in {"Create", "Update"}:
            ses.set_active_receipt_rule_set(
                RuleSetName=event["ResourceProperties"]["RuleSetName"],
            )
            send_cloudformation_response(
                event,
                Status="SUCCESS",
                PhysicalResourceId=event["ResourceProperties"]["RuleSetName"],
            )
        elif event["RequestType"] == "Delete":
            response = ses.describe_active_receipt_rule_set()
            if event["PhysicalResourceId"] == response.get("Metadata", {}).get("Name"):
                ses.set_active_receipt_rule_set()
            send_cloudformation_response(
                event, Status="SUCCESS", PhysicalResourceId=event["PhysicalResourceId"]
            )


@lambda_handler
def domain_verification_custom_resource_handler(event: Dict[str, Any]) -> None:
    with cloudformation_custom_resource_error_catcher(event):
        ses = boto3.client("ses")
        if event["RequestType"] in {"Create", "Update"}:
            response = ses.verify_domain_identity(
                Domain=event["ResourceProperties"]["Domain"],
            )
            send_cloudformation_response(
                event,
                Status="SUCCESS",
                PhysicalResourceId=event["ResourceProperties"]["Domain"],
                Data={"VerificationToken": response["VerificationToken"]},
            )
        elif event["RequestType"] == "Delete":
            ses.delete_identity(Identity=event["ResourceProperties"]["Domain"])
            send_cloudformation_response(
                event, Status="SUCCESS", PhysicalResourceId=event["PhysicalResourceId"]
            )
