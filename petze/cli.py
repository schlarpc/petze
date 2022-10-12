import argparse
import json
from typing import Dict, List, Optional

import boto3

from .handlers import dynamodb_to_json_default


def get_stack_outputs(session: boto3.Session, stack_name: str) -> Dict[str, str]:
    cloudformation = session.client("cloudformation")
    stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {
        output["OutputKey"]: output["OutputValue"]
        for output in stack.get("Outputs", [])
    }


def get_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", "-r")
    parser.add_argument("--stack", "-s", default="Petze")

    objects = parser.add_subparsers(required=True, dest="object")

    probe = objects.add_parser("probe")
    probe_commands = probe.add_subparsers(required=True, dest="command")

    probe_list = probe_commands.add_parser("list")

    probe_put = probe_commands.add_parser("put")
    probe_put.add_argument("--name")
    probe_put.add_argument("--payload")
    # add_argument notify/no-notify

    probe_events = probe_commands.add_parser("events")
    probe_events.add_argument("probe")

    payload = objects.add_parser("payload")
    payload_commands = payload.add_subparsers(required=True, dest="command")

    payload_put = payload_commands.add_parser("put")
    payload_put.add_argument("--mime-type")
    payload_put.add_argument("--name")
    payload_put.add_argument("file")

    payload_list = payload_commands.add_parser("list")

    # define = subparsers.add_parser("define")
    # define.add_argument("--probe")
    # define.add_argument("--payload")
    # define.add_argument("description")

    # ls = subparsers.add_parser("ls")
    # ls.add_argument("--limit", type=int)
    # ls.add_argument("--type")
    # ls.add_argument("probe")

    return parser.parse_args(argv)

import decimal
def main(argv: Optional[List[str]] = None):
    args = get_args(argv)
    session = boto3.Session(region_name=args.region)
    stack_outputs = get_stack_outputs(session, args.stack)
    table = session.resource("dynamodb").Table(stack_outputs["StorageTable"])

    if args.object == 'probe':
        if args.command == 'events':
            response = table.query(
                IndexName='ProbeTimestamp',
                KeyConditions={
                    'probe': {
                        'AttributeValueList': [args.probe],
                        'ComparisonOperator': 'EQ',
                    },

                },
                ScanIndexForward=False,
            )
            for item in response['Items']:
                print(json.dumps(item, separators=(",", ":"), default=dynamodb_to_json_default))
        elif args.command == 'list':
            kwargs = {}
            while True:
                response = table.scan(
                    Limit=1,
                    **kwargs
                )
                if not response["Items"]:
                    break
                for item in response['Items']:
                    kwargs = {"ExclusiveStartKey": {"probe": item['probe'], "type": "~"}}
                    print(item['probe'])
    # for item in paginate_table(
    # table.query,
    # IndexName="ProbeTimestamp",
    # KeyConditionExpression=Key("probe").eq("x"),
    # FilterExpression=Attr("type").begins_with("event:http:"),
    # ScanIndexForward=False,
    # ):
    # print(json.dumps(item, default=dynamodb_to_json_default))


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
