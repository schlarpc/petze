import datetime
import inspect
import os
import pathlib
import time
import types
import zipfile
from typing import Any, Dict, List, Optional

from awacs import acm, awslambda, dynamodb, logs, route53, s3, ses, sns, sqs, sts
from awacs.aws import (
    Allow,
    Condition,
    PolicyDocument,
    Principal,
    Statement,
    StringEquals,
)
from troposphere import (
    AccountId,
    AWSHelperFn,
    GetAtt,
    Join,
    NoValue,
    Output,
    Parameter,
    Partition,
    Ref,
    Region,
    StackName,
    Sub,
    Tags,
    Template,
    URLSuffix,
)
from troposphere.apigateway import (
    BasePathMapping,
    Deployment,
    DomainName,
    EndpointConfiguration,
    Integration,
    Method,
    MethodSetting,
    Resource,
    RestApi,
    Stage,
)
from troposphere.awslambda import (
    Code,
    DeadLetterConfig,
    Environment,
    EventSourceMapping,
    Function,
    Permission,
)
from troposphere.certificatemanager import Certificate
from troposphere.cloudformation import AWSCustomObject
from troposphere.dynamodb import (
    AttributeDefinition,
    KeySchema,
    LocalSecondaryIndex,
    Projection,
    StreamSpecification,
    Table,
    TimeToLiveSpecification,
)
from troposphere.events import Rule as EventRule
from troposphere.events import Target
from troposphere.iam import Policy, PolicyType, Role
from troposphere.logs import Destination, LogGroup, SubscriptionFilter
from troposphere.route53 import (
    AliasTarget,
    HostedZone,
    QueryLoggingConfig,
    RecordSet,
    RecordSetGroup,
    RecordSetType,
)
from troposphere.s3 import (
    AbortIncompleteMultipartUpload,
    Bucket,
    BucketEncryption,
    LifecycleConfiguration,
    LifecycleRule,
    PublicAccessBlockConfiguration,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
)
from troposphere.ses import (
    Action,
    LambdaAction,
    ReceiptRule,
    ReceiptRuleSet,
    Rule,
    SNSAction,
)
from troposphere.sns import Subscription, SubscriptionResource, Topic
from troposphere.sqs import Queue

from . import handlers, storage


class LogsResourcePolicy(AWSCustomObject):
    resource_type = "Custom::LogsResourcePolicy"

    props = dict(PolicyName=(str, True), PolicyDocument=(PolicyDocument, True))


class DomainVerification(AWSCustomObject):
    resource_type = "Custom::DomainVerification"

    props = dict(Domain=(str, True))


class ActiveReceiptRuleSet(AWSCustomObject):
    resource_type = "Custom::ActiveReceiptRuleSet"

    props = dict(RuleSetName=(str, True))


class IgnorePropertyType(AWSHelperFn):
    def __init__(self, data):
        self.data = data


def create_lambda(
    template,
    *,
    logical_name_prefix: str,
    function: types.FunctionType,
    function_bundle_path: str,
    memory_size: int = 256,
    timeout: int = 60,
    log_retention_days: Optional[int] = None,
    environment_variables: Optional[Dict[str, Any]] = None,
    create_dead_letter_queue: bool = False,
    python_runtime: str = "python3.8",
    policy_statements: Optional[List[Statement]] = None,
    invoke_permissions: Optional[List[Dict[str, Any]]] = None,
    streams: Optional[List[Any]] = None,
):
    resources = {}

    if create_dead_letter_queue:
        resources["DeadLetterQueue"] = template.add_resource(
            Queue(
                logical_name_prefix + "DeadLetterQueue",
                MessageRetentionPeriod=int(datetime.timedelta(days=14).total_seconds()),
                KmsMasterKeyId="alias/aws/sqs",
            )
        )

    policy_statements = (policy_statements or []).copy()

    if create_dead_letter_queue:
        policy_statements.append(
            Statement(
                Effect=Allow,
                Action=[sqs.SendMessage],
                Resource=[GetAtt(resources["DeadLetterQueue"], "Arn")],
            )
        )

    if streams:
        policy_statements.append(
            Statement(
                Effect=Allow,
                Action=[
                    dynamodb.GetRecords,
                    dynamodb.GetShardIterator,
                    dynamodb.DescribeStream,
                    dynamodb.ListStreams,
                ],
                Resource=streams,
            )
        )

    resources["Role"] = template.add_resource(
        Role(
            logical_name_prefix + "Role",
            AssumeRolePolicyDocument=PolicyDocument(
                Version="2012-10-17",
                Statement=[
                    Statement(
                        Effect="Allow",
                        Principal=Principal("Service", "lambda.amazonaws.com"),
                        Action=[sts.AssumeRole],
                    )
                ],
            ),
            Policies=NoValue
            if not policy_statements
            else [
                Policy(
                    PolicyName=logical_name_prefix,
                    PolicyDocument=PolicyDocument(
                        Version="2012-10-17", Statement=policy_statements,
                    ),
                )
            ],
        )
    )

    resources["Function"] = template.add_resource(
        Function(
            logical_name_prefix,
            Runtime=python_runtime,
            Code=IgnorePropertyType(function_bundle_path),
            MemorySize=memory_size,
            Timeout=timeout,
            Handler=".".join((function.__module__, function.__qualname__)),
            Role=GetAtt(resources["Role"], "Arn"),
            DeadLetterConfig=NoValue
            if not create_dead_letter_queue
            else DeadLetterConfig(
                TargetArn=GetAtt(resources["DeadLetterQueue"], "Arn")
            ),
            Environment=Environment(Variables=environment_variables or NoValue),
        )
    )

    resources["LogGroup"] = template.add_resource(
        LogGroup(
            logical_name_prefix + "LogGroup",
            LogGroupName=Join("/", ["/aws/lambda", Ref(resources["Function"])]),
            RetentionInDays=log_retention_days or NoValue,
        )
    )

    resources["RolePolicy"] = template.add_resource(
        PolicyType(
            logical_name_prefix + "RolePolicy",
            PolicyName=resources["LogGroup"].title,
            PolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[logs.PutLogEvents, logs.CreateLogStream],
                        Resource=[GetAtt(resources["LogGroup"], "Arn")],
                    ),
                ],
            ),
            Roles=[Ref(resources["Role"])],
        )
    )

    for idx, permission in enumerate(invoke_permissions or [], start=1):
        resources[f"Permission{idx}"] = template.add_resource(
            Permission(
                logical_name_prefix + f"Permission{idx}",
                Action=awslambda.InvokeFunction.JSONrepr(),
                FunctionName=GetAtt(resources["Function"], "Arn"),
                DependsOn=[resources["RolePolicy"]],
                **permission,
            )
        )

    for idx, stream in enumerate(streams or [], start=1):
        resources[f"Stream{idx}"] = template.add_resource(
            EventSourceMapping(
                logical_name_prefix + f"Stream{idx}",
                FunctionName=GetAtt(resources["Function"], "Arn"),
                EventSourceArn=stream,
                BisectBatchOnFunctionError=True,
                MaximumRetryAttempts=5,
                StartingPosition="LATEST",
                DependsOn=[resources["RolePolicy"]],
            )
        )

    return resources


def create_bundle():
    bundle_path = str(pathlib.Path("petze-bundle.zip").resolve())
    module_root = pathlib.Path(__file__).parent
    with zipfile.ZipFile(bundle_path, "w") as zip:
        for root, _, files in os.walk(module_root):
            for file in files:
                if not file.endswith(".py"):
                    continue
                file_path = pathlib.Path(root) / file
                zip.write(
                    file_path, arcname=str(file_path.relative_to(module_root.parent))
                )
    return bundle_path


def create_certificate_validation_child_template():
    template = Template()

    hosted_zone_id = template.add_parameter("HostedZoneId", Type="String")
    record_name = template.add_parameter("RecordName", Type="String", Default="")
    record_value = template.add_parameter("RecordValue", Type="String", Default="")

    record_is_defined = "RecordIsDefined"

    template.add_condition(
        record_is_defined,
        And(
            *(
                Not(Equals(Ref(parameter), ""))
                for parameter in (record_name, record_value)
            )
        ),
    )

    template.add_resource(
        RecordSetType(
            "ValidationRecord",
            HostedZoneId=Ref(hosted_zone),
            Name=Ref(record_name),
            ResourceRecords=[Ref(record_value)],
            Type="CNAME",
            TTL=300,
            Condition=record_is_defined,
        )
    )


def create_template():
    bundle_path = create_bundle()

    template = Template(Description="Blind XSS discovery and recon tool")

    domain_name = template.add_parameter(Parameter("DomainName", Type="String"))

    log_retention = template.add_parameter(
        Parameter("LogRetention", Type="Number", Default=30)
    )

    slack_webhook_url = template.add_parameter(
        Parameter("SlackWebhookUrl", Type="String")
    )
    storage_bucket = template.add_resource(
        Bucket(
            "StorageBucket",
            BucketEncryption=BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
                            SSEAlgorithm="aws:kms",
                            KMSMasterKeyID=Join(
                                ":",
                                [
                                    "arn",
                                    Partition,
                                    "kms",
                                    Region,
                                    AccountId,
                                    "alias/aws/s3",
                                ],
                            ),
                        ),
                    ),
                ],
            ),
            LifecycleConfiguration=LifecycleConfiguration(
                Rules=[
                    LifecycleRule(
                        Status="Enabled",
                        Prefix=storage.ProbeStorage._BUCKET_EVENTS_PREFIX,
                        ExpirationInDays=Ref(log_retention),
                    ),
                    LifecycleRule(
                        Status="Enabled",
                        AbortIncompleteMultipartUpload=AbortIncompleteMultipartUpload(
                            DaysAfterInitiation=1,
                        ),
                    ),
                ],
            ),
            PublicAccessBlockConfiguration=PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
        )
    )

    storage_table = template.add_resource(
        Table(
            "StorageTable",
            KeySchema=[
                KeySchema(
                    AttributeName=storage.ProbeStorage._TABLE_HASH_KEY, KeyType="HASH"
                ),
                KeySchema(
                    AttributeName=storage.ProbeStorage._TABLE_RANGE_KEY, KeyType="RANGE"
                ),
            ],
            AttributeDefinitions=[
                AttributeDefinition(
                    AttributeName=storage.ProbeStorage._TABLE_HASH_KEY,
                    AttributeType="S",
                ),
                AttributeDefinition(
                    AttributeName=storage.ProbeStorage._TABLE_RANGE_KEY,
                    AttributeType="S",
                ),
                AttributeDefinition(
                    AttributeName=storage.ProbeStorage._TABLE_TIMESTAMP_KEY,
                    AttributeType="N",
                ),
            ],
            LocalSecondaryIndexes=[
                LocalSecondaryIndex(
                    IndexName=storage.ProbeStorage._TABLE_TIMESTAMP_INDEX_NAME,
                    KeySchema=[
                        KeySchema(
                            AttributeName=storage.ProbeStorage._TABLE_HASH_KEY,
                            KeyType="HASH",
                        ),
                        KeySchema(
                            AttributeName=storage.ProbeStorage._TABLE_TIMESTAMP_KEY,
                            KeyType="RANGE",
                        ),
                    ],
                    Projection=Projection(ProjectionType="ALL"),
                ),
            ],
            TimeToLiveSpecification=TimeToLiveSpecification(
                AttributeName=storage.ProbeStorage._TABLE_EXPIRATION_KEY, Enabled=True,
            ),
            StreamSpecification=StreamSpecification(StreamViewType="NEW_IMAGE"),
            BillingMode="PAY_PER_REQUEST",
        )
    )

    event_recorder_environment_variables = {
        "PETZE_STORAGE_TABLE": Ref(storage_table),
        "PETZE_STORAGE_BUCKET": Ref(storage_bucket),
        "PETZE_DOMAIN_NAME": Ref(domain_name),
        "PETZE_EVENT_TTL_DAYS": Ref(log_retention),
    }

    dns_log_group = template.add_resource(LogGroup("DNSLogGroup", RetentionInDays=1))

    dns_log_function = create_lambda(
        template,
        logical_name_prefix="DNSLogFunction",
        function=handlers.dns_log_function_handler,
        function_bundle_path=bundle_path,
        timeout=300,
        log_retention_days=Ref(log_retention),
        environment_variables=event_recorder_environment_variables,
        policy_statements=[
            Statement(
                Effect=Allow,
                Resource=[GetAtt(storage_table, "Arn")],
                Action=[dynamodb.PutItem],
            ),
        ],
        invoke_permissions=[
            {
                "Principal": Join(".", ["logs", Region, "amazonaws.com"]),
                "SourceArn": GetAtt(dns_log_group, "Arn"),
                "SourceAccount": AccountId,
            },
        ],
    )

    dns_log_subscription = template.add_resource(
        SubscriptionFilter(
            "DNSLogSubscription",
            DestinationArn=GetAtt(dns_log_function["Function"], "Arn"),
            FilterPattern="",
            LogGroupName=Ref(dns_log_group),
            DependsOn=[r.title for r in dns_log_function.values()],
        )
    )

    log_policy_custom_resource_function = create_lambda(
        template,
        logical_name_prefix="LogPolicyCustomResourceFunction",
        function=handlers.log_policy_custom_resource_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        policy_statements=[
            Statement(
                Effect=Allow,
                Action=[logs.PutResourcePolicy, logs.DeleteResourcePolicy],
                Resource=["*"],
            ),
        ],
        create_dead_letter_queue=True,
    )

    log_policy = template.add_resource(
        LogsResourcePolicy(
            "LogPolicy",
            ServiceToken=GetAtt(log_policy_custom_resource_function["Function"], "Arn"),
            PolicyName=Ref(dns_log_group),
            PolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Principal=Principal("Service", "route53.amazonaws.com"),
                        Action=[logs.CreateLogStream, logs.PutLogEvents],
                        Resource=[GetAtt(dns_log_group, "Arn")],
                    )
                ],
            ),
            DependsOn=[r.title for r in log_policy_custom_resource_function.values()],
        )
    )

    hosted_zone = template.add_resource(
        HostedZone(
            "HostedZone",
            Name=Ref(domain_name),
            QueryLoggingConfig=QueryLoggingConfig(
                CloudWatchLogsLogGroupArn=GetAtt(dns_log_group, "Arn"),
            ),
            DependsOn=[log_policy.title],
        )
    )

    certificate_validator_function = create_lambda(
        template,
        logical_name_prefix="CertificateValidatorFunction",
        function=handlers.certificate_validator_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        environment_variables={"HOSTED_ZONE_ID": Ref(hosted_zone)},
        policy_statements=[
            Statement(
                Effect=Allow,
                Action=[route53.ChangeResourceRecordSets],
                Resource=[
                    Join(
                        ":",
                        [
                            "arn",
                            Partition,
                            "route53",
                            "",
                            "",
                            Join("/", ["hostedzone", Ref(hosted_zone)]),
                        ],
                    )
                ],
            ),
            Statement(
                Effect=Allow,
                Action=[acm.DescribeCertificate],
                Resource=[
                    Join(
                        ":",
                        ["arn", Partition, "acm", Region, AccountId, "certificate/*",],
                    ),
                ],
            ),
        ],
        create_dead_letter_queue=True,
    )

    certificate_validator_rule = template.add_resource(
        EventRule(
            "CertificateValidatorRule",
            EventPattern={
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["acm.amazonaws.com"],
                    "eventName": ["AddTagsToCertificate"],
                    "requestParameters": {
                        "tags": {
                            "key": [certificate_validator_function["Function"].title],
                            "value": [
                                GetAtt(
                                    certificate_validator_function["Function"], "Arn"
                                )
                            ],
                        }
                    },
                },
            },
            Targets=[
                Target(
                    Id="certificate-validator-lambda",
                    Arn=GetAtt(certificate_validator_function["Function"], "Arn"),
                )
            ],
        )
    )

    certificate_validator_permission = template.add_resource(
        Permission(
            "CertificateValidatorPermission",
            FunctionName=GetAtt(certificate_validator_function["Function"], "Arn"),
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=GetAtt(certificate_validator_rule, "Arn"),
            DependsOn=[r.title for r in certificate_validator_function.values()],
        )
    )

    certificate = template.add_resource(
        Certificate(
            "Certificate",
            DomainName=Ref(domain_name),
            SubjectAlternativeNames=[
                Ref(domain_name),
                Join(".", ["*", Ref(domain_name)]),
            ],
            ValidationMethod="DNS",
            Tags=Tags(
                **{
                    certificate_validator_function["Function"].title: GetAtt(
                        certificate_validator_function["Function"], "Arn"
                    )
                }
            ),
            DependsOn=[certificate_validator_permission],
        )
    )

    api = template.add_resource(
        RestApi(
            "Api",
            Name=StackName,
            EndpointConfiguration=EndpointConfiguration(Types=["REGIONAL"]),
            FailOnWarnings="true",
            BinaryMediaTypes=["*/*"],
            MinimumCompressionSize=0,
        )
    )

    api_function = create_lambda(
        template,
        logical_name_prefix="ApiFunction",
        function=handlers.api_handler,
        function_bundle_path=bundle_path,
        timeout=30,
        log_retention_days=Ref(log_retention),
        environment_variables=event_recorder_environment_variables,
        policy_statements=[
            Statement(
                Effect=Allow,
                Resource=[GetAtt(storage_table, "Arn")],
                Action=[dynamodb.PutItem, dynamodb.GetItem],
            ),
            Statement(
                Effect=Allow,
                Resource=[
                    Join(
                        "/",
                        [
                            GetAtt(storage_bucket, "Arn"),
                            storage.ProbeStorage._BUCKET_EVENTS_PREFIX + "*",
                        ],
                    )
                ],
                Action=[s3.PutObject],
            ),
            Statement(
                Effect=Allow,
                Resource=[
                    Join(
                        "/",
                        [
                            GetAtt(storage_bucket, "Arn"),
                            storage.ProbeStorage._BUCKET_PAYLOADS_PREFIX + "*",
                        ],
                    )
                ],
                Action=[s3.GetObject],
            ),
        ],
        invoke_permissions=[
            {
                "Principal": "apigateway.amazonaws.com",
                "SourceArn": Join(
                    ":",
                    [
                        "arn",
                        Partition,
                        "execute-api",
                        Region,
                        AccountId,
                        Join("/", [Ref(api), "*"]),
                    ],
                ),
            }
        ],
    )

    api_method_root = template.add_resource(
        Method(
            "ApiMethodRoot",
            HttpMethod="ANY",
            AuthorizationType="NONE",
            Integration=Integration(
                IntegrationHttpMethod="POST",
                PassthroughBehavior="NEVER",
                Type="AWS_PROXY",
                Uri=Join(
                    ":",
                    [
                        "arn",
                        Partition,
                        "apigateway",
                        Region,
                        "lambda",
                        Join(
                            "/",
                            [
                                "path",
                                "2015-03-31",
                                "functions",
                                GetAtt(api_function["Function"], "Arn"),
                                "invocations",
                            ],
                        ),
                    ],
                ),
            ),
            RestApiId=Ref(api),
            ResourceId=GetAtt(api, "RootResourceId"),
            DependsOn=[r.title for r in api_function.values()],
        )
    )

    api_resource_path = template.add_resource(
        Resource(
            "ApiResourcePath",
            RestApiId=Ref(api),
            ParentId=GetAtt(api, "RootResourceId"),
            PathPart="{proxy+}",
        )
    )

    api_method_path = template.add_resource(
        Method(
            "ApiMethodPath",
            HttpMethod="ANY",
            AuthorizationType="NONE",
            Integration=Integration(
                IntegrationHttpMethod="POST",
                PassthroughBehavior="NEVER",
                Type="AWS_PROXY",
                Uri=Join(
                    ":",
                    [
                        "arn",
                        Partition,
                        "apigateway",
                        Region,
                        "lambda",
                        Join(
                            "/",
                            [
                                "path",
                                "2015-03-31",
                                "functions",
                                GetAtt(api_function["Function"], "Arn"),
                                "invocations",
                            ],
                        ),
                    ],
                ),
            ),
            RestApiId=Ref(api),
            ResourceId=Ref(api_resource_path),
            DependsOn=[r.title for r in api_function.values()],
        )
    )

    api_deployment = template.add_resource(
        Deployment(
            "ApiDeployment" + str(int(time.time())),
            RestApiId=Ref(api),
            DependsOn=[api_method_root, api_method_path],
        )
    )

    api_stage = template.add_resource(
        Stage(
            "ApiStage",
            DeploymentId=Ref(api_deployment),
            RestApiId=Ref(api),
            StageName="default",
            MethodSettings=[
                MethodSetting(
                    HttpMethod="*",
                    ResourcePath="/*",
                    ThrottlingBurstLimit=IgnorePropertyType(-1),
                    ThrottlingRateLimit=IgnorePropertyType(-1),
                ),
            ],
        )
    )

    api_domain_name_bare = template.add_resource(
        DomainName(
            "ApiDomainNameBare",
            DomainName=Ref(domain_name),
            RegionalCertificateArn=Ref(certificate),
            EndpointConfiguration=EndpointConfiguration(Types=["REGIONAL"]),
        )
    )

    api_mapping_bare = template.add_resource(
        BasePathMapping(
            "ApiMappingBare",
            DomainName=Ref(api_domain_name_bare),
            RestApiId=Ref(api),
            Stage=Ref(api_stage),
        )
    )

    api_domain_name_wildcard = template.add_resource(
        DomainName(
            "ApiDomainNameWildcard",
            DomainName=Join(".", ["*", Ref(domain_name)]),
            RegionalCertificateArn=Ref(certificate),
            EndpointConfiguration=EndpointConfiguration(Types=["REGIONAL"]),
        )
    )

    api_mapping_wildcard = template.add_resource(
        BasePathMapping(
            "ApiMappingWildcard",
            DomainName=Ref(api_domain_name_wildcard),
            RestApiId=Ref(api),
            Stage=Ref(api_stage),
        )
    )

    domain_verification_custom_resource_function = create_lambda(
        template,
        logical_name_prefix="DomainVerificationCustomResourceFunction",
        function=handlers.domain_verification_custom_resource_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        policy_statements=[
            Statement(
                Effect=Allow,
                Action=[ses.VerifyDomainIdentity, ses.DeleteIdentity],
                Resource=["*"],
            ),
        ],
        create_dead_letter_queue=True,
    )

    email_domain_verification = template.add_resource(
        DomainVerification(
            "EmailDomainVerification",
            ServiceToken=GetAtt(
                domain_verification_custom_resource_function["Function"], "Arn"
            ),
            Domain=Ref(domain_name),
            DependsOn=[
                r.title for r in domain_verification_custom_resource_function.values()
            ],
        )
    )

    email_topic = template.add_resource(Topic("EmailTopic",))

    email_function = create_lambda(
        template,
        logical_name_prefix="EmailFunction",
        function=handlers.email_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        environment_variables=event_recorder_environment_variables,
        policy_statements=[
            Statement(
                Effect=Allow,
                Resource=[GetAtt(storage_table, "Arn")],
                Action=[dynamodb.PutItem],
            ),
            Statement(
                Effect=Allow,
                Resource=[
                    Join(
                        "/",
                        [
                            GetAtt(storage_bucket, "Arn"),
                            storage.ProbeStorage._BUCKET_EVENTS_PREFIX + "*",
                        ],
                    )
                ],
                Action=[s3.PutObject],
            ),
        ],
        invoke_permissions=[
            {"Principal": "sns.amazonaws.com", "SourceArn": Ref(email_topic)},
        ],
    )

    email_subscription = template.add_resource(
        SubscriptionResource(
            "EmailSubscription",
            TopicArn=Ref(email_topic),
            Protocol="lambda",
            Endpoint=GetAtt(email_function["Function"], "Arn"),
            DependsOn=[r.title for r in email_function.values()],
        )
    )

    email_receipt_rule_set = template.add_resource(
        ReceiptRuleSet("EmailReceiptRuleSet")
    )

    active_receipt_rule_set_custom_resource_function = create_lambda(
        template,
        logical_name_prefix="ActiveReceiptRuleSetCustomResourceFunction",
        function=handlers.active_receipt_rule_set_custom_resource_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        policy_statements=[
            Statement(
                Effect=Allow,
                Action=[ses.DescribeActiveReceiptRuleSet, ses.SetActiveReceiptRuleSet],
                Resource=["*"],
            ),
        ],
        create_dead_letter_queue=True,
    )

    email_active_receipt_rule_set = template.add_resource(
        ActiveReceiptRuleSet(
            "EmailActiveReceiptRuleSet",
            ServiceToken=GetAtt(
                active_receipt_rule_set_custom_resource_function["Function"], "Arn"
            ),
            RuleSetName=Ref(email_receipt_rule_set),
            DependsOn=[
                r.title
                for r in active_receipt_rule_set_custom_resource_function.values()
            ],
        )
    )

    email_receipt_rule = template.add_resource(
        ReceiptRule(
            "EmailReceiptRule",
            RuleSetName=Ref(email_receipt_rule_set),
            Rule=Rule(
                Recipients=[Ref(domain_name), Join("", [".", Ref(domain_name)]),],
                Enabled=True,
                Actions=[
                    Action(
                        SNSAction=SNSAction(
                            Encoding="Base64", TopicArn=Ref(email_topic),
                        ),
                    ),
                ],
                ScanEnabled=False,
                TlsPolicy="Optional",
            ),
            DependsOn=[r.title for r in email_function.values()],
        )
    )

    notification_topic = template.add_resource(Topic("NotificationTopic",))

    notification_stream_function = create_lambda(
        template,
        logical_name_prefix="NotificationStreamFunction",
        function=handlers.notification_stream_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        environment_variables={
            **event_recorder_environment_variables,
            "PETZE_NOTIFICATION_TOPIC": Ref(notification_topic),
        },
        policy_statements=[
            Statement(
                Effect=Allow, Action=[sns.Publish], Resource=[Ref(notification_topic)],
            ),
            Statement(
                Effect=Allow,
                Action=[dynamodb.GetItem],
                Resource=[GetAtt(storage_table, "Arn")],
            ),
        ],
        streams=[GetAtt(storage_table, "StreamArn"),],
    )

    notification_slack_function = create_lambda(
        template,
        logical_name_prefix="NotificationSlackFunction",
        function=handlers.notification_slack_handler,
        function_bundle_path=bundle_path,
        log_retention_days=Ref(log_retention),
        environment_variables={"PETZE_SLACK_WEBHOOK_URL": Ref(slack_webhook_url)},
        invoke_permissions=[
            {"Principal": "sns.amazonaws.com", "SourceArn": Ref(notification_topic),}
        ],
    )

    notification_slack_subscription = template.add_resource(
        SubscriptionResource(
            "NotificationSlackSubscription",
            TopicArn=Ref(notification_topic),
            Protocol="lambda",
            Endpoint=GetAtt(notification_slack_function["Function"], "Arn"),
            DependsOn=[r.title for r in notification_slack_function.values()],
        )
    )

    record_set_group = template.add_resource(
        RecordSetGroup(
            "HostedZoneRecords",
            HostedZoneId=Ref(hosted_zone),
            RecordSets=[
                RecordSet(
                    Name=Ref(domain_name),
                    Type="A",
                    AliasTarget=AliasTarget(
                        DNSName=GetAtt(api_domain_name_bare, "RegionalDomainName"),
                        HostedZoneId=GetAtt(
                            api_domain_name_bare, "RegionalHostedZoneId"
                        ),
                    ),
                ),
                RecordSet(
                    Name=Join(".", ["*", Ref(domain_name)]),
                    Type="A",
                    AliasTarget=AliasTarget(
                        DNSName=GetAtt(api_domain_name_wildcard, "RegionalDomainName"),
                        HostedZoneId=GetAtt(
                            api_domain_name_wildcard, "RegionalHostedZoneId"
                        ),
                    ),
                ),
                RecordSet(
                    Name=Ref(domain_name),
                    Type="MX",
                    TTL=300,
                    ResourceRecords=[
                        Join(
                            " ",
                            ["10", Join(".", ["inbound-smtp", Region, URLSuffix,]),],
                        ),
                    ],
                ),
                RecordSet(
                    Name=Join(".", ["*", Ref(domain_name)]),
                    Type="MX",
                    TTL=300,
                    ResourceRecords=[
                        Join(
                            " ",
                            ["10", Join(".", ["inbound-smtp", Region, URLSuffix,]),],
                        ),
                    ],
                ),
                RecordSet(
                    Name=Join(".", ["_amazonses", Ref(domain_name)]),
                    Type="TXT",
                    TTL=300,
                    ResourceRecords=[
                        Join(
                            "",
                            [
                                '"',
                                GetAtt(email_domain_verification, "VerificationToken"),
                                '"',
                            ],
                        )
                    ],
                ),
            ],
        )
    )

    template.add_output(
        Output("NameServers", Value=Join(",", GetAtt(hosted_zone, "NameServers")))
    )

    template.add_output(Output("StorageTable", Value=Ref(storage_table)))

    return template


if __name__ == "__main__":
    print(create_template().to_json())
