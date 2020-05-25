import dataclasses
import datetime
import enum
from typing import Any, Callable, Dict, Iterable, Optional

from boto3.dynamodb.conditions import Attr, Key


class ProbeEventType(enum.Enum):
    HTTP = "http"
    EMAIL = "email"
    DNS = "dns"


@dataclasses.dataclass
class ProbeEvent:
    type: ProbeEventType
    id: str
    timestamp: datetime.datetime
    expiration: datetime.datetime
    data: Dict[str, Any]
    body: Optional[bytes] = dataclasses.field(default=None)


@dataclasses.dataclass
class ProbePayload:
    name: str
    type: str
    content: bytes


@dataclasses.dataclass
class ProbeDefinition:
    name: str
    description: str
    payload: ProbePayload
    notify: bool

    @classmethod
    def create_default(cls, name):
        return cls(
            name=name,
            description="Uninitialized probe",
            payload=ProbePayload(name="default", type="text/html", content=b""),
            notify=False,
        )


class _PassthroughNamespaceMeta(type):
    def __get__(cls, obj, objtype):
        attrs = {
            **cls.__dict__,
            "__qualname__": cls.__qualname__,
            "_parent": (obj, objtype),
        }
        return type(cls)(cls.__name__, cls.__bases__, attrs)

    def __getattribute__(self, key):
        value = object.__getattribute__(self, key)
        if hasattr(value, "__get__"):
            return value.__get__(*self._parent)
        return value


class _PassthroughNamespace(metaclass=_PassthroughNamespaceMeta):
    def __getattribute__(self, key):
        return getattr(type(self), key)


class ProbeStorage:
    _TABLE_HASH_KEY = "probe"
    _TABLE_RANGE_KEY = "type"
    _TABLE_TIMESTAMP_KEY = "timestamp"
    _TABLE_EXPIRATION_KEY = "expiration"
    _TABLE_TIMESTAMP_INDEX_NAME = "ProbeTimestamp"
    _BUCKET_PAYLOADS_PREFIX = "payloads/"
    _BUCKET_EVENTS_PREFIX = "events/"

    def __init__(self, *, table, bucket):
        self._table = table
        self._bucket = bucket

    @classmethod
    def from_environment_variables(cls):
        raise NotImplementedError()

    def _paginate_table(self, operation, **arguments):
        while True:
            response = operation(**arguments)
            yield from response["Items"]
            if "LastEvaluatedKey" not in response:
                break
            arguments["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    class definitions(_PassthroughNamespace):
        def get(self, name: str) -> ProbeDefinition:
            if not name:
                return ProbeDefinition.create_default(name)

            response = self._table.get_item(
                Key={self._TABLE_HASH_KEY: name, self._TABLE_RANGE_KEY: "definition",},
            )
            if definition := response.get("Item", {}).get("data"):
                return ProbeDefinition(
                    name=name,
                    payload=self.payloads.get(definition.pop("payload")),
                    **definition,
                )
            return ProbeDefinition.create_default(name)

        def put(self, definition: ProbeDefinition) -> None:
            self._table.put_item(
                Item={
                    self._TABLE_HASH_KEY: definition.name,
                    self._TABLE_RANGE_KEY: "definition",
                    "data": {
                        "payload": definition.payload.name,
                        "description": definition.description,
                        "notify": definition.notify,
                    },
                },
            )

        def list(self) -> Iterable[ProbeDefinition]:
            # this would be a full table scan right now
            raise NotImplementedError()

    class payloads(_PassthroughNamespace):
        def get(self, name: str) -> ProbePayload:
            object = self._bucket.Object(self._BUCKET_PAYLOADS_PREFIX + name).get()
            return ProbePayload(
                name=name, type=object["ContentType"], content=object["Body"].read(),
            )

        def put(self, payload: ProbePayload) -> None:
            self._bucket.Object(self._BUCKET_PAYLOADS_PREFIX + payload.name).put(
                ContentType=payload.type, Body=payload.content,
            )

        def list(self) -> Iterable[ProbePayload]:
            iterator = self._bucket.objects.filter(Prefix=self._BUCKET_PAYLOADS_PREFIX)
            for summary in iterator:
                object = summary.Object().get()
                yield ProbePayload(
                    name=summary.key,
                    type=object["ContentType"],
                    content=object["Body"].read(),
                )

    class events(_PassthroughNamespace):
        def put(self, probe_name: str, event: ProbeEvent) -> None:
            if not probe_name:
                return
            if event.body is not None:
                key = self._BUCKET_EVENTS_PREFIX + event.type.value + "/" + event.id
                object = self._bucket.Object(key).put(Body=event.body)
            self._table.put_item(
                Item={
                    self._TABLE_HASH_KEY: probe_name,
                    self._TABLE_RANGE_KEY: f"event:{event.type.value}:{event.id}",
                    self._TABLE_TIMESTAMP_KEY: int(event.timestamp.timestamp()),
                    self._TABLE_EXPIRATION_KEY: int(event.expiration.timestamp()),
                    "data": event.data,
                    "body": bool(event.body is not None),
                },
            )

        def list(self, probe_name: str) -> Iterable[ProbeEvent]:
            for item in self._paginate_table(
                self._table.query,
                IndexName=self._TABLE_TIMESTAMP_INDEX_NAME,
                KeyConditionExpression=Key(self._TABLE_HASH_KEY).eq(probe_name),
                FilterExpression=Attr(self._TABLE_RANGE_KEY).begins_with("event:"),
                ScanIndexForward=False,
            ):
                _, event_type, event_id = item[self._TABLE_RANGE_KEY].split(":")
                body = None
                if item.get("body"):
                    key = self._BUCKET_EVENTS_PREFIX + event_type + "/" + event_id
                    body = self._bucket.Object(key).get()["Body"].read()
                yield ProbeEvent(
                    type=ProbeEventType(event_type),
                    id=event_id,
                    timestamp=datetime.datetime.fromtimestamp(item["timestamp"]),
                    expiration=datetime.datetime.fromtimestamp(item["expiration"]),
                    data=item["data"],
                    body=body,
                )
