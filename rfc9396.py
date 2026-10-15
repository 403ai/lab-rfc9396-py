"""RFC 9396 OAuth 2.0 Rich Authorization Requests (RAR) library.

Provides data models, parser, validator, and serializer for RFC 9396.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence

STANDARD_FIELDS = {
    "type",
    "locations",
    "actions",
    "datatypes",
    "identifier",
    "privileges",
}


class RFC9396Error(Exception):
    """Base exception for RFC 9396 errors."""
    pass


class InvalidAuthorizationDetailError(RFC9396Error):
    """Raised when an authorization detail object is invalid according to RFC 9396."""
    pass


class DuplicateTypeError(RFC9396Error):
    """Raised when duplicate types are encountered where uniqueness is enforced."""
    pass


def _validate_str_list(field_name: str, value: Any) -> None:
    """Validate that value is a non-empty list of non-empty strings, or list of strings."""
    if not isinstance(value, list) or isinstance(value, (str, bytes)):
        raise InvalidAuthorizationDetailError(
            f"Field '{field_name}' must be an array of strings, got {type(value).__name__}"
        )
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            raise InvalidAuthorizationDetailError(
                f"Field '{field_name}' element at index {idx} must be a string, got {type(item).__name__}"
            )


@dataclass
class AuthorizationDetail:
    """RFC 9396 Authorization Detail object.

    Attributes:
        type: The type of authorization data (required string).
        locations: List of location URIs (optional list of strings).
        actions: List of actions (optional list of strings).
        datatypes: List of data types (optional list of strings).
        identifier: Identifier for the resource or data (optional string).
        privileges: List of privileges (optional list of strings).
        extra: Additional custom extension members.
    """

    type: str
    locations: list[str] | None = None
    actions: list[str] | None = None
    datatypes: list[str] | None = None
    identifier: str | None = None
    privileges: list[str] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.extra is None:
            self.extra = {}

    def validate(self) -> None:
        """Validate the authorization detail according to RFC 9396 rules."""
        if not isinstance(self.type, str):
            raise InvalidAuthorizationDetailError(
                f"'type' must be a string, got {type(self.type).__name__}"
            )
        if not self.type:
            raise InvalidAuthorizationDetailError("'type' must be a non-empty string")

        if self.locations is not None:
            _validate_str_list("locations", self.locations)

        if self.actions is not None:
            _validate_str_list("actions", self.actions)

        if self.datatypes is not None:
            _validate_str_list("datatypes", self.datatypes)

        if self.identifier is not None:
            if not isinstance(self.identifier, str):
                raise InvalidAuthorizationDetailError(
                    f"'identifier' must be a string, got {type(self.identifier).__name__}"
                )

        if self.privileges is not None:
            _validate_str_list("privileges", self.privileges)

        if not isinstance(self.extra, dict):
            raise InvalidAuthorizationDetailError(
                f"'extra' must be a dict, got {type(self.extra).__name__}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize authorization detail to a dictionary with standard fields and extra fields.

        None fields are omitted.
        """
        result: dict[str, Any] = {"type": self.type}
        if self.locations is not None:
            result["locations"] = list(self.locations)
        if self.actions is not None:
            result["actions"] = list(self.actions)
        if self.datatypes is not None:
            result["datatypes"] = list(self.datatypes)
        if self.identifier is not None:
            result["identifier"] = self.identifier
        if self.privileges is not None:
            result["privileges"] = list(self.privileges)

        # Retain arbitrary custom extension members
        for k, v in self.extra.items():
            result[k] = v

        return result

    def to_json(self) -> str:
        """Serialize authorization detail to a clean JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


class AuthorizationDetails:
    """Collection wrapper of AuthorizationDetail objects."""

    def __init__(self, details: Sequence[AuthorizationDetail] | None = None) -> None:
        self._details: list[AuthorizationDetail] = list(details) if details else []

    def __iter__(self) -> Iterator[AuthorizationDetail]:
        return iter(self._details)

    def __len__(self) -> int:
        return len(self._details)

    def __getitem__(self, index: int | slice) -> Any:
        if isinstance(index, slice):
            return AuthorizationDetails(self._details[index])
        return self._details[index]

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, AuthorizationDetails):
            return len(self._details) == len(other._details) and all(
                compare_details_exact(a, b) for a, b in zip(self._details, other._details)
            )
        return False

    def validate(self) -> None:
        """Validate all contained authorization details."""
        for detail in self._details:
            detail.validate()

    def to_list(self) -> list[dict[str, Any]]:
        """Serialize collection to a list of dicts."""
        return [detail.to_dict() for detail in self._details]

    def to_json(self) -> str:
        """Serialize collection to a clean JSON string."""
        return json.dumps(self.to_list(), separators=(",", ":"))


def _parse_single_detail(data: Any) -> AuthorizationDetail:
    """Parse a single detail dictionary into an AuthorizationDetail."""
    if not isinstance(data, dict):
        raise InvalidAuthorizationDetailError(
            f"Authorization detail must be a JSON object (dict), got {type(data).__name__}"
        )

    if "type" not in data:
        raise InvalidAuthorizationDetailError("Missing required field 'type'")

    type_val = data["type"]
    if not isinstance(type_val, str):
        raise InvalidAuthorizationDetailError(
            f"Field 'type' must be a string, got {type(type_val).__name__}"
        )

    locations = data.get("locations")
    actions = data.get("actions")
    datatypes = data.get("datatypes")
    identifier = data.get("identifier")
    privileges = data.get("privileges")

    extra = {k: v for k, v in data.items() if k not in STANDARD_FIELDS}

    detail = AuthorizationDetail(
        type=type_val,
        locations=locations,
        actions=actions,
        datatypes=datatypes,
        identifier=identifier,
        privileges=privileges,
        extra=extra,
    )
    detail.validate()
    return detail


def parse_authorization_details(
    raw: str | list[dict[str, Any]] | dict[str, Any]
) -> AuthorizationDetails:
    """Parse and validate RFC 9396 JSON or dict/list inputs.

    Accepts:
    - JSON string representing either a single authorization detail object or an array of detail objects.
    - A dictionary representing a single authorization detail object.
    - A list of dictionaries representing authorization detail objects.

    Returns:
        AuthorizationDetails collection.
    """
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as err:
            raise RFC9396Error(f"Invalid JSON string: {err}") from err
    else:
        parsed = raw

    if isinstance(parsed, dict):
        details = [_parse_single_detail(parsed)]
    elif isinstance(parsed, list):
        details = [_parse_single_detail(item) for item in parsed]
    else:
        raise InvalidAuthorizationDetailError(
            f"Expected JSON object or array, got {type(parsed).__name__}"
        )

    auth_details = AuthorizationDetails(details)
    auth_details.validate()
    return auth_details


def _rfc8259_equal(val1: Any, val2: Any) -> bool:
    """Compare two values according to RFC 8259 rules without string normalization.

    RFC 8259 Section 8.3:
    Two strings are equal if and only if they consist of the same sequence of
    Unicode code points, ignoring any differences between representations of
    characters that could be made equivalent by normalization.
    """
    if type(val1) is not type(val2):
        # Strict type equality: do not conflate bool and int (e.g. True == 1 in Python)
        return False

    if isinstance(val1, str):
        # Python strings compare by exact sequence of Unicode code points without normalization
        return val1 == val2
    elif isinstance(val1, (int, float, bool)) or val1 is None:
        return val1 == val2
    elif isinstance(val1, list):
        if len(val1) != len(val2):
            return False
        return all(_rfc8259_equal(x, y) for x, y in zip(val1, val2))
    elif isinstance(val1, dict):
        if set(val1.keys()) != set(val2.keys()):
            return False
        return all(_rfc8259_equal(val1[k], val2[k]) for k in val1)
    else:
        return val1 == val2


def compare_details_exact(a: AuthorizationDetail, b: AuthorizationDetail) -> bool:
    """RFC 8259-compliant exact comparison helper without normalization.

    Compares standard fields and extra extension fields for exact equality.
    """
    if not isinstance(a, AuthorizationDetail) or not isinstance(b, AuthorizationDetail):
        return False

    dict_a = a.to_dict()
    dict_b = b.to_dict()
    return _rfc8259_equal(dict_a, dict_b)
