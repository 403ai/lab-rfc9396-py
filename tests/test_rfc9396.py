"""Tests for RFC 9396 OAuth 2.0 Rich Authorization Requests library."""

import unicodedata
import pytest
from rfc9396 import (
    AuthorizationDetail,
    AuthorizationDetails,
    DuplicateTypeError,
    InvalidAuthorizationDetailError,
    RFC9396Error,
    compare_details_exact,
    parse_authorization_details,
)


def test_parse_valid_single_detail_json_string():
    raw_json = (
        '{"type": "account_information", "actions": ["list_accounts", "read_balances"], '
        '"locations": ["https://api.example.com/accounts"]}'
    )
    details = parse_authorization_details(raw_json)
    assert len(details) == 1
    detail = details[0]
    assert detail.type == "account_information"
    assert detail.actions == ["list_accounts", "read_balances"]
    assert detail.locations == ["https://api.example.com/accounts"]
    assert detail.datatypes is None
    assert detail.identifier is None
    assert detail.privileges is None
    assert detail.extra == {}


def test_parse_valid_multiple_details_list():
    raw_list = [
        {"type": "account_information", "actions": ["list_accounts"]},
        {
            "type": "payment_initiation",
            "actions": ["execute"],
            "locations": ["https://api.example.com/payments"],
            "datatypes": ["instant_payment"],
            "identifier": "tx-12345",
            "privileges": ["admin"],
        },
    ]
    details = parse_authorization_details(raw_list)
    assert len(details) == 2
    assert details[0].type == "account_information"
    assert details[0].actions == ["list_accounts"]
    assert details[1].type == "payment_initiation"
    assert details[1].identifier == "tx-12345"
    assert details[1].datatypes == ["instant_payment"]
    assert details[1].privileges == ["admin"]


def test_parse_missing_type_field_raises_error():
    with pytest.raises(InvalidAuthorizationDetailError, match="Missing required field 'type'"):
        parse_authorization_details('{"actions": ["read"]}')

    with pytest.raises(InvalidAuthorizationDetailError, match="Missing required field 'type'"):
        parse_authorization_details([{"locations": ["https://api.example.com"]}])


def test_parse_non_string_type_raises_error():
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details('{"type": 12345}')

    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": None})

    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": ["account_info"]})

    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": ""})


def test_parse_locations_valid_and_invalid_types():
    # Valid
    d = parse_authorization_details({"type": "test", "locations": ["https://example.com/api"]})
    assert d[0].locations == ["https://example.com/api"]

    # Invalid: not a list
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "locations": "https://example.com/api"})

    # Invalid: list element not a string
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "locations": [123]})


def test_parse_actions_valid_and_invalid_types():
    # Valid
    d = parse_authorization_details({"type": "test", "actions": ["read", "write"]})
    assert d[0].actions == ["read", "write"]

    # Invalid: not a list
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "actions": "read"})

    # Invalid: list element not a string
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "actions": ["read", None]})


def test_parse_datatypes_valid_and_invalid_types():
    # Valid
    d = parse_authorization_details({"type": "test", "datatypes": ["contacts", "calendar"]})
    assert d[0].datatypes == ["contacts", "calendar"]

    # Invalid: not a list
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "datatypes": {"contacts": True}})

    # Invalid: list element not a string
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "datatypes": [True]})


def test_parse_identifier_valid_and_invalid_types():
    # Valid
    d = parse_authorization_details({"type": "test", "identifier": "account-987"})
    assert d[0].identifier == "account-987"

    # Invalid: not a string
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "identifier": 987})

    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "identifier": ["account-987"]})


def test_parse_privileges_valid_and_invalid_types():
    # Valid
    d = parse_authorization_details({"type": "test", "privileges": ["superadmin", "audit"]})
    assert d[0].privileges == ["superadmin", "audit"]

    # Invalid: not a list
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "privileges": "superadmin"})

    # Invalid: list element not a string
    with pytest.raises(InvalidAuthorizationDetailError):
        parse_authorization_details({"type": "test", "privileges": ["admin", 42]})


def test_extension_fields_preserved_in_extra():
    payload = {
        "type": "payment_initiation",
        "actions": ["execute"],
        "instructedAmount": {"currency": "EUR", "amount": "100.50"},
        "creditorName": "Merchant Bob",
        "custom_flags": [1, 2, 3],
    }
    details = parse_authorization_details(payload)
    detail = details[0]
    assert detail.extra["instructedAmount"] == {"currency": "EUR", "amount": "100.50"}
    assert detail.extra["creditorName"] == "Merchant Bob"
    assert detail.extra["custom_flags"] == [1, 2, 3]

    # Verify serialization retains extra
    d = detail.to_dict()
    assert d["instructedAmount"] == {"currency": "EUR", "amount": "100.50"}
    assert d["creditorName"] == "Merchant Bob"
    assert d["custom_flags"] == [1, 2, 3]


def test_serialization_to_dict_and_json():
    detail = AuthorizationDetail(
        type="customer_information",
        locations=["https://api.example.com/customers"],
        actions=["read"],
        datatypes=["profile"],
        identifier="cust-123",
        privileges=["view"],
        extra={"custom_attr": "value"},
    )
    d = detail.to_dict()
    assert d == {
        "type": "customer_information",
        "locations": ["https://api.example.com/customers"],
        "actions": ["read"],
        "datatypes": ["profile"],
        "identifier": "cust-123",
        "privileges": ["view"],
        "custom_attr": "value",
    }
    json_str = detail.to_json()
    assert '"type":"customer_information"' in json_str
    assert '"custom_attr":"value"' in json_str

    collection = AuthorizationDetails([detail])
    assert collection.to_list() == [d]
    assert collection.to_json() == f"[{json_str}]"


def test_roundtrip_serialization_matches_input():
    raw_json = (
        '[{"actions":["read","write"],"extra_data":{"nested":"val"},'
        '"identifier":"res-1","locations":["https://api.example.com"],'
        '"privileges":["owner"],"type":"cloud_resource"}]'
    )
    details = parse_authorization_details(raw_json)
    serialized_json = details.to_json()
    reparsed = parse_authorization_details(serialized_json)
    assert len(details) == len(reparsed)
    assert compare_details_exact(details[0], reparsed[0])


def test_exact_comparison_rfc8259_rules():
    # RFC 8259 Section 8.3: strings are equal if and only if they consist of the same sequence of Unicode code points,
    # ignoring differences between representations that could be made equivalent by normalization.
    # e.g., 'e' with acute accent: NFC vs NFD
    s_composed = "\u00e9"  # é in NFC (1 code point)
    s_decomposed = "e\u0301"  # e + combining acute accent in NFD (2 code points)
    assert unicodedata.normalize("NFC", s_decomposed) == s_composed
    assert s_composed != s_decomposed  # Code point sequences differ

    d1 = AuthorizationDetail(type="test", identifier=s_composed)
    d2 = AuthorizationDetail(type="test", identifier=s_decomposed)
    assert not compare_details_exact(d1, d2)

    d3 = AuthorizationDetail(type="test", identifier=s_composed)
    assert compare_details_exact(d1, d3)

    # Boolean vs int in extra should not be equal even though in Python True == 1
    d_bool = AuthorizationDetail(type="test", extra={"flag": True})
    d_int = AuthorizationDetail(type="test", extra={"flag": 1})
    assert not compare_details_exact(d_bool, d_int)


def test_invalid_json_string_raises_rfc9396_error():
    with pytest.raises(RFC9396Error):
        parse_authorization_details("{invalid_json:")

    with pytest.raises(RFC9396Error):
        parse_authorization_details("12345")


def test_empty_authorization_details_handling():
    # Empty list
    details = parse_authorization_details([])
    assert len(details) == 0
    assert details.to_list() == []
    assert details.to_json() == "[]"
    assert list(details) == []

    # Empty JSON array string
    details_str = parse_authorization_details("[]")
    assert len(details_str) == 0
    assert details_str.to_list() == []
    assert details_str.to_json() == "[]"


def test_authorization_details_iter_len_getitem():
    d1 = AuthorizationDetail(type="t1")
    d2 = AuthorizationDetail(type="t2")
    details = AuthorizationDetails([d1, d2])
    assert len(details) == 2
    assert details[0] == d1
    assert details[1] == d2
    assert list(details) == [d1, d2]
    slice_details = details[0:1]
    assert isinstance(slice_details, AuthorizationDetails)
    assert len(slice_details) == 1
    assert slice_details[0] == d1


def test_validation_explicit_call():
    invalid_detail = AuthorizationDetail(type=123)  # type: ignore
    with pytest.raises(InvalidAuthorizationDetailError):
        invalid_detail.validate()

    invalid_details = AuthorizationDetails([invalid_detail])
    with pytest.raises(InvalidAuthorizationDetailError):
        invalid_details.validate()


def test_duplicate_type_error_export():
    assert issubclass(DuplicateTypeError, RFC9396Error)

