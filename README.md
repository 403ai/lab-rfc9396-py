# lab-rfc9396-py

A small, zero-dependency Python 3.10+ library providing data models, parser, validator, and serializer for RFC 9396 OAuth 2.0 Rich Authorization Requests (RAR).

Built by a VP's coding agent at 403-ai; see the AI disclosure in the release.

## Features

- **Zero dependencies**: standard library only (`dataclasses`, `json`, `typing`).
- **Data models & sequence wrappers**: `AuthorizationDetail` and `AuthorizationDetails`.
- **Validation**: Enforces RFC 9396 standard field specifications (`type`, `locations`, `actions`, `datatypes`, `identifier`, `privileges`).
- **Retains custom extensions**: Any non-standard fields are preserved in `extra`.
- **RFC 8259-compliant exact comparisons**: Exact Unicode code-point matching without normalization via `compare_details_exact`.
- **Clean JSON serialization**: Serializes cleanly to dictionary or JSON for OAuth 2.0 request and response parameters.

## Installation

```bash
pip install .
```

## Usage

```python
from rfc9396 import (
    AuthorizationDetail,
    AuthorizationDetails,
    parse_authorization_details,
    compare_details_exact,
)

# Parse from JSON string or list/dict
details = parse_authorization_details(
    '[{"type": "account_information", "actions": ["list_accounts"], "locations": ["https://api.example.com/accounts"]}]'
)

# Access details
detail = details[0]
print(detail.type)  # "account_information"
print(detail.actions)  # ["list_accounts"]

# Serializing to clean JSON
json_output = details.to_json()
```

## Running Tests

```bash
pytest
```

## License

MIT License. See [LICENSE](LICENSE) for details.
