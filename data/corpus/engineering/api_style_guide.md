# API Style Guide

## Versioning
All public endpoints are versioned in the path: /v1/..., /v2/.... Breaking changes require a new
version and a 90 day deprecation window announced in the changelog.

## Naming
Use plural nouns for collections (orders, invoices) and lower-case, hyphen-separated path
segments. Query parameters use snake_case. Resource identifiers are opaque UUIDv7 strings.

## Errors
Return RFC 9457 problem documents with type, title, status, detail and instance. Never leak
stack traces or internal hostnames in error responses.

## Pagination
Cursor pagination is required for any collection that can exceed 500 items. Responses include
next_cursor and a stable sort key.

## Rate limits
Publish limits in the X-RateLimit-Limit and X-RateLimit-Remaining headers and return 429 with
Retry-After. Internal service-to-service calls get a higher bucket than customer traffic.

## Security
Authenticate with short-lived bearer tokens; tokens expire after 15 minutes. Validate input at
the boundary, reject unknown fields, and never log request bodies that may contain credentials.
