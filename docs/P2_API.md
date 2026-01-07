# P2/DSN Encrypted Storage Layer API Documentation

## Overview

The P2 API provides a RESTful interface for interacting with the P2/DSN (Distributed Storage Network) Encrypted Storage Layer. This document describes all available endpoints, their request/response formats, and usage examples.

**Base URL**: `http://localhost:3000` (default)

**Content-Type**: `application/json`

---

## Table of Contents

1. [Health & Status](#health--status)
2. [Payload Management](#payload-management)
3. [Ticket Management](#ticket-management)
4. [Evidence Management](#evidence-management)
5. [Snapshot Management](#snapshot-management)
6. [Audit Management](#audit-management)
7. [Sync Operations](#sync-operations)

---

## Health & Status

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "storage_backend": "local",
  "uptime_seconds": 3600
}
```

### GET /ready

Readiness check endpoint.

**Response:**
```json
{
  "status": "ready",
  "storage_available": true,
  "ledgers_loaded": true
}
```

---

## Payload Management

### POST /api/v1/payloads

Write a new encrypted payload.

**Request:**
```json
{
  "data": "base64_encoded_encrypted_data",
  "content_type": "application/octet-stream",
  "temperature": "hot",
  "actor_id": "actor_abc123",
  "metadata": {
    "original_size": 1024,
    "encryption_version": "v1"
  }
}
```

**Temperature Values:**
- `hot` - Frequently accessed, low latency
- `warm` - Moderately accessed
- `cold` - Archival, high latency acceptable

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "checksum": "blake3_hex_digest",
  "size": 1024,
  "temperature": "hot",
  "created_at": "2025-01-01T00:00:00Z",
  "evidence_level": "b_level"
}
```

### GET /api/v1/payloads/:ref_id

Get payload metadata by reference ID.

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "checksum": "blake3_hex_digest",
  "size": 1024,
  "content_type": "application/octet-stream",
  "temperature": "hot",
  "created_at": "2025-01-01T00:00:00Z",
  "last_accessed": "2025-01-01T12:00:00Z",
  "access_count": 5,
  "evidence_level": "a_level"
}
```

### GET /api/v1/payloads/:ref_id/data

Read encrypted payload data (requires valid ticket).

**Headers:**
- `X-Ticket-Ref`: Ticket reference ID

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "data": "base64_encoded_encrypted_data",
  "checksum": "blake3_hex_digest"
}
```

### DELETE /api/v1/payloads/:ref_id

Tombstone a payload (soft delete).

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "tombstoned": true,
  "tombstoned_at": "2025-01-01T00:00:00Z"
}
```

### POST /api/v1/payloads/:ref_id/verify

Verify payload integrity.

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "valid": true,
  "checksum_match": true,
  "size_match": true,
  "verified_at": "2025-01-01T00:00:00Z"
}
```

### GET /api/v1/payloads/:ref_id/temperature

Get current temperature tier.

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "temperature": "warm",
  "last_access": "2025-01-01T00:00:00Z",
  "access_count_30d": 3,
  "migration_eligible": true
}
```

### POST /api/v1/payloads/:ref_id/preheat

Request preheating (Cold -> Hot migration).

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "status": "preheating",
  "estimated_ready_at": "2025-01-01T00:05:00Z"
}
```

---

## Ticket Management

### POST /api/v1/tickets

Issue a new access ticket.

**Request:**
```json
{
  "holder": "actor_holder_id",
  "target_payload_ref": "payload:abc123def456",
  "permissions": ["Read", "Export"],
  "purpose_digest": "blake3_purpose_hash",
  "valid_until": "2025-01-02T00:00:00Z",
  "one_time": true,
  "max_uses": 1
}
```

**Permissions:**
- `Read` - Read encrypted payload data
- `Export` - Export payload to external systems
- `Verify` - Verify payload integrity and commitments
- `Audit` - View audit logs for the payload
- `Delegate` - Delegate access to other actors

**Response:**
```json
{
  "ticket_id": "ticket:abc123",
  "holder": "actor_holder_id",
  "target_payload_ref": "payload:abc123def456",
  "permissions": ["Read", "Export"],
  "issued_at": "2025-01-01T00:00:00Z",
  "valid_until": "2025-01-02T00:00:00Z",
  "one_time": true,
  "use_count": 0,
  "max_uses": 1,
  "status": "active"
}
```

### GET /api/v1/tickets/:ticket_id

Get ticket by ID.

**Response:** Same as POST /api/v1/tickets response.

### POST /api/v1/tickets/:ticket_id/validate

Validate a ticket.

**Request:**
```json
{
  "requested_permission": "Read",
  "target_payload_ref": "payload:abc123def456"
}
```

**Response:**
```json
{
  "valid": true,
  "ticket_id": "ticket:abc123",
  "remaining_uses": 1,
  "expires_in_seconds": 86400
}
```

### POST /api/v1/tickets/:ticket_id/use

Use (consume) a ticket.

**Request:**
```json
{
  "permission": "Read",
  "purpose_digest": "blake3_purpose_hash",
  "requester_ip": "192.168.1.1"
}
```

**Response:**
```json
{
  "success": true,
  "ticket_id": "ticket:abc123",
  "use_count": 1,
  "audit_log_id": "audit:xyz789"
}
```

### POST /api/v1/tickets/:ticket_id/revoke

Revoke a ticket.

**Request:**
```json
{
  "reason": "Security concern"
}
```

**Response:**
```json
{
  "ticket_id": "ticket:abc123",
  "revoked": true,
  "revoked_at": "2025-01-01T00:00:00Z",
  "reason": "Security concern"
}
```

### GET /api/v1/tickets/holder/:holder_id

List tickets for a holder.

**Query Parameters:**
- `status` (optional) - Filter by status (active, used, revoked, expired)
- `limit` (default: 100)
- `offset` (default: 0)

**Response:**
```json
{
  "tickets": [...],
  "total": 50,
  "limit": 100,
  "offset": 0
}
```

### GET /api/v1/tickets/payload/:payload_ref

List tickets for a payload.

**Response:** Same format as holder listing.

---

## Evidence Management

### GET /api/v1/evidence/:ref_id

Get evidence package for a payload.

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "evidence_level": "a_level",
  "payload_map_commit_ref": "pmc:abc123",
  "receipt_ref": "receipt:xyz789",
  "created_at": "2025-01-01T00:00:00Z",
  "verified_at": "2025-01-01T00:05:00Z",
  "chain_anchored": true
}
```

### POST /api/v1/evidence/:ref_id/export

Export evidence package.

**Request:**
```json
{
  "ticket_ref": "ticket:abc123",
  "format": "json",
  "include_payload": false,
  "destination": "external-system"
}
```

**Export Formats:**
- `json` - JSON format
- `cbor` - CBOR binary format
- `protobuf` - Protocol Buffers

**Response:**
```json
{
  "export_id": "export:abc123",
  "ref_id": "payload:abc123def456",
  "format": "json",
  "exported_at": "2025-01-01T00:00:00Z",
  "audit_log_id": "audit:xyz789"
}
```

### GET /api/v1/evidence/:ref_id/verify

Verify evidence integrity.

**Response:**
```json
{
  "ref_id": "payload:abc123def456",
  "valid": true,
  "evidence_level": "a_level",
  "checks": {
    "payload_exists": true,
    "checksum_valid": true,
    "map_commit_valid": true,
    "receipt_valid": true,
    "chain_anchored": true
  },
  "verified_at": "2025-01-01T00:00:00Z"
}
```

### GET /api/v1/evidence/actor/:actor_id

List evidence for an actor.

**Query Parameters:**
- `evidence_level` (optional) - Filter by level (a_level, b_level)
- `from` (optional) - Start timestamp
- `to` (optional) - End timestamp
- `limit` (default: 100)
- `offset` (default: 0)

**Response:**
```json
{
  "items": [...],
  "total": 100,
  "limit": 100,
  "offset": 0
}
```

---

## Snapshot Management

### POST /api/v1/snapshots/r0

Create an R0 (skeleton) snapshot.

**Request:**
```json
{
  "actor_id": "actor:abc123",
  "trigger": "manual",
  "policy_version": "v1"
}
```

**Trigger Types:**
- `subject_onset` - Subject onset event
- `scheduled` - Scheduled backup
- `manual` - Manual trigger
- `pre_migration` - Pre-migration checkpoint

**Response:**
```json
{
  "snapshot_id": "r0:abc123def456",
  "snapshot_type": "r0",
  "actor_id": "actor:abc123",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### POST /api/v1/snapshots/r1

Create an R1 (full resurrection) snapshot.

**Request:**
```json
{
  "actor_id": "actor:abc123",
  "r0_snapshot_id": "r0:abc123def456",
  "guardian_consent_ref": "consent:xyz789",
  "approving_authority": "guardian:001"
}
```

**Response:**
```json
{
  "snapshot_id": "r1:xyz789abc123",
  "snapshot_type": "r1",
  "actor_id": "actor:abc123",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### GET /api/v1/snapshots/:snapshot_id

Get snapshot details.

**Response:**
```json
{
  "type": "r0",
  "snapshot": {
    "snapshot_id": "r0:abc123def456",
    "actor_id": "actor:abc123",
    "package_digest": "blake3_hex",
    "trigger": "manual",
    "generated_at": "2025-01-01T00:00:00Z",
    "policy_version": "v1",
    "payload_count": 10
  }
}
```

### GET /api/v1/snapshots

List snapshots with filtering.

**Query Parameters:**
- `actor_id` (optional) - Filter by actor
- `type` (optional) - Filter by type (r0, r1)
- `limit` (default: 50)
- `offset` (default: 0)

**Response:**
```json
{
  "r0_snapshots": [...],
  "r1_snapshots": [...],
  "total": 20
}
```

### GET /api/v1/snapshots/r0/latest/:actor_id

Get latest R0 snapshot for an actor.

**Response:** Same as GET /api/v1/snapshots/:snapshot_id

### GET /api/v1/snapshots/r1/latest/:actor_id

Get latest R1 snapshot for an actor.

**Response:** Same as GET /api/v1/snapshots/:snapshot_id

### POST /api/v1/snapshots/:snapshot_id/verify

Verify snapshot integrity.

**Response:**
```json
{
  "snapshot_id": "r0:abc123def456",
  "valid": true,
  "snapshot_type": "r0",
  "verified_at": "2025-01-01T00:00:00Z",
  "errors": []
}
```

### POST /api/v1/snapshots/compare

Compare two snapshots.

**Request:**
```json
{
  "snapshot_a": "r0:abc123",
  "snapshot_b": "r0:def456"
}
```

**Response:**
```json
{
  "snapshot_a": "r0:abc123",
  "snapshot_b": "r0:def456",
  "identical": false,
  "differences": [
    {
      "field": "payload_count",
      "value_a": "10",
      "value_b": "12"
    }
  ],
  "compared_at": "2025-01-01T00:00:00Z"
}
```

### GET /api/v1/snapshots/stats

Get snapshot statistics.

**Response:**
```json
{
  "total_r0": 100,
  "total_r1": 5,
  "actors_with_r0": 50,
  "actors_with_r1": 3,
  "storage_bytes": 1073741824,
  "oldest_snapshot": "2024-01-01T00:00:00Z",
  "newest_snapshot": "2025-01-01T00:00:00Z",
  "computed_at": "2025-01-01T00:00:00Z"
}
```

---

## Audit Management

### GET /api/v1/audit

Query audit logs.

**Query Parameters:**
- `type` (optional) - Filter by entry type (decrypt, export, access_denied, policy_violation)
- `actor_id` (optional) - Filter by actor
- `payload_ref` (optional) - Filter by payload
- `ticket_ref` (optional) - Filter by ticket
- `from` (optional) - Start timestamp (ISO 8601)
- `to` (optional) - End timestamp (ISO 8601)
- `limit` (default: 100)
- `offset` (default: 0)

**Response:**
```json
{
  "entries": [
    {
      "sequence": 42,
      "entry_type": "decrypt",
      "timestamp": "2025-01-01T00:00:00Z",
      "actor_id": "actor:abc123",
      "payload_ref": "payload:xyz789",
      "ticket_ref": "ticket:def456",
      "details": {
        "purpose": "testing",
        "success": true
      },
      "entry_hash": "sha256_hex",
      "prev_hash": "sha256_hex_prev"
    }
  ],
  "total_count": 100,
  "offset": 0,
  "limit": 100,
  "chain_verified": true,
  "query_time_ms": 15
}
```

### GET /api/v1/audit/payload/:payload_ref

Get audit logs for a specific payload.

**Response:** Same format as GET /api/v1/audit

### GET /api/v1/audit/actor/:actor_id

Get audit logs for a specific actor.

**Response:** Same format as GET /api/v1/audit

### GET /api/v1/audit/entry/:sequence

Get a specific audit entry by sequence number.

**Response:**
```json
{
  "sequence": 42,
  "entry_type": "decrypt",
  "timestamp": "2025-01-01T00:00:00Z",
  "actor_id": "actor:abc123",
  "payload_ref": "payload:xyz789",
  "ticket_ref": "ticket:def456",
  "details": {...},
  "entry_hash": "sha256_hex",
  "prev_hash": "sha256_hex_prev"
}
```

### POST /api/v1/audit/verify

Verify audit chain integrity.

**Response:**
```json
{
  "chain_id": "chain:abc123",
  "verified": true,
  "entries_checked": 1000,
  "verified_at": "2025-01-01T00:00:00Z",
  "error": null
}
```

### GET /api/v1/audit/stats

Get audit statistics.

**Response:**
```json
{
  "chain_id": "chain:abc123",
  "total_entries": 10000,
  "decrypt_count": 5000,
  "export_count": 200,
  "access_denied_count": 50,
  "policy_violation_count": 5,
  "chain_verified": true,
  "oldest_entry": "2024-01-01T00:00:00Z",
  "newest_entry": "2025-01-01T00:00:00Z",
  "computed_at": "2025-01-01T00:00:00Z"
}
```

### GET /api/v1/audit/decrypt

Get decrypt audit logs.

**Query Parameters:** Same as GET /api/v1/audit

**Response:** Same format as GET /api/v1/audit

### GET /api/v1/audit/export-logs

Get export audit logs.

**Query Parameters:** Same as GET /api/v1/audit

**Response:** Same format as GET /api/v1/audit

### POST /api/v1/audit/export

Export audit logs for compliance.

**Request:**
```json
{
  "from": "2024-01-01T00:00:00Z",
  "to": "2025-01-01T00:00:00Z",
  "format": "json",
  "include_hashes": true
}
```

**Response:**
```json
{
  "export_id": "export:audit123",
  "entry_count": 10000,
  "format": "json",
  "from": "2024-01-01T00:00:00Z",
  "to": "2025-01-01T00:00:00Z",
  "exported_at": "2025-01-01T00:00:00Z",
  "download_url": null
}
```

---

## Sync Operations

### POST /api/v1/sync/commit

Submit a PayloadMapCommit for three-phase sync.

**Request:**
```json
{
  "actor_id": "actor:abc123",
  "payload_refs": ["payload:abc", "payload:def"],
  "sealed_payload_refs_digest": "blake3_hex",
  "evidence_level": "b_level"
}
```

**Response:**
```json
{
  "commit_id": "pmc:abc123",
  "actor_id": "actor:abc123",
  "status": "phase1_complete",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### GET /api/v1/sync/status/:commit_id

Get sync status for a commit.

**Response:**
```json
{
  "commit_id": "pmc:abc123",
  "phase": "phase3",
  "status": "complete",
  "receipt_ref": "receipt:xyz789",
  "evidence_level": "a_level",
  "updated_at": "2025-01-01T00:05:00Z"
}
```

### POST /api/v1/sync/reconcile

Trigger reconciliation check.

**Request:**
```json
{
  "actor_id": "actor:abc123",
  "from_sequence": 1,
  "to_sequence": 100
}
```

**Response:**
```json
{
  "reconciliation_id": "recon:abc123",
  "status": "in_progress",
  "started_at": "2025-01-01T00:00:00Z"
}
```

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Payload payload:abc123 not found"
  }
}
```

**HTTP Status Codes:**
- `200 OK` - Success
- `201 Created` - Resource created
- `202 Accepted` - Request accepted for processing
- `400 Bad Request` - Validation error
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Permission denied
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

**Error Codes:**
- `NOT_FOUND` - Resource not found
- `INVALID_REQUEST` - Invalid request parameters
- `TICKET_REQUIRED` - Valid ticket required
- `TICKET_EXPIRED` - Ticket has expired
- `TICKET_EXHAUSTED` - Ticket uses exhausted
- `PERMISSION_DENIED` - Insufficient permissions
- `LEGAL_HOLD` - Resource under legal hold
- `RETENTION_POLICY` - Retention policy violation
- `RATE_LIMITED` - Rate limit exceeded

---

## Pagination

List endpoints support pagination:

**Query Parameters:**
- `limit` (default: 100, max: 1000) - Items per page
- `offset` (default: 0) - Starting offset

**Response:**
```json
{
  "items": [...],
  "total": 1000,
  "limit": 100,
  "offset": 0
}
```

---

## Authentication

### JWT Authentication

Include JWT token in Authorization header:

```
Authorization: Bearer <jwt_token>
```

### Ticket-based Access

For payload data access, include ticket reference:

```
X-Ticket-Ref: ticket:abc123
```

---

## Data Types

### Digest Format
All digests are BLAKE3 hashes, hex-encoded (64 characters).

### Timestamps
All timestamps are ISO 8601 format in UTC: `2025-01-01T00:00:00Z`

### IDs
IDs are prefixed identifiers:
- Payload: `payload:ULID`
- Ticket: `ticket:ULID`
- Snapshot (R0): `r0:ULID`
- Snapshot (R1): `r1:ULID`
- Audit: `audit:ULID`

---

## Evidence Levels

P2 supports two evidence levels:

- **B-Level (B级证据)**: Encrypted storage with local commitment
- **A-Level (A级证据)**: Anchored on L0 Public Reality Ledger with receipt

Evidence level is determined by:
1. Presence of PayloadMapCommit on L0
2. Valid L0 Receipt
3. Successful reconciliation

---

## Temperature Tiers

P2 supports three storage temperature tiers:

| Tier | Access Latency | Cost | Use Case |
|------|---------------|------|----------|
| Hot | < 100ms | High | Frequently accessed |
| Warm | < 1s | Medium | Moderately accessed |
| Cold | < 30s | Low | Archival |

Automatic migration:
- Hot → Warm: 7 days without access
- Warm → Cold: 30 days without access

Preheating (Cold → Hot) available on demand.

---

## Retention Policy

Retention policies by content type:

| Content Type | Min Retention | Max Retention |
|--------------|---------------|---------------|
| evidence/* | 7 years | Indefinite |
| audit/* | 10 years | Indefinite |
| snapshot/* | 5 years | 20 years |
| temporary/* | 1 day | 30 days |

Legal holds override all retention policies.

---

## Rate Limiting

Default rate limits:

| Endpoint Type | Limit |
|--------------|-------|
| Read operations | 1000/min |
| Write operations | 100/min |
| Export operations | 10/min |

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1609459200
```

---

## Audit Trail

All operations that access payload data generate audit entries:

1. **Decrypt** - When payload is decrypted
2. **Export** - When payload is exported
3. **Access Denied** - When access is denied
4. **Policy Violation** - When policy is violated

Audit entries are cryptographically chained for tamper detection.
