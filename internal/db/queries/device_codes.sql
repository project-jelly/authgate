-- name: InsertDeviceCode :exec
INSERT INTO device_codes (id, device_code, user_code, client_id, resource, scopes, state, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8);

-- name: GetDeviceAuthorizationForUpdate :one
SELECT id, client_id, COALESCE(resource, '') AS resource, scopes, state, subject, expires_at, auth_time, last_polled_at
FROM device_codes
WHERE device_code = $1 AND client_id = $2
FOR UPDATE;

-- name: UpdateDeviceCodeStateConsumedByID :exec
UPDATE device_codes
SET state = 'consumed'
WHERE id = $1;

-- name: UpdateDeviceCodeLastPolledAt :exec
UPDATE device_codes
SET last_polled_at = $1
WHERE id = $2;

-- name: GetDeviceCodeByUserCode :one
SELECT id, device_code, user_code, client_id, COALESCE(resource, '') AS resource, scopes, state, subject, expires_at, auth_time
FROM device_codes
WHERE user_code = $1;

-- name: ApproveDeviceCodeByUserCode :execrows
UPDATE device_codes
SET state = 'approved', subject = $1, auth_time = $2
WHERE user_code = $3 AND state = 'pending' AND expires_at > $2;

-- name: DenyDeviceCodeByUserCode :exec
UPDATE device_codes
SET state = 'denied'
WHERE user_code = $1 AND state = 'pending';
