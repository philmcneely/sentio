-- 005: the `platform:admin` scope
--
-- Cross-tenant reach used to be implied by wildcard scope: a key with `*`
-- could address any tenant. But `*` is also what a tenant hands its own
-- keys, so `admin:api_keys:write` inside one tenant was enough to mint a
-- key that left it. Reach across tenants is now the named scope
-- `platform:admin`, which `*` does not cover.
--
-- Credentials that already had that reach keep it: the wildcard ones
-- belonging to the system tenant, which is the platform operator's own
-- (`config->>'system'`, seeded by 002). Nothing else gains anything.
--
-- Idempotent: the scope is only appended where it is absent.

UPDATE api_keys k
SET scopes = array_append(k.scopes, 'platform:admin')
FROM tenants t
WHERE t.id = k.tenant_id
  AND t.config ->> 'system' = 'true'
  AND '*' = ANY (k.scopes)
  AND NOT ('platform:admin' = ANY (k.scopes));

-- Same for OAuth bearer tokens, which resolve to the same AuthContext.
-- The API has no token endpoint, so any such row was seeded by hand.
UPDATE oauth_tokens o
SET scopes = array_append(o.scopes, 'platform:admin')
FROM tenants t
WHERE t.id = o.tenant_id
  AND t.config ->> 'system' = 'true'
  AND '*' = ANY (o.scopes)
  AND NOT ('platform:admin' = ANY (o.scopes));
