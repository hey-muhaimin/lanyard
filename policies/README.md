# Cedar policy bundles

`schema.cedarschema.json` defines Lanyard agent, connector action, resource, and request-context shapes. Policy bundles are tenant-versioned in the database; `default.cedar` is a development example, not an implicit production policy.

Validate a bundle before creating or publishing it:

```sh
cedar validate --schema policies/schema.cedarschema.json --schema-format json \
	--policies policies/default.cedar --policy-format cedar
```

Only the approval subsystem may verify an approval reference and set `context.approval.status` to `granted`. Grant request fields cannot directly set this context value. Cedar denies when no active policy set is loaded.
