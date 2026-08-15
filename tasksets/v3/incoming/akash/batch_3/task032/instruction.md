# GraphQL Alias Authorization Bypass Query

Create `/src/query.graphql`, an offline GraphQL query for a synthetic resolver bug. Authorization is checked only on the first top-level field, but aliased later fields still call `adminSecret(userId: "root")`. Submit only the query text.
