# Prototype Pollution Admin Escalation Artifact

Create `/src/pollution.json`, an offline exploit object for a synthetic Node.js recursive merge bug. The target merges attacker JSON into a fresh options object, then grants admin if inherited `isAdmin === true` and `role === "admin"`. Submit only the JSON object; no network or live service is involved.
