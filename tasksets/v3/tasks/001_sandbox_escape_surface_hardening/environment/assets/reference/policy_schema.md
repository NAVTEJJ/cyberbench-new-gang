# Policy schema and semantics

The files below are declarative policy. Lists are unordered unless order is explicitly meaningful. A policy may be stricter than the supplied examples as long as every required workflow remains possible.

## `services.json`

Each service has:

- `networks`: direct transport domains; sharing any value makes two services direct peers;
- `user`: runtime user;
- `capabilities`: added Linux capabilities;
- `no_new_privileges`: whether exec may gain privilege;
- `read_only_rootfs`: whether the root filesystem is immutable;
- `writable_paths`: explicit writable exceptions;
- `mounts`: `{source, target, mode}` objects;
- `seccomp`: `unconfined`, `default`, or a named restrictive profile;
- `pid_namespace`: `host` or `private`;
- `identity`: credential principal name.

Network names are not prescribed. Effective peer relationships are what matter.

## `proxy.json`

- `listen_networks`: networks on which the proxy accepts requests;
- `allowed_schemes`: permitted URI schemes;
- `destination_rules`: `{host, ports, path_prefixes, methods}` rules;
- `redirect_policy`: `never`, `same-origin`, or `any`;
- `allow_ip_literals`: permits an IP address in place of a hostname;
- `revalidate_dns`: validates destination identity and address after redirects or DNS changes;
- `strip_auth_on_redirect`: removes request authorization before following a redirect;
- `forward_caller_auth`: forwards the caller's credential to the destination.

Rules match an exact host unless the host is `*`. Paths match by prefix. Wildcard ports, paths, or methods are represented by `"*"`.

## `credentials.json`

Each entry in `principals.<name>.tokens` describes one independently issued token:

```json
{
  "audience": "receiving-service",
  "scopes": ["operation:verb"],
  "ttl_seconds": 120,
  "token_forwarding": false
}
```

Audience and scope are evaluated together on the same token. Wildcards grant authority outside a single workflow hop. Required tokens must be short lived; tokens lasting longer than five minutes are not considered short lived.

## `artifacts.json`

The uploader policy declares allowed methods, paths, content types and sizes; whether symlinks or archive extraction are permitted; whether manifests may be parsed without extraction; whether scanning is mandatory; the uploader token audience/scope; and the token audience/scope used for the scanner handoff.

An archive flag means the submitted opaque object happens to be an archive. Manifest parsing is metadata inspection and does not require extracting its payload.
