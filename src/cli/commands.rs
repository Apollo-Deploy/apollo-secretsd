//! Command vocabulary mirrors privileged operations without adding reveal paths.
use super::Args;
use apollo_secretsd::{Error, Result};
use secretsd_protocol::{admin_request::Action, *};

pub(super) fn action(args: &Args) -> Result<Action> {
    let command = args
        .positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    Ok(match command.as_slice() {
        ["status"] => Action::Status(Empty {}),
        ["namespace", "create"] => Action::NamespaceCreate(Empty {}),
        ["namespace", "inspect"] => Action::NamespaceInspect(Identity {
            id: args.id("--namespace")?,
        }),
        ["namespace", "delete"] => Action::NamespaceDelete(Identity {
            id: args.id("--namespace")?,
        }),
        ["secret", "create"] => Action::SecretCreate(input(args, false)?),
        ["secret", "put"] => Action::SecretPut(input(args, true)?),
        ["secret", "metadata"] => Action::SecretMetadata(reference(args)?),
        ["secret", "list"] => Action::SecretList(ListSecrets {
            namespace: args.id("--namespace")?,
            after: args
                .options
                .get("--after")
                .map(|s| super::parse_id(s))
                .transpose()?
                .unwrap_or_default(),
            limit: args.number("--limit", 128)?,
        }),
        ["secret", "activate"] => Action::SecretActivate(reference(args)?),
        ["secret", "disable"] => Action::SecretDisable(reference(args)?),
        ["secret", "delete"] => Action::SecretDelete(reference(args)?),
        ["grant", "issue"] => Action::GrantIssue(IssueGrant {
            scope: Some(reference(args)?),
            recipient: args.id("--recipient")?,
            generation: args.number("--generation", 0)?,
            uid: args.number("--uid", u32::MAX)?,
            gid: args.number("--gid", u32::MAX)?,
            pid: args.number("--pid", 0)?,
            ttl_ms: args.number("--ttl-ms", 0)?,
            max_uses: args.number("--max-uses", 0)?,
            cgroup: args.options.get("--cgroup").cloned().unwrap_or_default(),
        }),
        ["grant", "revoke"] => {
            let kind = match args.get("--kind")? {
                "capability" => RevocationKind::Capability,
                "recipient" => RevocationKind::Recipient,
                "namespace" => RevocationKind::Namespace,
                _ => return Err(Error::Invalid),
            };

            let id = match kind {
                RevocationKind::Capability => args.id("--capability")?,
                RevocationKind::Recipient => args.id("--recipient")?,
                RevocationKind::Namespace => args.id("--namespace")?,
            };

            Action::Revoke(Revoke {
                kind: kind as i32,
                id,
                next_generation: args.number("--next-generation", 0)?,
            })
        }
        ["key", "status"] => Action::KeyStatus(Empty {}),
        ["key", "rotate"] => Action::KeyRotate(Empty {}),
        ["audit", "verify"] => Action::Audit(AuditQuery {
            verify: true,
            after: 0,
            limit: 1,
        }),
        ["audit", "tail"] => Action::Audit(AuditQuery {
            verify: false,
            after: args.number("--after", 0)?,
            limit: args.number("--limit", 32)?,
        }),
        _ => return Err(Error::Invalid),
    })
}

fn reference(args: &Args) -> Result<SecretRef> {
    Ok(SecretRef {
        namespace: args.id("--namespace")?,
        secret: args.id("--secret")?,
        version: args.number("--version", 0)?,
    })
}

fn input(args: &Args, update: bool) -> Result<SecretInput> {
    Ok(SecretInput {
        scope: Some(SecretRef {
            namespace: args.id("--namespace")?,
            secret: if update {
                args.id("--secret")?
            } else {
                Vec::new()
            },
            version: 0,
        }),
        name: args.get("--name")?.into(),
        length: 0,
    })
}
