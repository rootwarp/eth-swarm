//! The wire surface of a package, read from the compiled descriptor set: which RPCs stream,
//! which are unary, and which carry `common.v1.Envelope` in their request or response.
//!
//! The suite uses it so a rule never passes silently: a package with a streaming RPC must have
//! a probe, and a rule with nothing to apply to asserts that the surface is really absent.

use std::collections::{BTreeMap, BTreeSet};

use ethswarm_proto::FILE_DESCRIPTOR_SET;
use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorSet};

const ENVELOPE: &str = ".ethswarm.common.v1.Envelope";
const HELLO: &str = ".ethswarm.common.v1.Hello";

/// One RPC of a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpc {
    /// `/<package>.<Service>/<Method>`.
    pub path: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
    /// The request message contains an `Envelope` (at any depth).
    pub request_envelopes: bool,
    /// The response message contains an `Envelope` (at any depth).
    pub response_envelopes: bool,
    /// The request message has a `Hello` field of its own.
    pub request_hello: bool,
    /// Every streamed message of the RPC is `oneof frame { Hello hello = 1; <Body> body = 2; }`,
    /// and a server-streaming request (the client's only frame) carries a `Hello` field.
    pub framed: bool,
}

impl Rpc {
    #[must_use]
    pub fn streaming(&self) -> bool {
        self.client_streaming || self.server_streaming
    }
}

/// Every RPC of one package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
    pub package: String,
    pub rpcs: Vec<Rpc>,
}

impl Surface {
    /// RPCs with a stream in either direction.
    pub fn streams(&self) -> impl Iterator<Item = &Rpc> {
        self.rpcs.iter().filter(|r| r.streaming())
    }

    /// Unary RPCs.
    pub fn unary(&self) -> impl Iterator<Item = &Rpc> {
        self.rpcs.iter().filter(|r| !r.streaming())
    }

    /// Whether any RPC carries an envelope in either direction.
    #[must_use]
    pub fn carries_envelopes(&self) -> bool {
        self.rpcs
            .iter()
            .any(|r| r.request_envelopes || r.response_envelopes)
    }

    /// The RPC at `path`.
    #[must_use]
    pub fn rpc(&self, path: &str) -> Option<&Rpc> {
        self.rpcs.iter().find(|r| r.path == path)
    }
}

fn index(set: &FileDescriptorSet) -> BTreeMap<String, &DescriptorProto> {
    fn walk<'a>(
        prefix: &str,
        messages: &'a [DescriptorProto],
        out: &mut BTreeMap<String, &'a DescriptorProto>,
    ) {
        for m in messages {
            let name = format!("{prefix}.{}", m.name());
            walk(&name, &m.nested_type, out);
            out.insert(name, m);
        }
    }
    let mut out = BTreeMap::new();
    for f in &set.file {
        walk(&format!(".{}", f.package()), &f.message_type, &mut out);
    }
    out
}

fn contains(
    messages: &BTreeMap<String, &DescriptorProto>,
    root: &str,
    target: &str,
    seen: &mut BTreeSet<String>,
) -> bool {
    if root == target {
        return true;
    }
    if !seen.insert(root.to_owned()) {
        return false;
    }
    let Some(m) = messages.get(root) else {
        return false;
    };
    m.field
        .iter()
        .filter(|f| !f.type_name().is_empty())
        .any(|f| contains(messages, f.type_name(), target, seen))
}

/// `oneof frame` holding exactly `Hello hello = 1` and one message field numbered 2.
fn is_framed(messages: &BTreeMap<String, &DescriptorProto>, name: &str) -> bool {
    let Some(m) = messages.get(name) else {
        return false;
    };
    let Some(frame) = m.oneof_decl.iter().position(|o| o.name() == "frame") else {
        return false;
    };
    let members: Vec<_> = m
        .field
        .iter()
        .filter(|f| f.oneof_index.and_then(|i| usize::try_from(i).ok()) == Some(frame))
        .collect();
    members.len() == 2
        && members
            .iter()
            .any(|f| f.number() == 1 && f.name() == "hello" && f.type_name() == HELLO)
        && members
            .iter()
            .any(|f| f.number() == 2 && !f.type_name().is_empty() && f.type_name() != HELLO)
}

fn has_field_of(messages: &BTreeMap<String, &DescriptorProto>, root: &str, ty: &str) -> bool {
    messages
        .get(root)
        .is_some_and(|m| m.field.iter().any(|f| f.type_name() == ty))
}

/// The surface of `package` (e.g. `ethswarm.engine.v1`); panics if the package has no service.
#[must_use]
pub fn surface(package: &str) -> Surface {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("descriptor set decodes");
    let messages = index(&set);
    let mut rpcs = Vec::new();
    for file in set.file.iter().filter(|f| f.package() == package) {
        for service in &file.service {
            for m in &service.method {
                let (input, output) = (m.input_type(), m.output_type());
                rpcs.push(Rpc {
                    path: format!("/{package}.{}/{}", service.name(), m.name()),
                    client_streaming: m.client_streaming(),
                    server_streaming: m.server_streaming(),
                    request_envelopes: contains(&messages, input, ENVELOPE, &mut BTreeSet::new()),
                    response_envelopes: contains(&messages, output, ENVELOPE, &mut BTreeSet::new()),
                    request_hello: has_field_of(&messages, input, HELLO),
                    framed: (!m.server_streaming() || is_framed(&messages, output))
                        && if m.client_streaming() {
                            is_framed(&messages, input)
                        } else {
                            !m.server_streaming() || has_field_of(&messages, input, HELLO)
                        },
                });
            }
        }
    }
    assert!(!rpcs.is_empty(), "package {package} has no RPC");
    Surface {
        package: package.to_owned(),
        rpcs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unary_only_packages_have_no_stream_and_no_envelope() {
        for pkg in ["ethswarm.engine.v1", "ethswarm.sync.v1", "ethswarm.api.v1"] {
            let s = surface(pkg);
            assert_eq!(s.streams().count(), 0, "{pkg}");
            assert!(!s.carries_envelopes(), "{pkg}");
        }
    }

    #[test]
    fn chain_streams_and_carries_envelopes() {
        let s = surface("ethswarm.chain.v1");
        let import = s
            .rpc("/ethswarm.chain.v1.ImportService/ImportBatch")
            .unwrap();
        assert!(import.client_streaming && import.server_streaming);
        assert!(import.request_envelopes);
        assert!(!import.response_envelopes);
        let submit = s.rpc("/ethswarm.chain.v1.QueryService/Submit").unwrap();
        assert!(!submit.streaming() && submit.request_envelopes);
        let subscribe = s.rpc("/ethswarm.chain.v1.EventsService/Subscribe").unwrap();
        assert!(subscribe.server_streaming && subscribe.request_hello);
    }

    #[test]
    fn store_requests_carry_no_envelope_but_responses_do() {
        let s = surface("ethswarm.store.v1");
        assert!(s.rpcs.iter().all(|r| !r.request_envelopes));
        let cols = s
            .rpc("/ethswarm.store.v1.StoreService/GetDataColumns")
            .unwrap();
        assert!(cols.response_envelopes && cols.request_hello);
    }

    #[test]
    fn every_stream_of_every_package_has_the_frame_shape() {
        for pkg in ethswarm_proto::SERVICE_PACKAGES {
            for r in surface(pkg).streams() {
                assert!(r.framed, "{}", r.path);
            }
        }
    }

    #[test]
    fn frame_shape_needs_hello_at_one_and_a_body_at_two() {
        use prost_types::{FieldDescriptorProto, OneofDescriptorProto};
        let field = |name: &str, number, ty: &str| FieldDescriptorProto {
            name: Some(name.into()),
            number: Some(number),
            type_name: Some(ty.into()),
            oneof_index: Some(0),
            ..Default::default()
        };
        let msg = |fields| DescriptorProto {
            name: Some("M".into()),
            field: fields,
            oneof_decl: vec![OneofDescriptorProto {
                name: Some("frame".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let check = |m: DescriptorProto| {
            let mut index = BTreeMap::new();
            index.insert(".p.M".to_owned(), &m);
            is_framed(&index, ".p.M")
        };
        assert!(check(msg(vec![
            field("hello", 1, HELLO),
            field("body", 2, ".p.B")
        ])));
        assert!(!check(msg(vec![
            field("hello", 2, HELLO),
            field("body", 1, ".p.B")
        ])));
        assert!(!check(msg(vec![field("hello", 1, HELLO)])));
        assert!(!check(msg(vec![
            field("a", 1, ".p.A"),
            field("body", 2, ".p.B")
        ])));
        let mut no_oneof = msg(vec![field("hello", 1, HELLO), field("body", 2, ".p.B")]);
        no_oneof.oneof_decl.clear();
        assert!(!check(no_oneof));
    }

    #[test]
    fn no_unary_request_carries_a_hello() {
        for pkg in ethswarm_proto::SERVICE_PACKAGES {
            for r in surface(pkg).unary() {
                assert!(!r.request_hello, "{}", r.path);
            }
        }
    }

    #[test]
    #[should_panic(expected = "has no RPC")]
    fn unknown_package_panics() {
        let _ = surface("ethswarm.nope.v1");
    }
}
