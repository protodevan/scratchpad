use std::{fs, io::{self, Read}, path::{Path, PathBuf}};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::{signatures::Signer, types::SignatureScheme, OpenMlsProvider};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

#[derive(Default)]
struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> { serde_json::to_vec(value) }
    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> { serde_json::from_slice(slice) }
}

struct PersistentProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}
impl PersistentProvider {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        let mut storage = SqliteStorageProvider::new(connection);
        storage.run_migrations().map_err(|e| e.to_string())?;
        Ok(Self { crypto: RustCrypto::default(), storage })
    }
}
impl OpenMlsProvider for PersistentProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;
    fn storage(&self) -> &Self::StorageProvider { &self.storage }
    fn crypto(&self) -> &Self::CryptoProvider { &self.crypto }
    fn rand(&self) -> &Self::RandProvider { &self.crypto }
}

#[derive(Serialize, Deserialize)]
struct PersistedIdentity { public_key_base64: String }

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Init { group_id: String, members: Vec<String> },
    AddMember { group_id: String, actor_device_id: String, new_device_id: String },
    RemoveMember { group_id: String, actor_device_id: String, remove_device_id: String },
    Encrypt { group_id: String, sender_device_id: String, plaintext_base64: String },
    Decrypt { group_id: String, receiver_device_id: String, wire_base64: String },
    GroupInfo { group_id: String, device_id: Option<String> },
}

fn hex_id(value: &str) -> String { value.as_bytes().iter().map(|b| format!("{b:02x}")).collect() }
fn device_dir(state: &Path, device_id: &str) -> PathBuf { state.join("devices").join(hex_id(device_id)) }
fn provider_for(state: &Path, device_id: &str) -> Result<PersistentProvider, String> { PersistentProvider::open(&device_dir(state, device_id).join("openmls.sqlite")) }
fn identity_path(state: &Path, device_id: &str) -> PathBuf { device_dir(state, device_id).join("identity.json") }
fn suite() -> Ciphersuite { Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 }
fn group_id(value: &str) -> GroupId { GroupId::from_slice(value.as_bytes()) }

fn credential(device_id: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(device_id.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn load_or_create_identity(state: &Path, device_id: &str, provider: &PersistentProvider) -> Result<SignatureKeyPair, String> {
    let path = identity_path(state, device_id);
    if path.exists() {
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        let identity: PersistedIdentity = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let public = B64.decode(identity.public_key_base64).map_err(|e| e.to_string())?;
        return SignatureKeyPair::read(provider.storage(), &public, SignatureScheme::ED25519)
            .ok_or_else(|| format!("persisted signer missing for device {device_id}"));
    }
    fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|e| format!("new signer: {e:?}"))?;
    signer.store(provider.storage()).map_err(|e| format!("store signer: {e:?}"))?;
    let metadata = PersistedIdentity { public_key_base64: B64.encode(signer.public()) };
    fs::write(&path, serde_json::to_vec(&metadata).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(signer)
}

fn key_package(state: &Path, device_id: &str) -> Result<KeyPackage, String> {
    let provider = provider_for(state, device_id)?;
    let signer = load_or_create_identity(state, device_id, &provider)?;
    let bundle = KeyPackage::builder().build(suite(), &provider, &signer, credential(device_id, &signer)).map_err(|e| format!("key package: {e:?}"))?;
    Ok(bundle.key_package().clone())
}

fn load_group(state: &Path, device_id: &str, room: &str) -> Result<(PersistentProvider, SignatureKeyPair, MlsGroup), String> {
    let provider = provider_for(state, device_id)?;
    let signer = load_or_create_identity(state, device_id, &provider)?;
    let group = MlsGroup::load(provider.storage(), &group_id(room)).map_err(|e| format!("load group: {e:?}"))?
        .ok_or_else(|| format!("group {room} not found for device {device_id}"))?;
    Ok((provider, signer, group))
}

fn out_to_in(out: MlsMessageOut) -> Result<MlsMessageIn, String> {
    let bytes = out.to_bytes().map_err(|e| format!("serialize message: {e:?}"))?;
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| format!("deserialize message: {e:?}"))
}
fn out_to_welcome(out: MlsMessageOut) -> Result<Welcome, String> {
    match out_to_in(out)?.extract() {
        MlsMessageBodyIn::Welcome(w) => Ok(w),
        _ => Err("expected Welcome".into()),
    }
}
fn member_ids(group: &MlsGroup) -> Vec<String> {
    group.members().map(|m| String::from_utf8_lossy(m.credential.serialized_content()).to_string()).collect()
}

fn process_commit_for(state: &Path, room: &str, device_id: &str, wire: &[u8]) -> Result<(), String> {
    let (provider, _signer, mut group) = load_group(state, device_id, room)?;
    let incoming = MlsMessageIn::tls_deserialize_exact(wire.to_vec()).map_err(|e| format!("deserialize commit: {e:?}"))?;
    let processed = group.process_message(&provider, incoming.try_into_protocol_message().map_err(|e| format!("protocol commit: {e:?}"))?)
        .map_err(|e| format!("process commit for {device_id}: {e:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => group.merge_staged_commit(&provider, *staged).map_err(|e| format!("merge commit for {device_id}: {e:?}"))?,
        _ => return Err("expected staged commit".into()),
    }
    Ok(())
}

fn init(state: &Path, room: &str, members: Vec<String>) -> Result<Value, String> {
    if members.is_empty() { return Err("at least one member required".into()); }
    let leader = &members[0];
    let leader_provider = provider_for(state, leader)?;
    let leader_signer = load_or_create_identity(state, leader, &leader_provider)?;
    if let Some(group) = MlsGroup::load(leader_provider.storage(), &group_id(room)).map_err(|e| format!("load existing: {e:?}"))? {
        return Ok(json!({"ok":true,"epoch":group.epoch().as_u64(),"members":member_ids(&group)}));
    }
    let config = MlsGroupCreateConfig::builder().ciphersuite(suite()).use_ratchet_tree_extension(true).build();
    let mut leader_group = MlsGroup::new_with_group_id(&leader_provider, &leader_signer, &config, group_id(room), credential(leader, &leader_signer))
        .map_err(|e| format!("create group: {e:?}"))?;
    if members.len() > 1 {
        let key_packages = members[1..].iter().map(|id| key_package(state, id)).collect::<Result<Vec<_>,_>>()?;
        let (_commit, welcome_out, _) = leader_group.add_members(&leader_provider, &leader_signer, &key_packages).map_err(|e| format!("add initial members: {e:?}"))?;
        leader_group.merge_pending_commit(&leader_provider).map_err(|e| format!("merge initial add: {e:?}"))?;
        let welcome_bytes = welcome_out.to_bytes().map_err(|e| format!("serialize welcome: {e:?}"))?;
        for id in &members[1..] {
            let provider = provider_for(state, id)?;
            let _signer = load_or_create_identity(state, id, &provider)?;
            let welcome = match MlsMessageIn::tls_deserialize_exact(welcome_bytes.clone()).map_err(|e| format!("welcome decode: {e:?}"))?.extract() {
                MlsMessageBodyIn::Welcome(w) => w,
                _ => return Err("expected welcome".into()),
            };
            let join = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
            StagedWelcome::new_from_welcome(&provider, &join, welcome, None).map_err(|e| format!("stage welcome {id}: {e:?}"))?
                .into_group(&provider).map_err(|e| format!("join {id}: {e:?}"))?;
        }
    }
    Ok(json!({"ok":true,"epoch":leader_group.epoch().as_u64(),"members":member_ids(&leader_group)}))
}

fn add_member(state: &Path, room: &str, actor: &str, new_member: &str) -> Result<Value, String> {
    let (provider, signer, mut group) = load_group(state, actor, room)?;
    let existing = member_ids(&group);
    if existing.iter().any(|x| x == new_member) { return Err("member already exists".into()); }
    let kp = key_package(state, new_member)?;
    let (commit_out, welcome_out, _) = group.add_members(&provider, &signer, &[kp]).map_err(|e| format!("add member: {e:?}"))?;
    let commit_wire = commit_out.to_bytes().map_err(|e| format!("commit bytes: {e:?}"))?;
    group.merge_pending_commit(&provider).map_err(|e| format!("merge add: {e:?}"))?;
    for id in existing.iter().filter(|id| id.as_str() != actor) { process_commit_for(state, room, id, &commit_wire)?; }
    let new_provider = provider_for(state, new_member)?;
    let _new_signer = load_or_create_identity(state, new_member, &new_provider)?;
    let join = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
    StagedWelcome::new_from_welcome(&new_provider, &join, out_to_welcome(welcome_out)?, None).map_err(|e| format!("stage new welcome: {e:?}"))?
        .into_group(&new_provider).map_err(|e| format!("join new member: {e:?}"))?;
    Ok(json!({"ok":true,"epoch":group.epoch().as_u64(),"members":member_ids(&group)}))
}

fn remove_member(state: &Path, room: &str, actor: &str, remove: &str) -> Result<Value, String> {
    let (provider, signer, mut group) = load_group(state, actor, room)?;
    let existing = member_ids(&group);
    if actor == remove { return Err("actor cannot remove itself through this bridge operation".into()); }
    let index = group.members().find(|m| m.credential.serialized_content() == remove.as_bytes()).map(|m| m.index).ok_or_else(|| "member not found".to_string())?;
    let (commit_out, _, _) = group.remove_members(&provider, &signer, &[index]).map_err(|e| format!("remove member: {e:?}"))?;
    let commit_wire = commit_out.to_bytes().map_err(|e| format!("remove commit bytes: {e:?}"))?;
    group.merge_pending_commit(&provider).map_err(|e| format!("merge remove: {e:?}"))?;
    for id in existing.iter().filter(|id| id.as_str() != actor) { process_commit_for(state, room, id, &commit_wire)?; }
    Ok(json!({"ok":true,"epoch":group.epoch().as_u64(),"members":member_ids(&group)}))
}

fn encrypt(state: &Path, room: &str, sender: &str, plaintext_b64: &str) -> Result<Value, String> {
    let (provider, signer, mut group) = load_group(state, sender, room)?;
    let plaintext = B64.decode(plaintext_b64).map_err(|e| e.to_string())?;
    let out = group.create_message(&provider, &signer, &plaintext).map_err(|e| format!("create message: {e:?}"))?;
    let wire = out.to_bytes().map_err(|e| format!("serialize message: {e:?}"))?;
    Ok(json!({"ok":true,"epoch":group.epoch().as_u64(),"wire_base64":B64.encode(wire)}))
}

fn decrypt(state: &Path, room: &str, receiver: &str, wire_b64: &str) -> Result<Value, String> {
    let (provider, _signer, mut group) = load_group(state, receiver, room)?;
    let wire = B64.decode(wire_b64).map_err(|e| e.to_string())?;
    let incoming = MlsMessageIn::tls_deserialize_exact(wire).map_err(|e| format!("deserialize message: {e:?}"))?;
    let processed = group.process_message(&provider, incoming.try_into_protocol_message().map_err(|e| format!("protocol message: {e:?}"))?)
        .map_err(|e| format!("process message: {e:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(json!({"ok":true,"epoch":group.epoch().as_u64(),"plaintext_base64":B64.encode(app.into_bytes())})),
        other => Err(format!("expected application message, got {other:?}")),
    }
}

fn group_info(state: &Path, room: &str, device: Option<String>) -> Result<Value, String> {
    let chosen = if let Some(d) = device { d } else {
        let root = state.join("devices");
        let mut found = None;
        if root.exists() {
            for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let id_path = entry.path().join("identity.json");
                if !id_path.exists() { continue; }
                let db_path = entry.path().join("openmls.sqlite");
                let provider = PersistentProvider::open(&db_path)?;
                if let Some(g) = MlsGroup::load(provider.storage(), &group_id(room)).map_err(|e| format!("probe group: {e:?}"))? {
                    found = member_ids(&g).into_iter().next();
                    if found.is_some() { break; }
                }
            }
        }
        found.ok_or_else(|| format!("group {room} not found"))?
    };
    let (_provider, _signer, group) = load_group(state, &chosen, room)?;
    Ok(json!({"ok":true,"epoch":group.epoch().as_u64(),"members":member_ids(&group)}))
}

fn handle(state: &Path, req: Request) -> Result<Value, String> {
    match req {
        Request::Init { group_id, members } => init(state, &group_id, members),
        Request::AddMember { group_id, actor_device_id, new_device_id } => add_member(state, &group_id, &actor_device_id, &new_device_id),
        Request::RemoveMember { group_id, actor_device_id, remove_device_id } => remove_member(state, &group_id, &actor_device_id, &remove_device_id),
        Request::Encrypt { group_id, sender_device_id, plaintext_base64 } => encrypt(state, &group_id, &sender_device_id, &plaintext_base64),
        Request::Decrypt { group_id, receiver_device_id, wire_base64 } => decrypt(state, &group_id, &receiver_device_id, &wire_base64),
        Request::GroupInfo { group_id, device_id } => group_info(state, &group_id, device_id),
    }
}

fn main() {
    let state = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("./openmls-state"));
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) { println!("{}", json!({"ok":false,"error":e.to_string()})); std::process::exit(2); }
    let result = serde_json::from_str::<Request>(&input).map_err(|e| e.to_string()).and_then(|req| handle(&state, req));
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => { println!("{}", json!({"ok":false,"error":error})); std::process::exit(2); }
    }
}
