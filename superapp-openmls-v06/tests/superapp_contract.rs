use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{signatures::Signer, types::SignatureScheme, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};

fn credential(
    identity: &[u8],
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity.to_vec());
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.storage()).unwrap();
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

fn key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    provider: &impl OpenMlsProvider,
    signer: &impl Signer,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}

fn decode_message(message: MlsMessageOut) -> MlsMessageIn {
    let bytes = message.to_bytes().expect("MLS message must serialize");
    MlsMessageIn::tls_deserialize_exact(bytes).expect("MLS message must deserialize")
}

fn decode_welcome(message: MlsMessageOut) -> Welcome {
    match decode_message(message).extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        other => panic!("expected welcome message, got {other:?}"),
    }
}

fn join_from_welcome(
    provider: &impl OpenMlsProvider,
    welcome: Welcome,
) -> MlsGroup {
    let config = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
    StagedWelcome::new_from_welcome(provider, &config, welcome, None)
        .unwrap()
        .into_group(provider)
        .unwrap()
}

fn process_application(
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
    message: MlsMessageOut,
) -> Vec<u8> {
    let protocol = decode_message(message)
        .try_into_protocol_message()
        .expect("application message must be protocol message");
    let processed = group
        .process_message(provider, protocol)
        .expect("message should decrypt");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => app.into_bytes(),
        other => panic!("expected application message, got {other:?}"),
    }
}

#[test]
fn superapp_group_epoch_contract() {
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let charlie_provider = OpenMlsRustCrypto::default();

    let (alice_cred, alice_signer) = credential(b"alice", suite.signature_algorithm(), &alice_provider);
    let (bob_cred, bob_signer) = credential(b"bob", suite.signature_algorithm(), &bob_provider);
    let (charlie_cred, charlie_signer) = credential(b"charlie", suite.signature_algorithm(), &charlie_provider);

    let bob_kp = key_package(suite, bob_cred.clone(), &bob_provider, &bob_signer);
    let charlie_kp = key_package(suite, charlie_cred.clone(), &charlie_provider, &charlie_signer);

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice = MlsGroup::new(&alice_provider, &alice_signer, &config, alice_cred).unwrap();
    let epoch0 = alice.epoch();

    let (_commit_add_bob, welcome_bob, _) = alice
        .add_members(&alice_provider, &alice_signer, &[bob_kp.key_package().clone()])
        .unwrap();
    alice.merge_pending_commit(&alice_provider).unwrap();
    assert!(alice.epoch() > epoch0);
    let mut bob = join_from_welcome(&bob_provider, decode_welcome(welcome_bob));

    let m1 = alice
        .create_message(&alice_provider, &alice_signer, b"epoch-one")
        .unwrap();
    assert_eq!(process_application(&mut bob, &bob_provider, m1), b"epoch-one");

    let bob_member = alice
        .members()
        .find(|member| member.credential.serialized_content() == b"bob")
        .expect("Bob must be a member");
    let (remove_bob, _, _) = alice
        .remove_members(&alice_provider, &alice_signer, &[bob_member.index])
        .unwrap();
    alice.merge_pending_commit(&alice_provider).unwrap();

    let processed_remove = bob
        .process_message(
            &bob_provider,
            decode_message(remove_bob).try_into_protocol_message().unwrap(),
        )
        .unwrap();
    match processed_remove.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            assert!(staged.self_removed());
            bob.merge_staged_commit(&bob_provider, *staged).unwrap();
        }
        _ => panic!("expected removal commit"),
    }

    let future_for_members = alice
        .create_message(&alice_provider, &alice_signer, b"after-bob-removal")
        .unwrap();
    let future_protocol = decode_message(future_for_members)
        .try_into_protocol_message()
        .unwrap();
    assert!(
        bob.process_message(&bob_provider, future_protocol).is_err(),
        "removed member must not decrypt future application data"
    );

    let before_charlie = alice
        .create_message(&alice_provider, &alice_signer, b"before-charlie")
        .unwrap();
    let before_charlie_bytes = before_charlie.to_bytes().unwrap();
    let (_commit_add_charlie, welcome_charlie, _) = alice
        .add_members(&alice_provider, &alice_signer, &[charlie_kp.key_package().clone()])
        .unwrap();
    alice.merge_pending_commit(&alice_provider).unwrap();
    let mut charlie = join_from_welcome(&charlie_provider, decode_welcome(welcome_charlie));

    let old_in = MlsMessageIn::tls_deserialize_exact(before_charlie_bytes).unwrap();
    let old_protocol = old_in.try_into_protocol_message().unwrap();
    assert!(
        charlie.process_message(&charlie_provider, old_protocol).is_err(),
        "new member must not decrypt pre-join application data"
    );

    let current = alice
        .create_message(&alice_provider, &alice_signer, b"after-charlie")
        .unwrap();
    assert_eq!(
        process_application(&mut charlie, &charlie_provider, current),
        b"after-charlie"
    );
}
