#[macro_use] extern crate bbs;
use bbs::prelude::*;
use std::collections::BTreeMap;

fn main() {
    let (dpk, sk) = Issuer::new_short_keys(None);
    let pk = dpk.to_public_key(5).unwrap();
    let signing_nonce = Issuer::generate_signing_nonce();

// Send `signing_nonce` to holder

// Recipient wants to hide a message in each signature to be able to link
// them together
    let link_secret = Prover::new_link_secret();
    let mut messages = BTreeMap::new();
    messages.insert(0, link_secret.clone());
    let (ctx, signature_blinding) =
        Prover::new_blind_signature_context(&pk, &messages, &signing_nonce).unwrap();

// Send `ctx` to signer
    let messages = sm_map![
    1 => b"Will",
    2 => b"Some Skill",
    3 => b"message_3",
    4 => b"message_4"
];

// Will fail if `ctx` is invalid
    let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();

// Send `blind_signature` to recipient
// Recipient knows all `messages` that are signed
    let mut msgs = messages
        .iter()
        .map(|(_, m)| m.clone())
        .collect::<Vec<SignatureMessage>>();
    msgs.insert(0, link_secret.clone());




    let res =
        Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding);
    assert!(res.is_ok());
    println!("RES {:?}", res);
    let signature = res.unwrap();


//    let cred = (signature, msgs);

    // Proving stage.

    let nonce = Verifier::generate_proof_nonce();
    let proof_request = Verifier::new_proof_request(&[1, 2], &pk).unwrap();


    let data_to_sign: &[u8] = b"I am signing this statment";


    let link_hidden = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
        link_secret.clone(),
        nonce.clone(),
    ));

//    let link_hidden_2 = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
//        link_secret,
//        nonce,
//    ));
//
//    println!("Link 1 {:?} \n Link 2 {:?}", &link_hidden.get_message(), &link_hidden_2.get_message());



// Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![
        link_hidden,
        pm_revealed!(b"Will"),
        pm_revealed!(b"Some Skill"),
        pm_hidden!(b"message_3"),
        pm_hidden!(b"message_4"),
    ];

    let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
        .unwrap();


// complete other zkps as desired and compute `challenge_hash`
// add bytes from other proofs

    let data_to_sign: &[u8] = b"I am signing this statment";

//    let bytes = Vec::from(data_to_sign);

    let claims: &[&[u8]] = &vec!(data_to_sign);



//    let mut challenge_bytes = Vec::new();
//    challenge_bytes.extend_from_slice(pok.to_bytes().as_slice());
//    challenge_bytes.extend_from_slice(&nonce.to_bytes_compressed_form()[..]);
//    challenge_bytes.extend_from_slice(data_to_sign);

//    let challenge = ProofChallenge::hash(&challenge_bytes);

    let option_claim = Some(claims);
    let challenge = Prover::create_challenge_hash(&[pok.clone()], option_claim, &nonce).unwrap();

    let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();
    println!("Proof {:?}", proof);




// Send `proof` and `challenge` to Verifier



    match verify_signature_claim_pok(&proof_request, &proof, data_to_sign, &nonce) {
        Ok(sig_messages) => {
            println!("Signature {:?}", sig_messages);
            println!("Signature reveal {:?}", proof.revealed_messages)
        },   // check revealed messages
        Err(_) => assert!(false), // Why did the proof failed
    };
}

pub fn verify_signature_claim_pok(
    proof_request: &ProofRequest,
    signature_proof: &SignatureProof,
    claim: &[u8],
    nonce: &ProofNonce,
) -> Result<Vec<SignatureMessage>, BBSError> {
    let mut challenge_bytes = signature_proof.proof.get_bytes_for_challenge(
        proof_request.revealed_messages.clone(),
        &proof_request.verification_key,
    );
    challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
    challenge_bytes.extend_from_slice(claim);

    let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
    match signature_proof.proof.verify(
        &proof_request.verification_key,
        &signature_proof.revealed_messages,
        &challenge_verifier,
    )? {
        PoKOfSignatureProofStatus::Success => Ok(signature_proof
            .revealed_messages
            .iter()
            .map(|(_, m)| *m)
            .collect::<Vec<SignatureMessage>>()),
        e => Err(BBSErrorKind::InvalidProof { status: e }.into()),
    }
}
