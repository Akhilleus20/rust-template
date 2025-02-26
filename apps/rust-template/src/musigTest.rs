use serde_json::Value;
use serde_json::json;

use musig2::secp256k1::{Secp256k1,PublicKey,SecretKey};
use musig2::{KeyAggContext,FirstRound, SecNonceSpices};
//use musig2::{MuSig2, KeyPair, PublicKey, Signature};
//use rand::rngs::OsRng;

#[cfg(test)]
mod tests {
    use klave::crypto::subtle::{EcKeyGenParams, GenAlgorithm};
    use klave;
    use musig2::{secp256k1::Secp256k1, CompactSignature, PartialSignature, PubNonce, SecNonce, SecondRound};

    use super::*;

    #[test]
    fn test_verify_transaction_root() {
        //create a Secp256k1 context
        //let secp = Secp256k1::new();

        //First step: share all public keys
        let pubkeys = [
            "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap(),
            "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
            .parse::<PublicKey>()
            .unwrap(),
            "03204ea8bc3425b2cbc9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
            .parse::<PublicKey>()
            .unwrap(),
        ];

        let signer_index = 2;
        let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
            .parse()
            .unwrap();

        let mut key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();


        // This is the key which the group has control over.
        let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
        assert_eq!(
            aggregated_pubkey,
            "02e272de44ea720667aba55341a1a761c0fc8fbe294aa31dbaf1cff80f1c2fd940"
                .parse()
                .unwrap()
        );

        //Second step: do the first round
        // The group wants to sign something!
        let message = "hello interwebz!";

        // Normally this should be sampled securely from a CSPRNG.
        // let mut nonce_seed = [0u8; 32]
        // rand::rngs::OsRng.fill_bytes(&mut nonce_seed);
        let nonce_seed = [0xACu8; 32];

        let mut first_round = FirstRound::new(
            key_agg_ctx,
            nonce_seed,
            signer_index,
            SecNonceSpices::new()
                .with_seckey(seckey)
                .with_message(&message),
        )
        .unwrap();

        // We would share our public nonce with our peers.
        assert_eq!(
            first_round.our_public_nonce(),
            "02d1e90616ea78a612dddfe97de7b5e7e1ceef6e64b7bc23b922eae30fa2475cca\
            02e676a3af322965d53cc128597897ef4f84a8d8080b456e27836db70e5343a2bb"
                .parse()
                .unwrap(),
            "Our public nonce should match"
        );

        // We can see a list of which signers (by index) have yet to provide us
        // with a nonce.
        assert_eq!(first_round.holdouts(), &[0, 1]);

        // We receive the public nonces from our peers one at a time.
        first_round.receive_nonce(
            0,
            "02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
            0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45"
                .parse::<PubNonce>()
                .unwrap()
        )
        .unwrap();

        // `is_complete` provides a quick check to see whether we have nonces from
        // every signer yet.
        assert!(!first_round.is_complete());

        // ...once we receive all their nonces...
        first_round.receive_nonce(
            1,
            "020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
            03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d"
                .parse::<PubNonce>()
                .unwrap()
        )
        .unwrap();

        // ... the round will be complete.
        assert!(first_round.is_complete());

        let mut second_round: SecondRound<&str> = first_round.finalize(seckey, message).unwrap();

        // We could now send our partial signature to our peers.
        // Be careful not to send your signature first if your peers
        // might run away without surrendering their signatures in exchange!
        let our_partial_signature: PartialSignature = second_round.our_signature();
        assert_eq!(
            our_partial_signature,
            "efd62850b959a76a462f1e42eb3cecc77a5a0982742fff2901456b7d1453a817"
                .parse()
                .unwrap()
        );

        second_round.receive_signature(
            0,
            "5a476e0126583e9e0ceebb01a34bdd342c72eab92efbe8a1c7f07e793fd88f96"
                .parse::<PartialSignature>()
                .unwrap()
        )
        .expect("signer 0's partial signature should be valid");

        // Same methods as on FirstRound are available for SecondRound.
        assert!(!second_round.is_complete());
        assert_eq!(second_round.holdouts(), &[1]);

        // Receive a partial signature from one of our cosigners. This
        // automatically verifies the partial signature and returns an
        // error if the signature is invalid.
        second_round.receive_signature(
            1,
            "45ac8a698fc9e82408367e28a2d257edf6fc49f14dcc8a98c43e9693e7265e7e"
                .parse::<PartialSignature>()
                .unwrap()
        )
        .expect("signer 1's partial signature should be valid");

        assert!(second_round.is_complete());

        // If all signatures were received successfully, finalizing the second round
        // should succeed with overwhelming probability.
        let final_signature: CompactSignature = second_round.finalize().unwrap();

        assert_eq!(
            final_signature.to_string(),
            "38fbd82d1d27bb3401042062acfd4e7f54ce93ddf26a4ae87cf71568c1d4e8bb\
            8fca20bb6f7bce2c5b54576d315b21eae31a614641afd227cda221fd6b1c54ea"
        );

        musig2::verify_single(
            aggregated_pubkey,
            final_signature,
            message
        )
        .expect("aggregated signature must be valid");
    }

    #[test]
    fn test_create_ecc_key() {
        //create ECC key
        let ec_params = EcKeyGenParams {
            namedCurve: "secp256k1".to_string()
        };
        let algo = GenAlgorithm::EcKeyGenParams(ec_params);
        let user_key = klave::crypto::subtle::generate_key(&algo, true, &["sign","verify"]).unwrap();
        let buffer = klave::crypto::subtle::export_key("raw", &user_key).unwrap();
        let s = String::from_utf8(buffer).expect("Found invalid UTF-8");
        assert_eq!(s,"");
    }
}
