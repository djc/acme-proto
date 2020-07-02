use serde::{Deserialize, Serialize};
use serde_json::to_string;

struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl Jws {
fn new<K, P>(key: K, nonce: &[u8], url: &str, payload: P, inline_key: bool) -> Result<String> where K: Key, P: Serialize {
    let header = Header {
        alg: key.alg(),
        key_data: if inline_key {
            KeyData::Named(key.id())
        } else {
            KeyData::Inline(key.public_key())
        },
        nonce,
        url,
    };

    let protected = base64url(&serde_json::to_vec(header));
    let payload = base64url(&serde_json::to_vec(header));
    let message = format!("{}.{}", protected, payload);
    let signature = key.sign(message.as_bytes());
    Ok(Self {
        protected,
        payload,
        signature,
    })
}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Jwk {
    Curve {
        pub crv: String, // P-384
        pub kty: String, // EC
        pub x: String, // base64url(x)
        pub y: String, // base64url(y)
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Header<'a> {
    alg: &'a str,
    #[serde(flatten)]
    key_data: KeyData<'a>,
    nonce: &'a [u8],
    url: &str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum KeyData<'a> {
    Named(&'a str),
    Inline(Jwk),
}

trait Key {
    fn alg(&self) -> &'static str;
    fn id(&self) -> Option<&str>;
    fn public_key(&self) -> Jwk;
    fn sign(msg: &[u8]) -> Result<Vec<u8>, Error>;
}

struct Ecdsa {
    fn new(key_pair: EcdsaKeyPair, 
}

impl Key for EcdsaKeyPair

impl Jwk {
    pub fn from_key(ring_ecdsa_p384_keypair: &[u8]) -> Result<Jwk> {
        let mut k = ring_ecdsa_p384_keypair.to_vec();
        if k.len() < 96 { return Err("Jwk: Congratulation. Key is horribly malformed".into()); }
        let mut y = k.split_off(k.len() - 48);
        let mut x = k.split_off(k.len() - 48);
        while x[0] == 0 { x.remove(0); }
        while y[0] == 0 { y.remove(0); }

        Ok(Jwk::Curve {
            crv: "P-384".to_owned(),
            kty: "EC".to_owned(),
            x: base64url(&x),
            y: base64url(&y),
        })
    }
}



impl Jws {
    fn create(h: JwsHeader, p: JwsPayload, key: &[u8]) -> Result<Jws> {
        let protected = base64url(&to_string(&h)?.into_bytes());
        let payload = match p {
            JwsPayload::None => "".to_owned(),
            _ => base64url(&to_string(&p)?.into_bytes()),
        };
        let signature = {
            let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                untrusted::Input::from(key)
            )?;
            let content = &format!("{}.{}", protected, payload).into_bytes();
            let rng = ring::rand::SystemRandom::new();
            let sig = key_pair.sign(&rng, untrusted::Input::from(&content))?;

            base64url(sig.as_ref())
        };

        Ok(Jws { protected, payload, signature })
    }
}

pub fn base64url(bytes: &[u8]) -> String {
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}
