use reqwest::{Client, StatusCode, header::CONTENT_TYPE};
use serde_json::to_string;
use crate::acme;

pub struct Directory {
    inner: acme::Directory,
    url: String,
}

pub struct Account<'a> {
    inner: acme::Account,
    directory: Directory,
    key: &'a [u8],
    jwk: Jwk,
    url: String,
}

pub struct Order<'a> {
    inner: acme::Order,
    account: &'a Account<'a>,
    url: String,
}

pub struct Authorization<'a> {
    inner: acme::Authorization,
    order: &'a Order<'a>,
    url: String,
    challenge_url: String,
    challenge_token: String,
}

impl Directory {
    pub fn from_url(url: &str) -> Result<Directory> {
        let mut rsp = Client::new().get(url).send()?;
        if rsp.status() == StatusCode::OK {
            Ok(Directory {
                inner: res.json()?,
                url: url.to_owned(),
            })
        } else {
            Err("Not a functional ACMEv2 directory".into())
        }
    }

    fn get_nonce(&self) -> Result<String> {
        let rsp = Client::new().head(&self.inner.newNonce).send()?;
        let string: Result<String> = res.headers()
            .get("Replay-Nonce")
            .ok_or("Replay-Nonce header not found".into())
            .and_then(|nonce| nonce.to_str().map(|s| s.to_string()).map_err(|e| e.into()));
        Ok(string?)
    }

    pub fn register<'a>(self, key: &'a [u8], email: &str) -> Result<Account<'a>> {
        let payload = acme::Account {
            contact: Some(vec![format!("mailto:{}", email)]),
            terms_of_service_agreed: true,
            only_return_existing: None,
        };

        /*
        let jwk = Jwk::from_key(&key)?;
        let jws = Jws::create(
            JwsHeader::Jwk {
                alg: "ES384".to_owned(),
                jwk: jwk.clone(),
                nonce: self.get_nonce()?,
                url: self.inner.newAccount.clone(),
            },
            JwsPayload::NewAccount {
            },
            &key,
        )?;
        */

        let mut rsp = Client::new()
            .post(&self.inner.new_account)
            .json(&signed)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;
        match rsp.status() {
            StatusCode::CREATED | StatusCode::OK => {
                Ok(Account {
                    inner: rsp.json()?,
                    directory: self,
                    key,
                    jwk,
                    url: rsp.headers()
                        .get("Location")
                        .ok_or("account location header not found".into())
                        .and_then(|location| location.to_str().map(|s| s.to_string()).map_err(|e| e.into()))?,
                })
            },
            _ => Err(AcmeErr(res.json()?).into()),
        }
    }
}

/*
impl<'a> Account<'a> {
    pub fn order(&'a self, domains: &[&str]) -> Result<Order<'a>> {
        println!("New order");
        let mut identifiers = Vec::<AcmeIdentifier>::new();
        for domain in domains.iter() {
            identifiers.push(AcmeIdentifier { r#type: "dns".to_owned(), value: domain.to_string(), });
        }
        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.url.to_owned(),
                nonce: self.directory.get_nonce()?.to_owned(),
                url: self.directory.inner.newOrder.clone(),
            },
            JwsPayload::NewOrder {
                identifiers,
                notBefore: None,
                notAfter: None,
            },
            &self.key,
        )?;
        let mut res = Client::new()
            .post(&self.directory.inner.newOrder)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::CREATED {
            let location: Result<String> = res.headers()
                .get("Location")
                .ok_or("order location header not found".into())
                .and_then(|location| location.to_str().map(|s| s.to_string()).map_err(|e| e.into()));
            let url = location?;
            let order: AcmeOrder = res.json()?;
            println!("order: {:?}", &order);
            Ok(Order { inner: order, account: self, url })
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
}

impl<'a> Order<'a> {
    pub fn get_authorizations(&self) -> Result<Vec<Authorization>> {
        println!("get authorizations");
        let mut authorizations = Vec::<Authorization>::new();
        for url in self.inner.authorizations.iter() {
            let jws = Jws::create(
                JwsHeader::Kid {
                    alg: "ES384".to_owned(),
                    kid: self.account.url.to_owned(),
                    nonce: self.account.directory.get_nonce()?.to_owned(),
                    url: url.clone(),
                },
                JwsPayload::None,
                &self.account.key,
            )?;
            let mut res = Client::new()
                .post(url)
                .json(&jws)
                .header(CONTENT_TYPE, "application/jose+json")
                .send()?;

            if res.status() == StatusCode::OK {
                let authz: AcmeAuthorization = res.json()?;
                let mut challenge_url = "".to_owned();
                let mut challenge_token = "".to_owned();
                for chall in authz.challenges.iter() {
                    if chall.r#type == "dns-01".to_owned() {
                        println!("dns challenge: {:?}", &chall);
                        challenge_url = chall.url.clone();
                        challenge_token = chall.token.clone();
                    }
                };
                authorizations.push(Authorization { inner: authz, order: self, url: url.to_owned(), challenge_url, challenge_token });
            } else {
                return Err(AcmeErr(res.json()?).into());
            }
        }
        Ok(authorizations)
    }
    pub fn poll_status(&mut self) -> Result<bool> {
        println!("poll order status");
        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.account.url.to_owned(),
                nonce: self.account.directory.get_nonce()?.to_owned(),
                url: self.url.clone(),
            },
            JwsPayload::None,
            &self.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.url)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let order: AcmeOrder = res.json()?;
            self.inner = order;
            match self.inner.status.as_ref() {
                "pending" => Ok(false),
                "processing" => Ok(false),
                "invalid" => {
                    Err(AcmeErr(res.json()?).into())
                },
                "valid" => Ok(false),
                "ready" => Ok(true),
                _ => Err("Unrecognized order status".into()),
            }
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
    pub fn finalize(&mut self, csr: &[u8]) -> Result<()> {
        println!("finalize");
        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.account.url.to_owned(),
                nonce: self.account.directory.get_nonce()?.to_owned(),
                url: self.inner.finalize.clone(),
            },
            JwsPayload::Finalize {
                csr: base64url(csr),
            },
            &self.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.inner.finalize)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let order: AcmeOrder = res.json()?;
            self.inner = order;
            Ok(())
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
    pub fn get_cert(&self) -> Result<Option<String>> {
        println!("get cert");
        if self.inner.status == "valid".to_owned() {
            if let Some(cert_url) = &self.inner.certificate {
                let jws = Jws::create(
                    JwsHeader::Kid {
                        alg: "ES384".to_owned(),
                        kid: self.account.url.to_owned(),
                        nonce: self.account.directory.get_nonce()?.to_owned(),
                        url: cert_url.clone(),
                    },
                    JwsPayload::None,
                    &self.account.key,
                )?;
                let mut res = Client::new()
                    .post(&cert_url.to_string())
                    .json(&jws)
                    .header(CONTENT_TYPE, "application/jose+json")
                    .send()?;
                if res.status() == StatusCode::OK {
                    let cert = res.text()?;
                    Ok(Some(cert))
                } else {
                    Err("Problem downloading certificate".into())
                }
            } else {
                Err("Order is valid, but there is no certificate url".into())
            }
        } else {
            Ok(None)
        }
    }
}

impl<'a> Authorization<'a> {
    pub fn name(&self) -> String {
        self.inner.identifier.value.clone()
    }
    pub fn key_authorization(&self) -> Result<String> {
        let token = self.challenge_token.to_owned();
        let jwk_thumbprint = base64url(
            ring::digest::digest(&ring::digest::SHA256, &to_string(&self.order.account.jwk.clone())?.as_bytes()).as_ref()
        );
        let key_authorization = format!("{}.{}", token, jwk_thumbprint);
        println!("key_authorization: {:?}", &key_authorization);
        let dns_key_authorization = base64url(
            ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes()).as_ref()
        );
        println!("dns_key_authorization: {:?}", &dns_key_authorization);
        Ok(dns_key_authorization)
    }
    pub fn validate(&self) -> Result<()> {
        println!("validating authorization");

        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.order.account.url.to_owned(),
                nonce: self.order.account.directory.get_nonce()?.to_owned(),
                url: self.challenge_url.clone(),
            },
            JwsPayload::EmptyJSON,
            &self.order.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.challenge_url)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let challenge: AcmeChallenge = res.json()?;
            println!("{:?}", challenge);
            Ok(())
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
    pub fn poll_status(&mut self) -> Result<bool> {
        println!("poll authz status");

        let jws = Jws::create(
            JwsHeader::Kid {
                alg: "ES384".to_owned(),
                kid: self.order.account.url.to_owned(),
                nonce: self.order.account.directory.get_nonce()?.to_owned(),
                url: self.url.clone(),
            },
            JwsPayload::None,
            &self.order.account.key,
        )?;
        let mut res = Client::new()
            .post(&self.url)
            .json(&jws)
            .header(CONTENT_TYPE, "application/jose+json")
            .send()?;

        if res.status() == StatusCode::OK {
            let authz: AcmeAuthorization = res.json()?;
            println!("poll authz response: {:?}", &authz);
            match authz.status.as_ref() {
                "pending" => Ok(false),
                "processing" => Ok(false),
                "invalid" => {
                    Err("Invalid challenge".into())
                },
                "valid" => Ok(true),
                _ => Err("Unrecognized challenge status".into()),
            }
        } else {
            Err(AcmeErr(res.json()?).into())
        }
    }
}
*/

#[derive(Debug)]
struct Error(acme::Error);

impl std::error::Error for Error {}
