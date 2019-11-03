use std::cell::RefCell;
use std::ops::Add;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, SystemTime};

use hashbrown::hash_map::rayon::*;
use hashbrown::HashMap;
use rayon::prelude::*;
use serde::*;
use sodiumoxide::crypto::box_::*;
use tokio::prelude::*;

type DecodePair = (Option<String>, Option<String>);

struct UserRecord {
    time: RwLock<SystemTime>,
    pubkey: Arc<PublicKey>,
    nonce: RwLock<Nonce>,
    name: Arc<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UserJson {
    last_active: SystemTime,
    pubkey: String,
    name: String,
}

impl From<&UserRecord> for UserJson {
    fn from(r: &UserRecord) -> Self {
        UserJson {
            last_active: r.time.read().expect("unable to read data").clone(),
            pubkey: base64::encode(&r.pubkey.0),
            name: r.name.as_ref().clone(),
        }
    }
}

impl PartialEq for UserRecord {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl Eq for UserRecord {}

#[derive(Clone, StateData)]
pub struct GlobalState {
    data: Arc<RwLock<HashMap<String, Arc<UserRecord>>>>,
    thread_flag: Arc<AtomicBool>,
    public_key: Arc<PublicKey>,
    secret_key: Arc<SecretKey>,
}

impl UserRecord {
    fn update(&self) -> String {
        let mut nonce = self.nonce.write().expect("unable to lock nonce");
        let mut time = self.time.write().expect("unable to lock time");
        *time = SystemTime::now();
        *nonce = gen_nonce();
        base64::encode(&nonce.0)
    }
}

impl Drop for GlobalState {
    fn drop(&mut self) {
        self.thread_flag.store(true, SeqCst);
    }
}

impl GlobalState {
    pub fn public_key(&self) -> &PublicKey {
        self.public_key.as_ref()
    }

    pub fn secret_key(&self) -> &SecretKey {
        self.secret_key.as_ref()
    }


    pub fn new() -> Self {
        let keys = gen_keypair();
        let res = GlobalState {
            data: Arc::new(RwLock::new(HashMap::new())),
            thread_flag: Arc::new(AtomicBool::new(false)),
            public_key: Arc::new(keys.0),
            secret_key: Arc::new(keys.1),
        };
        {
            let ptr = res.clone();
            let flag = res.thread_flag.clone();
            let thd = std::thread::Builder::new()
                .name(String::from("global watcher"))
                .stack_size(1024 * 75)
                .spawn(move || {
                    loop {
                        if flag.load(Relaxed) {
                            break;
                        } else {
                            println!("cleaning up");
                            ptr.clean_up();
                            std::thread::sleep(Duration::from_secs(30));
                        }
                    }
                }).expect("unable to spawn watching thread");
        }
        res
    }

    pub fn update(&self, name: &String) -> Option<String> {
        let mut reader = self.data.write().expect("unable to read data");
        if let Some(user) = reader.get_mut(name) {
            Some(user.update())
        } else {
            None
        }
    }

    pub fn check(&self, name: &String) -> bool {
        let reader = self.data.read().unwrap();
        reader.contains_key(name)
    }

    pub fn get_list(&self) -> Vec<UserJson> {
        self.data.read().unwrap().par_values().map(|x| UserJson::from(x.as_ref())).collect()
    }

    pub fn clean_up(&self) {
        let mut writer = self.data.write().unwrap();
        let threshold = Duration::from_secs(60 * 15);
        let now = SystemTime::now();
        let todo: Vec<Arc<String>> = writer
            .par_values()
            .filter(|x| {
                x.time.read().unwrap().add(threshold) < now
            })
            .map(|x| x.name.clone())
            .collect();
        for i in todo {
            writer.remove(i.as_ref());
        }
    }

    pub fn add_user(&self, name: &String, key: &String) -> Result<String, String> {
        base64::decode(&key).map_err(|x| x.to_string()).and_then(|x| {
            PublicKey::from_slice(x.as_slice()).ok_or("cannot convert key".to_string())
        }).and_then(|x| {
            if self.check(name) {
                Err("name exsits".to_string())
            } else {
                let nonce = gen_nonce();
                let encoded = base64::encode(&nonce.0);
                let user = UserRecord {
                    time: RwLock::new(SystemTime::now()),
                    pubkey: Arc::new(x),
                    nonce: RwLock::new(nonce),
                    name: Arc::new(name.clone()),
                };
                self.data.write().unwrap().insert(name.clone(), Arc::new(user));
                Ok(encoded)
            }
        })
    }

    pub fn decode(&self, name: &String, msg: &String) -> DecodePair {
        let t = {
            let reader = self.data.read().unwrap();
            reader.get(name).cloned()
        };
        let decoded = if let Some(user) = t {
            let text = open(msg.as_bytes(),
                            &user.nonce.read().unwrap(),
                            user.pubkey.as_ref(),
                            &self.secret_key);
            match text {
                Ok(data) =>
                    match String::from_utf8(data) {
                        Ok(m) => Some(m),
                        Err(_) => None
                    }
                Err(_) => None
            }
        } else { None };
        let nonce = if decoded.is_some() { self.update(name) } else { None };
        (decoded, nonce)
    }
}