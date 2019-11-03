use std::sync::{Arc, Mutex};

use cookie::SameSite;
use futures::{future, Future, Stream};
use futures::prelude::*;
use gotham::handler::{HandlerFuture, IntoHandlerError};
use gotham::helpers::http::response::{create_empty_response, create_response};
use gotham::middleware::state::StateMiddleware;
use gotham::pipeline::{new_pipeline, single_middleware};
use gotham::pipeline::single::single_pipeline;
use gotham::router::builder::*;
use gotham::router::Router;
use gotham::state::{FromState, State};
use hyper::{Body, Response, StatusCode};
use mime::Mime;
use rayon::prelude::*;
use serde::*;
use serde_json;
use simd_json;

use crate::state::GlobalState;

fn get_list(state: State) -> (State, Response<Body>) {
    let message = {
        // borrow a reference of the global from the state
        let global = GlobalState::borrow_from(&state);

        // create our message, incrementing our request global
        let list = global.get_list();
        serde_json::to_string(&list).unwrap()
    };
    let mut res = create_response(&state, StatusCode::OK, mime::APPLICATION_JSON, message);
    // return message
    (state, res)
}

fn pub_key(state: State) -> (State, Response<Body>) {
    let message = {
        // borrow a reference of the global from the state
        let global = GlobalState::borrow_from(&state);

        // create our message, incrementing our request global

        format!(
            "{{\"public_key\": \"{}\"}}", base64::encode(&global.public_key().0)
        )
    };
    let mut res = create_response(&state, StatusCode::OK, mime::APPLICATION_JSON, message);
    (state, res)
}


#[derive(Serialize, Deserialize, Debug)]
struct HandshakeReq {
    name: String,
    key: String,
}

#[derive(Serialize)]
pub struct HandshakeResult {
    success: bool,
    err: String,
    nonce: Option<String>,
}

fn handshake(mut state: State) -> Box<HandlerFuture> {
    let global = GlobalState::borrow_from(&state).clone();
    let f = Body::take_from(&mut state)
        .concat2()
        .then(move |full_body| match full_body {
            Ok(valid_body) => {
                let body_content = String::from_utf8(valid_body.to_vec())
                    .map_err(|x| x.to_string())
                    .and_then(|mut x|
                        simd_json::serde::from_str::<HandshakeReq>(x.as_mut_str())
                            .map_err(|x| x.to_string()));

                match body_content {
                    Ok(req) => {
                        let nonce = global.add_user(&req.name, &req.key);
                        let result = match nonce {
                            Ok(nonce) =>
                                HandshakeResult {
                                    success: true,
                                    err: String::new(),
                                    nonce: Some(nonce),
                                },
                            Err(err) => HandshakeResult {
                                success: false,
                                err,
                                nonce: None,
                            }
                        };
                        let json = serde_json::to_string(&result).unwrap();
                        let res =
                            create_response(&state, StatusCode::BAD_REQUEST, mime::APPLICATION_JSON, json);
                        future::ok((state, res))
                    }
                    Err(err) => {
                        let result = HandshakeResult {
                            success: false,
                            err,
                            nonce: None,
                        };
                        let json = serde_json::to_string(&result).unwrap();
                        let res =
                            create_response(&state, StatusCode::BAD_REQUEST, mime::APPLICATION_JSON, json);
                        future::ok((state, res))
                    }
                }
            }
            Err(e) => future::err((state, e.into_handler_error())),
        });

    Box::new(f)
}


pub fn ignite() -> Router {
    // create the global to share across handlers
    let users: GlobalState = GlobalState::new();

    // create our state middleware to share the global
    let middleware = StateMiddleware::new(users);

    // create a middleware pipeline from our middleware
    let pipeline = single_middleware(middleware);

    // construct a basic chain from our pipeline
    let (chain, pipelines) = single_pipeline(pipeline);

    // build a router with the chain & pipeline
    build_router(chain, pipelines, |route| {
        route.get("/list").to(get_list);
        route.get("/public-key").to(pub_key);
        route.post("/handshake").to(handshake)
    })
}