use std::thread;
use std::time::Duration;

use actix_web::middleware::Logger;
use actix_web::{
    delete, error, get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use humantime::parse_duration;
use log::{error, info};

mod pgp;
mod store;
use sequoia_openpgp::parse::Parse;

#[derive(std::clone::Clone)]
struct Context {
    pgp: pgp::Verificator,
    store: store::Store,
}

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    let mut host = "$YOUR_SERVER_HOST";
    if let Some(h) = req.headers().get("host") {
        if let Ok(h) = h.to_str() {
            host = h
        }
    }
    format!("upload:   $ gpg -s </path/to/file | curl http://{0}/file-name --data-binary @-\ndownload: $ curl http://{0}/file-name\ndelete:   $ curl -XDELETE http://{0}/file-name\n", host)
}

#[get("/{key:.*}")]
async fn get_file(web::Path(key): web::Path<String>, ctx: web::Data<Context>) -> impl Responder {
    if let Ok(body) = ctx.store.open(&key) {
        Ok(body
            .set_content_type("application/pgp".parse::<mime::Mime>().unwrap())
            .disable_content_disposition())
    } else {
        Err(error::ErrorNotFound("no such file\n"))
    }
}

#[post("/{key:.*}")]
async fn post_file(
    body: web::Bytes,
    web::Path(key): web::Path<String>,
    ctx: web::Data<Context>,
) -> impl Responder {
    if let Err(_) = ctx.pgp.verify_bytes(&body) {
        Err(error::ErrorUnauthorized(
            "request body must signed by registered key\n",
        ))
    } else if let Err(err) = ctx.store.save(&key, &body) {
        error!("failed to store file: {}", err);
        Err(error::ErrorInternalServerError("failed to store file\n"))
    } else {
        Ok(HttpResponse::NoContent().body(""))
    }
}

#[delete("/{key:.*}")]
async fn delete_file(web::Path(key): web::Path<String>, ctx: web::Data<Context>) -> impl Responder {
    if let Err(_) = ctx.store.delete(&key) {
        Err(error::ErrorUnauthorized("no such file\n"))
    } else {
        Ok(HttpResponse::NoContent().body(""))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    let args = clap::App::new("signed-store")
        .about("OpenPGP signed file uploader")
        .arg(
            clap::Arg::with_name("KEY_FILE")
                .help("Public keys file for validate uploaded file")
                .required(true)
                .index(1),
        )
        .arg(
            clap::Arg::with_name("STORE_PATH")
                .help("Path to the directory for save files into")
                .required(true)
                .index(2),
        )
        .arg(
            clap::Arg::with_name("listen")
                .short("l")
                .long("listen")
                .value_name("ADDRESS")
                .default_value("localhost:3000")
                .help("Listen address")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("ttl")
                .short("t")
                .long("ttl")
                .value_name("DURATION")
                .default_value("1d")
                .help("Duration to expires file from last access")
                .takes_value(true),
        )
        .get_matches();

    let listen = args.value_of("listen").unwrap();
    info!("listen on: {}", listen);

    let verificator = pgp::Verificator::from_file(args.value_of("KEY_FILE").unwrap())
        .expect("failed to read keys");
    info!("accept keys:");
    for cert in &verificator.certs() {
        info!("  key: {}", cert.fingerprint());
        for ua in cert.userids() {
            info!("    User ID: {}", ua.userid());
        }
    }

    let ttl = args.value_of("ttl").unwrap();
    info!("files ttl: {}", ttl);

    let store = store::Store::new(
        args.value_of("STORE_PATH").unwrap(),
        parse_duration(ttl).unwrap(),
    )
    .expect("failed to open store");

    let ctx = Context {
        pgp: verificator,
        store: store.clone(),
    };

    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(60 * 60));
        match store.prune() {
            Ok(0) => info!("there is no expired file"),
            Ok(removed) => info!("prune {} file(s)", removed),
            Err(err) => error!("failed to prune: {}", err),
        }
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .data(ctx.clone())
            .service(index)
            .service(get_file)
            .service(post_file)
            .service(delete_file)
    })
    .bind(listen)?
    .run()
    .await
}
