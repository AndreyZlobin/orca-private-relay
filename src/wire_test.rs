//! Real HTTP/WebSocket contract check, including PKCE and opaque-frame splicing.
use super::*;
use base64::engine::general_purpose::STANDARD;
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, OsRng},
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};

async fn http(
    addr: std::net::SocketAddr,
    path: &str,
    body: &str,
    token: Option<&str>,
    content_type: &str,
) -> (u16, String, String) {
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let method = if body.is_empty() { "GET" } else { "POST" };
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{auth}\r\n{body}",
        body.len()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    socket.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        head.into(),
        body.into(),
    )
}
async fn post(addr: std::net::SocketAddr, path: &str, v: Value, token: Option<&str>) -> Value {
    let (status, _, body) = http(addr, path, &v.to_string(), token, "application/json").await;
    assert_eq!(status, 200, "{path}: {body}");
    serde_json::from_str(&body).unwrap()
}
type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;
async fn send(socket: &mut Socket, v: Value) {
    socket
        .send(Message::Text(v.to_string().into()))
        .await
        .unwrap();
}
async fn recv(socket: &mut Socket) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(t) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "ping" {
                    send(socket, json!({"type":"pong","t":v["t"]})).await;
                } else {
                    return v;
                }
            }
            Message::Ping(v) => socket.send(Message::Pong(v)).await.unwrap(),
            _ => panic!("expected JSON"),
        }
    }
}

#[tokio::test]
async fn pkce_host_proof_invite_splice_and_durable_resume() {
    tokio::time::timeout(std::time::Duration::from_secs(20),async{
        let s=test_server();let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
        let app=router(s.clone());let task=tokio::spawn(async move{axum::serve(listener,app).await.unwrap()});
        let verifier=random();let nonce=random();let state=random();
        let q=json!({"client_id":"orca-desktop","response_type":"code","redirect_uri":"http://127.0.0.1:43210/auth/callback","nonce":nonce,"state":state,"code_challenge":hash(&verifier),"code_challenge_method":"S256","local_profile_id":"profile-test"});
        let mut form=url::form_urlencoded::Serializer::new(String::new());form.append_pair("password","owner");form.append_pair("request",&URL_SAFE_NO_PAD.encode(q.to_string()));
        let (status,headers,_)=http(addr,"/v1/desktop/auth/authorize",&form.finish(),None,"application/x-www-form-urlencoded").await;assert_eq!(status,303);
        let location=headers.lines().find_map(|line|line.strip_prefix("location: ")).unwrap();let u=url::Url::parse(location.trim()).unwrap();let code=u.query_pairs().find(|(k,_)|k=="code").unwrap().1.to_string();
        let exchange=json!({"code":code,"codeVerifier":verifier,"nonce":nonce,"state":state,"redirectUri":q["redirect_uri"],"localProfileId":"profile-test"});
        let session=post(addr,"/v1/desktop/auth/session",exchange.clone(),None).await;
        let (status,_,_)=http(addr,"/v1/desktop/auth/session",&exchange.to_string(),None,"application/json").await;assert_eq!(status,401,"code replay must fail");
        let access=session["accessToken"].as_str().unwrap();
        let host_secret=SecretKey::generate(&mut OsRng);let public=host_secret.public_key();let host=hash(public.as_bytes())[..16].to_string();
        let token=post(addr,"/v1/desktop/auth/relay-token",json!({"relayHostId":host,"hostPublicKeyB64":STANDARD.encode(public.as_bytes())}),Some(access)).await;
        let token=token["relayToken"].as_str().unwrap();
        let assignment=post(addr,"/v1/assign",json!({"v":1,"relayHostId":host}),Some(token)).await;
        let base=format!("ws://{addr}");let mut request=format!("{base}/v1/host/control").into_client_request().unwrap();request.headers_mut().insert("authorization",format!("Bearer {token}").parse().unwrap());
        let(mut control,_)=connect_async(request).await.unwrap();
        send(&mut control,json!({"type":"host-hello","v":1,"relayHostId":host,"hostPublicKeyB64":STANDARD.encode(public.as_bytes()),"assignmentEpoch":assignment["assignmentEpoch"],"appVersion":"1.4.245"})).await;
        let challenge=recv(&mut control).await;assert_eq!(challenge["type"],"host-challenge");
        let peer:[u8;32]=STANDARD.decode(challenge["relayEphemeralPublicKeyB64"].as_str().unwrap()).unwrap().try_into().unwrap();let nonce=STANDARD.decode(challenge["nonceB64"].as_str().unwrap()).unwrap();
        let plain=SalsaBox::new(&PublicKey::from(peer),&host_secret).decrypt(nonce.as_slice().into(),STANDARD.decode(challenge["ciphertextB64"].as_str().unwrap()).unwrap().as_slice()).unwrap();
        let start=b"orca-relay-host-challenge/v1\0".len()+4;let transcript=&plain[start..plain.len()-32];let secret=&plain[plain.len()-32..];let mut mac=<Hmac<Sha256>as Mac>::new_from_slice(secret).unwrap();mac.update(b"orca-relay-host-proof/v1\0ack\0");mac.update(transcript);
        send(&mut control,json!({"type":"host-challenge-ack","challengeId":challenge["challengeId"],"proofB64":STANDARD.encode(mac.finalize().into_bytes())})).await;
        let ack=recv(&mut control).await;assert_eq!(ack["type"],"host-hello-ack");let generation=ack["generation"].as_u64().unwrap();
        send(&mut control,json!({"type":"invite-create","reqId":"invite-1","relayDeviceId":"phone-1"})).await;
        let invite=recv(&mut control).await;assert_eq!(invite["type"],"invite-created");
        let(mut phone,_)=connect_async(format!("{base}/v1/connect/{host}")).await.unwrap();send(&mut phone,json!({"type":"relay-auth","v":1,"mode":"connect","credential":invite["inviteToken"]})).await;
        let open=recv(&mut control).await;assert_eq!(open["type"],"conn-open");let(mut data,_)=connect_async(format!("{base}/v1/host/data/{}",open["connId"].as_str().unwrap())).await.unwrap();
        send(&mut data,json!({"type":"host-data-auth","v":1,"connTicket":open["connTicket"],"generation":generation})).await;assert_eq!(recv(&mut phone).await["credentialKind"],"invite");
        let bytes=vec![7u8;65536];phone.send(Message::Binary(bytes.clone().into())).await.unwrap();assert_eq!(data.next().await.unwrap().unwrap().into_data(),bytes);data.send(Message::Binary(vec![9,8,7].into())).await.unwrap();assert_eq!(phone.next().await.unwrap().unwrap().into_data(),vec![9,8,7]);
        let resume=random();send(&mut control,json!({"type":"device-credential-install","v":1,"reqId":"install-1","relayDeviceId":"phone-1","newResumeTokenHash":hash(&resume),"authorization":{"mode":"relay-basis","basisConnId":open["connId"]}})).await;assert_eq!(recv(&mut control).await["currentVersion"],1);
        phone.close(None).await.unwrap();drop(data);
        let(mut phone2,_)=connect_async(format!("{base}/v1/connect/{host}")).await.unwrap();send(&mut phone2,json!({"type":"relay-auth","v":1,"mode":"connect","credential":resume})).await;
        let open=recv(&mut control).await;assert_eq!(open["kind"],"resume");let(mut data2,_)=connect_async(format!("{base}/v1/host/data/{}",open["connId"].as_str().unwrap())).await.unwrap();send(&mut data2,json!({"type":"host-data-auth","v":1,"connTicket":open["connTicket"],"generation":generation})).await;
        assert_eq!(recv(&mut phone2).await["credentialKind"],"resume");send(&mut control,json!({"type":"device-resume-confirm","v":1,"reqId":"confirm-1","basisConnId":open["connId"]})).await;assert_eq!(recv(&mut control).await["renewed"],true);
        drop((phone2,data2,control));task.abort();
    }).await.unwrap();
}
