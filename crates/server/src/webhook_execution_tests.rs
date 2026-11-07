#[cfg(all(test, feature="redis-cache", not(target_arch="wasm32")))]
mod webhook_execution_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RevocationCache { url:String, stop:Arc<AtomicBool>, thread:Option<std::thread::JoinHandle<()>> }
    impl RevocationCache {
        fn start(hash:String)->Self {
            let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let url=format!("redis://{}",listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap(); let stop=Arc::new(AtomicBool::new(false)); let done=stop.clone();
            let thread=std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    let (stream,_)=match listener.accept(){Ok(v)=>v,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(std::time::Duration::from_millis(5));continue;},Err(e)=>panic!("Redis accept: {e}")};
                    stream.set_read_timeout(Some(std::time::Duration::from_millis(100))).unwrap(); let mut reader=BufReader::new(stream);
                    while !done.load(Ordering::SeqCst) {
                        let mut line=String::new();
                        match reader.read_line(&mut line){Ok(0)=>break,Ok(_)=>(),Err(e) if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut)=>continue,Err(e)=>panic!("Redis read: {e}")}
                        let count:usize=line.strip_prefix('*').expect("RESP array").trim().parse().unwrap(); let mut args=Vec::new();
                        for _ in 0..count {
                            line.clear(); reader.read_line(&mut line).unwrap(); let len:usize=line.strip_prefix('$').unwrap().trim().parse().unwrap();
                            let mut bytes=vec![0;len+2]; std::io::Read::read_exact(&mut reader,&mut bytes).unwrap(); assert_eq!(&bytes[len..],b"\r\n");args.push(String::from_utf8(bytes[..len].to_vec()).unwrap());
                        }
                        let response=match args[0].to_ascii_uppercase().as_str(){
                            "CLIENT"=>"+OK\r\n",
                            "PING"=>"+PONG\r\n",
                            "GET"=>{assert_eq!(args[1],format!("revoked:{hash}"));"$1\r\n1\r\n"},
                            other=>panic!("unexpected Redis command {other}"),
                        };
                        reader.get_mut().write_all(response.as_bytes()).unwrap();
                    }
                }
            });
            Self{url,stop,thread:Some(thread)}
        }
    }
    impl Drop for RevocationCache {fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);self.thread.take().unwrap().join().unwrap();}}

    #[tokio::test]
    async fn webhook_executor_rejects_ssh_from_its_current_dispatch_row() {
        let db=Db::open_memory().await.unwrap(); let (live,_)=tokio::sync::broadcast::channel(8);
        let st=new_state(db,String::new(),"executor-test".into(),"https://example.invalid".into(),oc::random_key(),live,None);
        st.db.exec("INSERT INTO integrations(id,env_id,kind,name,config_enc,created_at) VALUES('exec-integration','unused-env','webhook','executor','invalid-ciphertext-must-not-decrypt',?)",&[json!(now())]).await.unwrap();
        let admitted=st.db.one("SELECT kind FROM integrations WHERE id='exec-integration'",&[]).await.unwrap().unwrap();
        assert_eq!(db::s(&admitted,"kind"),"webhook");
        st.db.exec("UPDATE integrations SET kind='ssh' WHERE id='exec-integration'",&[]).await.unwrap();
        let result=sync_one_for_webhook(&st,"exec-integration","unused-user").await;
        assert!(matches!(result,Err((StatusCode::CONFLICT,_))),"executor must reject current SSH row before authorization, decryption or adapter execution: {result:?}");
    }

    #[tokio::test]
    async fn persisted_revoked_session_is_denied_for_cookie_as_well_as_bearer() {
        let token="revoked-but-still-persisted"; let hash=oc::hash_token(token); let cache=RevocationCache::start(hash.clone());
        let connection=redis::Client::open(cache.url.as_str()).unwrap().get_connection().unwrap();
        let db=Db::open_memory().await.unwrap();
        db.exec("INSERT INTO users(id,email,pass_hash,pubkey,wrapped_privkey,created_at) VALUES('cache-user','cache@test.invalid','','','',?)",&[json!(now())]).await.unwrap();
        db.exec("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,'cache-user',?)",&[json!(hash),json!(now())]).await.unwrap();
        let (live,_)=tokio::sync::broadcast::channel(8);
        let st=new_state(db,String::new(),"cache-test".into(),"https://example.invalid".into(),oc::random_key(),live,Some(connection));
        let mut bearer=HeaderMap::new();bearer.insert("authorization",format!("Bearer {token}").parse().unwrap());
        assert!(matches!(st.token_user(&bearer).await,Err((StatusCode::UNAUTHORIZED,_))),"Bearer revocation control failed");
        let mut cookie=HeaderMap::new();cookie.insert("cookie",format!("ow_session={token}").parse().unwrap());
        let result=st.token_user(&cookie).await;
        assert!(matches!(result,Err((StatusCode::UNAUTHORIZED,_))),"cookie skipped cached revocation: {result:?}");
        assert!(st.db.one("SELECT user_id FROM sessions WHERE token_hash=?",&[json!(hash)]).await.unwrap().is_some(),"fixture must retain the database session");
        drop(st);drop(cache);
    }
}
