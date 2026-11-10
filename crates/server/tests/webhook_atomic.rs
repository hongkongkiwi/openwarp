use openwarp_server::db::Db;
use serde_json::json;
use std::sync::mpsc;
use std::time::Duration;

#[tokio::test]
async fn webhook_transaction_error_rolls_back_every_write_and_leaves_connection_usable() {
    let db=Db::open_memory().await.unwrap();
    db.exec("INSERT INTO meta(k,v) VALUES(?,?)",&[json!("atomic-existing"),json!("before")]).await.unwrap();
    let failed:Result<(),String>=db.webhook_atomic(|tx| {
        tx.exec("UPDATE meta SET v=? WHERE k=?",&[json!("partial"),json!("atomic-existing")])?;
        tx.exec("INSERT INTO meta(k,v) VALUES(?,?)",&[json!("atomic-new"),json!("partial")])?;
        assert_eq!(tx.one("SELECT v FROM meta WHERE k=?",&[json!("atomic-existing")])?.unwrap()["v"],"partial");
        Err("deliberate transaction failure".into())
    }).await;
    assert_eq!(failed.unwrap_err(),"deliberate transaction failure");
    assert_eq!(db.one("SELECT v FROM meta WHERE k=?",&[json!("atomic-existing")]).await.unwrap().unwrap()["v"],"before");
    assert!(db.one("SELECT v FROM meta WHERE k=?",&[json!("atomic-new")]).await.unwrap().is_none());
    db.webhook_atomic(|tx| { tx.exec("UPDATE meta SET v=? WHERE k=?",&[json!("committed"),json!("atomic-existing")])?; Ok(()) }).await.unwrap();
    assert_eq!(db.one("SELECT v FROM meta WHERE k=?",&[json!("atomic-existing")]).await.unwrap().unwrap()["v"],"committed");
}

#[tokio::test]
async fn webhook_transactions_serialize_barrier_controlled_reads_after_complete_commit() {
    let file=std::env::temp_dir().join(format!("openwarp-webhook-atomic-{}-{}.db",std::process::id(),openwarp_crypto::random_token("fixture")));
    let url=format!("sqlite://{}",file.display());
    let first_db=Db::open(&url).await.unwrap(); let second_db=Db::open(&url).await.unwrap();
    first_db.exec("INSERT INTO meta(k,v) VALUES(?,?)",&[json!("atomic-barrier"),json!("before")]).await.unwrap();
    let (entered_tx,entered_rx)=mpsc::channel(); let (release_tx,release_rx)=mpsc::channel();
    let first=std::thread::spawn(move || {
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(first_db.webhook_atomic(move |tx| {
            tx.exec("UPDATE meta SET v=? WHERE k=?",&[json!("uncommitted-intermediate"),json!("atomic-barrier")])?;
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).expect("release first transaction");
            tx.exec("UPDATE meta SET v=? WHERE k=?",&[json!("complete"),json!("atomic-barrier")])?; Ok(())
        })).unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).expect("first transaction entered");
    let (attempt_tx,attempt_rx)=mpsc::channel();
    let second=std::thread::spawn(move || {
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        attempt_tx.send(()).unwrap();
        runtime.block_on(second_db.webhook_atomic(|tx| {
            let row=tx.one("SELECT v FROM meta WHERE k=?",&[json!("atomic-barrier")])?.unwrap();
            Ok(row["v"].clone())
        })).unwrap()
    });
    attempt_rx.recv_timeout(Duration::from_secs(10)).expect("second thread ready");
    release_tx.send(()).unwrap(); first.join().unwrap();
    assert_eq!(second.join().unwrap(),json!("complete"),"another transaction observed intermediate state");
    std::fs::remove_file(file).unwrap();
}
