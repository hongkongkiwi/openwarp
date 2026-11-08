#[derive(Clone)]
struct AuditEvent { fields: [String; 6], id: String, created_at: i64 }
impl AuditEvent {
    fn new(fields: [&str; 6]) -> Self { Self { fields: fields.map(str::to_string), id: id(), created_at: now() } }
    fn append(&self, tx: &db::WebhookTx<'_>) -> Result<(), String> {
        let [org, app, env, actor, action, detail] = &self.fields;
        let head = tx.one("SELECT seq,hash FROM audit_heads WHERE org_id=?", &[json!(org)])?;
        let (prev_seq, prev) = head.as_ref().map(|r| (db::n(r,"seq"), db::s(r,"hash"))).unwrap_or_default();
        let seq = prev_seq + 1;
        let hash = audit_hash(&prev,seq,org,app,env,actor,action,detail,self.created_at);
        if head.is_some() { tx.exec("UPDATE audit_heads SET seq=?,hash=? WHERE org_id=?", &[json!(seq),json!(hash),json!(org)])?; }
        else { tx.exec("INSERT INTO audit_heads(org_id,seq,hash) VALUES(?,?,?)", &[json!(org),json!(seq),json!(hash)])?; }
        tx.exec("INSERT INTO audit(id,org_id,app_id,env_id,actor,action,detail,created_at,seq,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)", &[json!(self.id),json!(org),json!(app),json!(env),json!(actor),json!(action),json!(detail),json!(self.created_at),json!(seq),json!(prev),json!(hash)])?;
        #[cfg(not(target_arch="wasm32"))]
        { let wall=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_micros() as i64;
          let prior=tx.one("SELECT MAX(id) AS last_id FROM live_events", &[])?.map(|r|db::n(&r,"last_id")).unwrap_or(0); let live_id=wall.max(prior+1);
          tx.exec("INSERT INTO live_events(id,org_id,app_id,env_id,action,detail,created_at) VALUES(?,?,?,?,?,?,?)", &[json!(live_id),json!(org),json!(app),json!(env),json!(action),json!(detail),json!(self.created_at)])?; }
        let count = tx.one("SELECT COUNT(*) AS n FROM webhook_outbox", &[])?.map(|r| db::n(&r,"n")).unwrap_or(0);
        if count >= 10000 { return Err("webhook outbox capacity exhausted".into()); }
        let payload = json!({"id":self.id,"type":action,"timestamp":self.created_at,"workspace_id":org,"app_id":app,"env_id":env,"actor_id":actor}).to_string();
        tx.exec("INSERT INTO webhook_outbox(id,payload,created_at) VALUES(?,?,?)", &[json!(self.id),json!(payload),json!(self.created_at)])?;
        for row in tx.query("SELECT id,version,events FROM webhook_subscriptions WHERE org_id=? AND enabled=1 AND (app_id='' OR app_id=?)", &[json!(org),json!(app)])? {
            let filters: Vec<String> = serde_json::from_str(&db::s(&row,"events")).map_err(|_|"invalid webhook event filters")?;
            if filters.iter().any(|v| v=="*" || v==action) {
                tx.exec("INSERT INTO webhook_outbox_targets(event_id,webhook_id,version,delivery_id) VALUES(?,?,?,?)", &[json!(self.id),json!(db::s(&row,"id")),json!(db::n(&row,"version")),json!(id())])?;
            }
        }
        Ok(())
    }
}
fn meta_statements(k: &str, v: &str) -> [(String,Vec<Value>);2] {
    [("DELETE FROM meta WHERE k=?".into(),vec![json!(k)]),
     ("INSERT INTO meta(k,v) VALUES(?,?)".into(),vec![json!(k),json!(v)])]
}
impl AppState {
    pub(crate) async fn audited_batch(&self, statements: &[(String,Vec<Value>)], require_one: &[usize], fields: [&str;6]) -> Result<(),String> {
        self.audited_batch_inner(statements,require_one,fields,None).await
    }
    // Master-dependent writes fence the captured master in the same transaction
    // as the mutation, so a stale replica rolls back instead of writing.
    pub(crate) async fn audited_batch_master(&self, statements: &[(String,Vec<Value>)], require_one: &[usize], fields: [&str;6], master: [u8;32]) -> Result<(),String> {
        self.audited_batch_inner(statements,require_one,fields,Some(master)).await
    }
    async fn audited_batch_inner(&self, statements: &[(String,Vec<Value>)], require_one: &[usize], fields: [&str;6], master: Option<[u8;32]>) -> Result<(),String> {
        let event = AuditEvent::new(fields); let statements=statements.to_vec(); let checked=require_one.to_vec();
        self.db.webhook_atomic(move |tx| {
            if let Some(master)=master { webhooks::epoch_lock(tx,&master)?; }
            for (index,(sql,params)) in statements.iter().enumerate() {
                let affected=tx.exec(sql,params)?;
                if checked.contains(&index) && affected!=1 { return Err("version conflict: concurrent change".into()); }
            }
            event.append(tx)
        }).await?;
        self.drain_outbox().await;
        Ok(())
    }
    // Master-dependent write without a business audit event.
    pub(crate) async fn epoch_write(&self, statements: &[(String,Vec<Value>)], require_one: &[usize], master: [u8;32]) -> Result<(),String> {
        let statements=statements.to_vec(); let checked=require_one.to_vec();
        self.db.webhook_atomic(move |tx| {
            webhooks::epoch_lock(tx,&master)?;
            for (index,(sql,params)) in statements.iter().enumerate() {
                let affected=tx.exec(sql,params)?;
                if checked.contains(&index) && affected!=1 { return Err("version conflict: concurrent change".into()); }
            }
            Ok(())
        }).await
    }
    // Read-side epoch check. A stale replica fails closed instead of decrypting
    // with a root the current epoch no longer recognises.
    pub(crate) async fn epoch_ok(&self) -> Result<i64,(StatusCode,Json<Value>)> {
        webhooks::epoch_current(&self.db,&self.master()).await.map_err(|e| if e==webhooks::EPOCH_STALE {webhooks::epoch_stale()} else {err(StatusCode::SERVICE_UNAVAILABLE,&e)})
    }
    async fn drain_outbox(&self) {
        let result=self.db.webhook_atomic(move |tx| {
            let targets=tx.query("SELECT t.event_id,t.webhook_id,t.version,t.delivery_id,o.payload,o.created_at FROM webhook_outbox_targets t JOIN webhook_outbox o ON o.id=t.event_id WHERE NOT EXISTS (SELECT 1 FROM webhook_subscriptions s WHERE s.id=t.webhook_id AND s.version=t.version AND s.enabled=1) OR (SELECT COUNT(*) FROM webhook_deliveries d WHERE d.webhook_id=t.webhook_id AND d.status IN ('pending','failed','processing'))<1000 ORDER BY o.created_at,t.event_id,t.webhook_id LIMIT 100", &[])?;
            for target in targets {
                let event=db::s(&target,"event_id"); let wid=db::s(&target,"webhook_id"); let version=db::n(&target,"version");
                let current=tx.one("SELECT id FROM webhook_subscriptions WHERE id=? AND version=? AND enabled=1", &[json!(wid),json!(version)])?.is_some();
                if current {
                    let queued=tx.one("SELECT COUNT(*) AS n FROM webhook_deliveries WHERE webhook_id=? AND status IN ('pending','failed','processing')", &[json!(wid)])?.map(|r|db::n(&r,"n")).unwrap_or(0);
                    if queued>=1000 { continue; }
                    tx.exec("INSERT INTO webhook_deliveries(id,webhook_id,event_id,payload,version,status,created_at,updated_at,next_attempt_at) VALUES(?,?,?,?,?,'pending',?,?,?)", &[json!(db::s(&target,"delivery_id")),json!(wid),json!(event),json!(db::s(&target,"payload")),json!(version),json!(db::n(&target,"created_at")),json!(now()),json!(now())])?;
                }
                tx.exec("DELETE FROM webhook_outbox_targets WHERE event_id=? AND webhook_id=?", &[json!(event),json!(wid)])?;
            }
            tx.exec("DELETE FROM webhook_outbox WHERE NOT EXISTS (SELECT 1 FROM webhook_outbox_targets t WHERE t.event_id=webhook_outbox.id)", &[])?;
            Ok(())
        }).await;
        if let Err(error)=result { tracing::error!(%error,"webhook outbox drain failed"); }
    }
}
