// Included inside iroh::tests so frozen exact selectors retain their module.
use super::quota_test_support as sq_support;
const SQ_PAYLOAD: &[u8] = b"actual served quota payload";
#[derive(Default)]
struct SqStats {
    attempts: AtomicUsize, source: AtomicUsize, data: AtomicUsize,
    unavailable: AtomicUsize, authorizations: AtomicUsize,
}
impl SqStats {
    fn value(&self)->serde_json::Value {
        serde_json::json!({"attempts":self.attempts.load(Ordering::SeqCst),"source_calls":self.source.load(Ordering::SeqCst),"data":self.data.load(Ordering::SeqCst),"unavailable":self.unavailable.load(Ordering::SeqCst),"authorizations":self.authorizations.load(Ordering::SeqCst)})
    }
    fn assert_counts(&self,attempts:usize,data:usize,unavailable:usize) {
        assert_eq!(self.attempts.load(Ordering::SeqCst),attempts);
        assert_eq!(self.source.load(Ordering::SeqCst),data);
        assert_eq!(self.data.load(Ordering::SeqCst),data);
        assert_eq!(self.authorizations.load(Ordering::SeqCst),data);
        assert_eq!(self.unavailable.load(Ordering::SeqCst),unavailable);
    }
}
fn sq_observe(node:&L2SwarmNode,peer:&L2AuthenticatedPeer,req:&L2ChunkRequest,stats:&SqStats)->bool {
    sq_observe_source_gate(node,peer,req,stats,||{})
}
fn sq_observe_source_gate<F:FnMut()>(node:&L2SwarmNode,peer:&L2AuthenticatedPeer,req:&L2ChunkRequest,stats:&SqStats,mut source_gate:F)->bool {
    stats.attempts.fetch_add(1,Ordering::SeqCst);
    let mut reads=0;
    let (response,authorization)=node.handle_request_authorized(peer,req,|root,index|{
        assert_eq!(root,"ab".repeat(32));assert_eq!(index,0);
        reads+=1;stats.source.fetch_add(1,Ordering::SeqCst);source_gate();Some(SQ_PAYLOAD.to_vec())
    }).unwrap();
    match response {
        L2ChunkResponse::Data{slice_index,slice_bytes}=>{
            assert_eq!(reads,1);assert_eq!(slice_index,0);assert_eq!(slice_bytes.as_slice(),SQ_PAYLOAD);
            let authorization=authorization.expect("actual successful final handler guard");
            node.validate_data_release(peer,&authorization,now_ms()).unwrap();
            stats.data.fetch_add(1,Ordering::SeqCst);stats.authorizations.fetch_add(1,Ordering::SeqCst);true
        },
        L2ChunkResponse::Unavailable(frame)=>{
            // Source/final-guard contention must not masquerade as quota denial.
            assert_eq!(reads,0,"post-source refusal cannot establish admission refusal");
            assert!(authorization.is_none());assert_eq!(frame.len(),UNAVAILABLE_FRAME_SIZE);assert!(is_unavailable_frame(&frame));
            stats.unavailable.fetch_add(1,Ordering::SeqCst);false
        }
    }
}
struct SqFixture {
    f: Fixture, holders:Vec<SigningKey>, peers:Vec<L2AuthenticatedPeer>,
    seq:Vec<u64>,clock:Arc<Mutex<Instant>>,t0:Instant,stats:Arc<SqStats>,
}
fn sq_principal(name:&str)->String {format!("spiffe://fixture.example/engineer/{name}")}
impl SqFixture {
    fn with_members(holders:Vec<SigningKey>,members:Vec<enclave_core::enterprise_authority::EnterpriseMember>)->Self {
        let issuer=KeyPair::new();
        let authority=enclave_core::enterprise_authority::EnterpriseAuthority::ephemeral(SigningKey::from_bytes(&[42;32]).verifying_key().to_bytes(),enterprise_policy(1,members));
        let mut gate=SeedGateFSM::new(Profile::L2);gate.update(HostConditions::default());
        let mut node=L2SwarmNode::new(SigningKey::from_bytes(&[99;32]),Shard::EU,gate,L2CapabilityPolicy::new(issuer.public(),POLICY).with_enterprise_authority(authority));
        node.pad_budget=Duration::ZERO;
        let t0=Instant::now();let clock=Arc::new(Mutex::new(t0));node.quota_test_clock(clock.clone());
        let peers:Vec<_>=holders.iter().map(|holder|L2AuthenticatedPeer{public_key:holder.verifying_key().to_bytes(),channel_binding:*blake3::hash(holder.verifying_key().as_bytes()).as_bytes()}).collect();
        for peer in &peers {assert_ne!(peer.channel_binding,[0;32]);node.authorize_peer(&hex::encode(peer.public_key));}
        let f=Fixture{issuer,holder:holders[0].clone(),node,peer:peers[0].clone()};
        let seq=vec![0;holders.len()];Self{f,holders,peers,seq,clock,t0,stats:Arc::new(SqStats::default())}
    }
    fn new()->Self {
        let holders:Vec<_>=(71..=75).map(|n|SigningKey::from_bytes(&[n;32])).collect();
        let members=vec![enterprise_member("alice",vec![holders[0].verifying_key().to_bytes(),holders[1].verifying_key().to_bytes()]),enterprise_member("bob",vec![holders[2].verifying_key().to_bytes()])];
        Self::with_members(holders,members)
    }
    fn select(&mut self,who:usize) {
        self.f.holder=self.holders[who].clone();self.f.peer=self.peers[who].clone();
    }
    fn issue(&mut self,who:usize)->(L2AuthenticatedPeer,L2ChunkRequest) {
        self.select(who);let base=request(&self.f);let token=grant(&self.f,&self.f.issuer,&base,now_ms()+10_000);
        let seq=self.seq[who];self.seq[who]+=1;
        (self.peers[who].clone(),signed(&self.f,&token,&base,seq))
    }
    fn call(&mut self,who:usize)->bool {
        let (peer,req)=self.issue(who);sq_observe(&self.f.node,&peer,&req,&self.stats)
    }
    fn at(&self,ms:u64) {*self.clock.lock().unwrap()=self.t0+Duration::from_millis(ms);}
    fn deplete(&mut self,n:usize) {for index in 0..n {assert!(self.call(if index<25 {0}else{1}));}}
    fn certificate_headroom(&self,who:usize)->f64 {
        let (_,certificates)=self.f.node.quota_test_snapshots();
        if let Some(bucket)=certificates.get(&hex::encode(self.peers[who].public_key)) {assert!(bucket.0>=1.0);bucket.0}
        else {assert!(certificates.len()<1024);50.0}
    }
    fn observation(&self)->serde_json::Value {
        let (principals,certificates)=self.f.node.quota_test_snapshots();
        serde_json::json!({"counts":self.stats.value(),"principal_entries":principals.len(),"certificate_entries":certificates.len(),"quota_elapsed_ns":self.clock.lock().unwrap().checked_duration_since(self.t0).map(|d|d.as_nanos()),"process_children":0})
    }
    fn complete(&self,run:&mut sq_support::Run,case:&'static str) {run.complete(case,self.observation());}
}
#[test]
fn served_quota_burst_50_51_preserves_other_principal() {
    let mut run=sq_support::Run::new("transport::iroh::tests::served_quota_burst_50_51_preserves_other_principal",sq_support::SQ01,30);
    let mut f=SqFixture::new();
    let authority=f.f.node.enterprise_authority().unwrap();
    let a=authority.authorize(&f.peers[0].public_key,"models",enclave_crypto::time::now_unix()).unwrap();
    let b=authority.authorize(&f.peers[1].public_key,"models",enclave_crypto::time::now_unix()).unwrap();
    assert_eq!(a.principal,b.principal);assert_ne!(f.peers[0].public_key,f.peers[1].public_key);
    f.complete(&mut run,sq_support::SQ01[0]);
    f.deplete(50);f.stats.assert_counts(50,50,0);f.complete(&mut run,sq_support::SQ01[1]);
    let credit=f.certificate_headroom(0);assert_eq!(credit,25.0);
    assert!(!f.call(0));f.stats.assert_counts(51,50,1);f.complete(&mut run,sq_support::SQ01[2]);
    assert_eq!(f.certificate_headroom(0),24.0);f.complete(&mut run,sq_support::SQ01[3]);
    assert!(f.call(2));f.complete(&mut run,sq_support::SQ01[4]);
    f.stats.assert_counts(52,51,1);f.complete(&mut run,sq_support::SQ01[5]);run.finish();
}
#[test]
fn served_quota_fractional_refill_regression_and_ten_per_second() {
    let mut run=sq_support::Run::new("transport::iroh::tests::served_quota_fractional_refill_regression_and_ten_per_second",sq_support::SQ02,30);
    let mut f=SqFixture::new();f.deplete(50);f.certificate_headroom(0);f.complete(&mut run,sq_support::SQ02[0]);
    for (case,ms,accepted) in [(1,99,false),(2,100,true),(3,199,false),(4,200,true),(5,150,false)] {
        f.at(ms);f.certificate_headroom(0);assert_eq!(f.call(0),accepted);f.complete(&mut run,sq_support::SQ02[case]);
    }
    f.at(1200);for _ in 0..10 {f.certificate_headroom(0);assert!(f.call(0));}
    f.stats.assert_counts(65,62,3);f.complete(&mut run,sq_support::SQ02[6]);
    f.certificate_headroom(0);assert!(!f.call(0));f.stats.assert_counts(66,62,4);f.complete(&mut run,sq_support::SQ02[7]);run.finish();
}
#[test]
fn served_quota_clone_channel_and_rekey_share_principal_debt() {
    let mut run=sq_support::Run::new("transport::iroh::tests::served_quota_clone_channel_and_rekey_share_principal_debt",sq_support::SQ03,30);
    let mut f=SqFixture::new();f.deplete(50);f.complete(&mut run,sq_support::SQ03[0]);
    let (peer,req)=f.issue(0);f.certificate_headroom(0);let clone=f.f.node.clone();assert!(!sq_observe(&clone,&peer,&req,&f.stats));f.complete(&mut run,sq_support::SQ03[1]);
    f.peers[0].channel_binding=[91;32];let (peer,req)=f.issue(0);f.certificate_headroom(0);assert!(!sq_observe(&f.f.node,&peer,&req,&f.stats));f.complete(&mut run,sq_support::SQ03[2]);
    f.f.node.enterprise_authority().unwrap().replace_ephemeral(enterprise_policy(2,vec![enterprise_member("alice",vec![f.peers[0].public_key,f.peers[1].public_key,f.peers[3].public_key]),enterprise_member("bob",vec![f.peers[2].public_key])])).unwrap();
    let replacement=f.f.node.enterprise_authority().unwrap().authorize(&f.peers[3].public_key,"models",enclave_crypto::time::now_unix()).unwrap();assert_eq!(replacement.principal,sq_principal("alice"));
    f.certificate_headroom(3);assert!(!f.call(3));assert_eq!(f.certificate_headroom(3),49.0);f.complete(&mut run,sq_support::SQ03[3]);
    f.certificate_headroom(4);assert!(!f.call(4));f.complete(&mut run,sq_support::SQ03[4]);
    assert!(f.call(2));f.complete(&mut run,sq_support::SQ03[5]);
    assert_eq!(f.seq[0],27);assert_eq!(f.seq[3],1);f.complete(&mut run,sq_support::SQ03[6]);
    assert!(f.certificate_headroom(0)>=23.0);assert_eq!(f.certificate_headroom(3),49.0);f.stats.assert_counts(55,51,4);f.complete(&mut run,sq_support::SQ03[7]);run.finish();
}
#[test]
fn served_quota_concurrent_last_token_has_one_winner() {
    let mut run=sq_support::Run::new("transport::iroh::tests::served_quota_concurrent_last_token_has_one_winner",sq_support::SQ04,30);
    let mut f=SqFixture::new();f.deplete(49);f.certificate_headroom(0);f.certificate_headroom(1);f.complete(&mut run,sq_support::SQ04[0]);
    let calls=vec![f.issue(0),f.issue(1)];assert_ne!(calls[0].0.public_key,calls[1].0.public_key);assert_ne!(calls[0].1.pop_biscuit_token,calls[1].1.pop_biscuit_token);
    let barrier=Arc::new(std::sync::Barrier::new(3));let mut workers=Vec::new();
    let (loser_tx,loser_rx)=std::sync::mpsc::sync_channel(2);
    let loser_rx=Arc::new(Mutex::new(loser_rx));let loser_returned=Arc::new(std::sync::atomic::AtomicBool::new(false));
    for (peer,req) in calls {
        let node=f.f.node.clone();let stats=f.stats.clone();let start=barrier.clone();
        let tx=loser_tx.clone();let rx=loser_rx.clone();let returned=loser_returned.clone();
        workers.push(std::thread::spawn(move||{
            start.wait();
            let accepted=sq_observe_source_gate(&node,&peer,&req,&stats,||{
                // Both requests race through real admission. Delay the sole
                // winning source return until the actual source-zero loser
                // has returned and released its membership lookup guards.
                // Overspend yields two waiting source entrants and a bounded
                // failure, never an authority-contention quota PASS.
                rx.lock().unwrap().recv_timeout(Duration::from_secs(2)).expect("actual quota loser must return before final guard");
                assert!(returned.load(Ordering::SeqCst));
            });
            if !accepted {returned.store(true,Ordering::SeqCst);tx.send(()).unwrap();}
            (peer,req,accepted)
        }));
    }
    barrier.wait();f.complete(&mut run,sq_support::SQ04[1]);
    let outcomes:Vec<_>=workers.into_iter().map(|worker|worker.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|v|v.2).count(),1);assert!(loser_returned.load(Ordering::SeqCst));f.stats.assert_counts(51,50,1);
    run.complete(sq_support::SQ04[2],serde_json::json!({"counts":f.stats.value(),"source_return_after_actual_source_zero_loser":loser_returned.load(Ordering::SeqCst),"source_gate_timeout_ms":2000}));
    let (peer,req,_)=outcomes.into_iter().find(|v|!v.2).unwrap();f.at(100);assert!(sq_observe(&f.f.node,&peer,&req,&f.stats));f.complete(&mut run,sq_support::SQ04[3]);
    assert!(f.call(2));f.complete(&mut run,sq_support::SQ04[4]);f.stats.assert_counts(53,52,1);f.complete(&mut run,sq_support::SQ04[5]);run.finish();
}
#[test]
fn served_quota_full_1024_signed_revision_reclaims_only_replenished_entries() {
    let mut run=sq_support::Run::new("transport::iroh::tests::served_quota_full_1024_signed_revision_reclaims_only_replenished_entries",sq_support::SQ05,90);
    let holders:Vec<_>=(0..1024).map(|i|SigningKey::from_bytes(blake3::hash(format!("served-quota-capacity-{i}").as_bytes()).as_bytes())).collect();
    let mut members:Vec<_>=holders.iter().enumerate().map(|(i,h)|enterprise_member(&format!("p{i:04}"),vec![h.verifying_key().to_bytes()])).collect();
    assert_eq!(members.len(),1024);let mut f=SqFixture::with_members(holders,members.clone());
    for (index,name) in [(0,"p0000"),(1023,"p1023")] {
        let member=f.f.node.enterprise_authority().unwrap().authorize(&f.peers[index].public_key,"models",enclave_crypto::time::now_unix()).unwrap();assert_eq!(member.principal,sq_principal(name));
    }
    f.complete(&mut run,sq_support::SQ05[0]);
    for i in 0..1024 {
        assert!(f.call(i));
        if (i+1)%128==0 {f.stats.assert_counts(i+1,i+1,0);run.progress(&format!("capacity-fill-{:04}",i+1),f.observation());}
    }
    f.stats.assert_counts(1024,1024,0);
    let (principals,certificates)=f.f.node.quota_test_snapshots();assert_eq!(principals.len(),1024);assert_eq!(certificates.len(),1024);
    assert!(principals.values().all(|b|*b==(49.0,50.0,10.0)));assert!(certificates.values().all(|b|*b==(49.0,50.0,10.0)));
    for i in 0..1024 {assert!(principals.contains_key(&sq_principal(&format!("p{i:04}"))));}
    f.complete(&mut run,sq_support::SQ05[1]);f.complete(&mut run,sq_support::SQ05[2]);
    members[1023]=enterprise_member("p1024",vec![f.peers[1023].public_key]);
    f.f.node.enterprise_authority().unwrap().replace_ephemeral(enterprise_policy(2,members)).unwrap();
    let lease=f.f.node.enterprise_authority().unwrap().authorize(&f.peers[1023].public_key,"models",enclave_crypto::time::now_unix()).unwrap();assert_eq!(lease.principal,sq_principal("p1024"));f.complete(&mut run,sq_support::SQ05[3]);
    f.certificate_headroom(1023);assert!(!f.call(1023));let (p,_)=f.f.node.quota_test_snapshots();assert_eq!(p.len(),1024);assert!(p.contains_key(&sq_principal("p1023")));assert!(!p.contains_key(&sq_principal("p1024")));f.complete(&mut run,sq_support::SQ05[4]);
    assert!(f.call(0));let (p,_)=f.f.node.quota_test_snapshots();assert_eq!(p[&sq_principal("p0000")].0,48.0);f.complete(&mut run,sq_support::SQ05[5]);
    f.at(99);f.certificate_headroom(1023);assert!(!f.call(1023));assert_eq!(f.f.node.quota_test_snapshots().0.len(),1024);f.complete(&mut run,sq_support::SQ05[6]);
    f.at(100);f.certificate_headroom(1023);assert!(f.call(1023));let (p,c)=f.f.node.quota_test_snapshots();
    assert_eq!(p.len(),2);assert_eq!(c.len(),1024);assert_eq!(p[&sq_principal("p0000")].0,49.0);assert_eq!(p[&sq_principal("p1024")].0,49.0);f.complete(&mut run,sq_support::SQ05[7]);
    assert!(p.len()<=1024&&!p.contains_key(&sq_principal("p1023")));f.complete(&mut run,sq_support::SQ05[8]);
    assert!(f.call(0));let (p,_)=f.f.node.quota_test_snapshots();assert_eq!(p[&sq_principal("p0000")].0,48.0);f.stats.assert_counts(1029,1027,2);f.complete(&mut run,sq_support::SQ05[9]);run.finish();
}
#[test]
fn served_quota_hostile_proofs_refuse_and_valid_calls_recover() {
    let mut run=sq_support::Run::new("transport::iroh::tests::served_quota_hostile_proofs_refuse_and_valid_calls_recover",sq_support::SQ06,30);
    let mut controls=0;
    for case in 0..7 {
        let mut f=SqFixture::new();let (peer,valid)=f.issue(0);
        assert!(sq_observe(&f.f.node,&peer,&valid,&f.stats));controls+=1;
        let (mut bad_peer,mut bad)=if case==6 {(peer.clone(),valid.clone())}else{f.issue(0)};
        match case {
            0=>{f.select(0);let base=request(&f.f);let token=grant(&f.f,&KeyPair::new(),&base,now_ms()+10_000);bad=signed(&f.f,&token,&base,1);},
            1=>bad_peer=f.peers[1].clone(),
            2=>bad_peer.channel_binding=[202;32],
            3=>bad.namespace_id="other".into(),
            4=>bad.root_hash="cd".repeat(32),
            5=>{f.select(0);let base=request(&f.f);let token=grant(&f.f,&f.f.issuer,&base,now_ms()-1000);bad=signed(&f.f,&token,&base,1);},
            _=>{},
        }
        assert!(!sq_observe(&f.f.node,&bad_peer,&bad,&f.stats));f.complete(&mut run,sq_support::SQ06[case]);
        assert!(f.call(0));controls+=1;f.stats.assert_counts(3,2,1);
    }
    assert_eq!(controls,14);run.complete(sq_support::SQ06[7],serde_json::json!({"healthy_source_data_controls":controls,"hostile_source_calls":0,"hostile_unavailable":7,"fresh_fixture_per_hostile_case":true,"process_children":0}));run.finish();
}
