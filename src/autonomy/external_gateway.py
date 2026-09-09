"""AF-05 authenticated external-adapter gateway; no provider attestation."""
from __future__ import annotations
import base64, hashlib, json, math, secrets
from dataclasses import asdict, dataclass
from cryptography.exceptions import InvalidSignature
from .protocol import DispatchEnvelope
from .runtime import RuntimeRootPolicy
from .store import AutonomyStore, BlockedError, IntegrityBlockedError
from .transport import DurableLocalSpool
from .trust import AUTHENTICATION_SCOPE, TrustedWorkerProfile, TrustedWorkerRegistry, identifier, signed_bytes

AF05_PROTOCOL_VERSION = "AF05/1"
DOMAINS = {name: f"AI-CONTROL-PLANE/AF05/{name}" for name in ("SESSION","HEARTBEAT","ACK","RESULT")}

@dataclass(frozen=True)
class SessionChallenge:
    challenge_id:str; worker_id:str; key_id:str; nonce:str; protocol_version:str
    profile_digest:str; issued_at:float; expires_at:float
    def transcript(self, session_id:str, capacity:int)->dict[str,object]:
        return {**asdict(self),"session_id":session_id,"capacity":capacity}

class AuthenticatedExternalGateway:
    def __init__(self, store:AutonomyStore, runtime_root, profiles:tuple[TrustedWorkerProfile,...], *, repository_roots, challenge_ttl:float=30.0, scoped_capabilities:frozenset[str]=frozenset()):
        if isinstance(challenge_ttl,bool) or not math.isfinite(float(challenge_ttl)) or not 1<=float(challenge_ttl)<=300: raise BlockedError("invalid challenge TTL")
        roots=tuple(repository_roots)
        if not roots: raise BlockedError("protected repository roots required")
        safe_root=RuntimeRootPolicy(roots).validate(runtime_root)
        self.store=store; self.registry=TrustedWorkerRegistry(profiles,scoped_capabilities=scoped_capabilities); self.transport=DurableLocalSpool(safe_root); self.challenge_ttl=float(challenge_ttl)
        self._init_schema(); self._persist_profiles()
        self.store.db.execute("UPDATE af05_sessions SET state='REAUTH_REQUIRED' WHERE state='AUTHENTICATED'")

    def _init_schema(self):
        self.store.db.executescript("""
CREATE TABLE IF NOT EXISTS af05_profiles(worker_id TEXT PRIMARY KEY,worker_kind TEXT NOT NULL,key_id TEXT NOT NULL,fingerprint TEXT NOT NULL,profile_digest TEXT NOT NULL,profile_version INTEGER NOT NULL,capabilities TEXT NOT NULL,targets TEXT NOT NULL,max_capacity INTEGER NOT NULL,heartbeat_sla REAL NOT NULL,enabled INTEGER NOT NULL,revoked INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS af05_challenges(challenge_id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,key_id TEXT NOT NULL,nonce_digest TEXT NOT NULL,protocol TEXT NOT NULL,profile_digest TEXT NOT NULL,issued_at REAL NOT NULL,expires_at REAL NOT NULL,consumed INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS af05_sessions(worker_id TEXT PRIMARY KEY,worker_kind TEXT NOT NULL,session_id TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,fingerprint TEXT NOT NULL,profile_digest TEXT NOT NULL,scope TEXT NOT NULL,authenticated_at REAL NOT NULL,last_sequence INTEGER NOT NULL,last_heartbeat REAL NOT NULL,capacity INTEGER NOT NULL,state TEXT NOT NULL,last_message_id TEXT);
CREATE TABLE IF NOT EXISTS af05_messages(message_id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,session_id TEXT NOT NULL,sequence INTEGER NOT NULL,domain TEXT NOT NULL,accepted_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS af05_dispatches(dispatch_id TEXT PRIMARY KEY,task_id TEXT NOT NULL,worker_id TEXT NOT NULL,session_id TEXT NOT NULL,lease_id TEXT NOT NULL,lease_expires_at REAL NOT NULL,capability TEXT NOT NULL,target_project TEXT NOT NULL,protocol TEXT NOT NULL,acknowledged INTEGER NOT NULL DEFAULT 0,result_received INTEGER NOT NULL DEFAULT 0,ack_at REAL);
""")

    def _persist_profiles(self):
        for item in self.registry.all():
            p=item.profile; binding=(p.worker_id,p.worker_kind,p.key_id,item.fingerprint,item.digest,p.profile_version,json.dumps(sorted(p.capabilities)),json.dumps(sorted(p.allowed_targets)),p.max_capacity,float(p.heartbeat_sla),int(p.enabled),int(p.revoked))
            row=self.store.db.execute("SELECT * FROM af05_profiles WHERE worker_id=?",(p.worker_id,)).fetchone()
            if row:
                keys=("worker_id","worker_kind","key_id","fingerprint","profile_digest","profile_version","capabilities","targets","max_capacity","heartbeat_sla","enabled","revoked")
                actual=tuple(row[k] for k in keys)
                if actual[:10]!=binding[:10] or (not binding[10] and actual[10]) or (binding[11] and not actual[11]): raise IntegrityBlockedError("trusted profile contradiction")
                if binding[11]: self.store.db.execute("UPDATE af05_profiles SET revoked=1 WHERE worker_id=?",(p.worker_id,))
            else: self.store.db.execute("INSERT INTO af05_profiles VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",binding)

    @staticmethod
    def _time(value):
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(float(value)) or value<0: raise BlockedError("invalid message time")
        return float(value)

    def issue_challenge(self,worker_id,key_id,*,now):
        n=self.store.now(now); profile=self._trusted(worker_id)
        if key_id!=profile.profile.key_id: raise BlockedError("unknown worker key")
        nonce_bytes=secrets.token_bytes(32); nonce=base64.b64encode(nonce_bytes).decode("ascii")
        cid=hashlib.sha256(b"AF05-CHALLENGE\0"+nonce_bytes+worker_id.encode()).hexdigest(); challenge=SessionChallenge(cid,worker_id,key_id,nonce,AF05_PROTOCOL_VERSION,profile.digest,n,n+self.challenge_ttl)
        try: self.store.db.execute("INSERT INTO af05_challenges VALUES(?,?,?,?,?,?,?,?,0,0)",(cid,worker_id,key_id,hashlib.sha256(nonce_bytes).hexdigest(),AF05_PROTOCOL_VERSION,profile.digest,n,n+self.challenge_ttl))
        except Exception as exc: raise IntegrityBlockedError("challenge collision") from exc
        return challenge

    def _trusted(self, worker_id):
        profile=self.registry.get(worker_id)
        row=self.store.db.execute("SELECT enabled,revoked,profile_digest,key_id FROM af05_profiles WHERE worker_id=?",(profile.profile.worker_id,)).fetchone()
        if not row or not row["enabled"] or row["revoked"] or row["profile_digest"]!=profile.digest or row["key_id"]!=profile.profile.key_id: raise BlockedError("worker trust revoked or contradictory")
        return profile

    def _verify(self,profile,domain,frame):
        signature=frame.get("signature")
        if not isinstance(signature,str): raise BlockedError("missing signature")
        try: profile.public_key.verify(base64.b64decode(signature,validate=True),signed_bytes(DOMAINS[domain],frame))
        except (ValueError,InvalidSignature) as exc: raise BlockedError("invalid signature") from exc

    def authenticate_session(self,frame,*,now):
        expected={"challenge_id","worker_id","key_id","nonce","protocol_version","profile_digest","issued_at","expires_at","session_id","capacity","signature"}
        if not isinstance(frame,dict) or set(frame)!=expected: raise BlockedError("malformed session frame")
        n=self.store.now(now); worker=identifier(frame.get("worker_id"),"worker_id"); key=identifier(frame.get("key_id"),"key_id"); session=identifier(frame.get("session_id"),"session_id"); cid=identifier(frame.get("challenge_id"),"challenge_id"); profile=self._trusted(worker)
        if key!=profile.profile.key_id or frame.get("protocol_version")!=AF05_PROTOCOL_VERSION or frame.get("profile_digest")!=profile.digest: raise BlockedError("session binding mismatch")
        capacity=frame.get("capacity")
        if isinstance(capacity,bool) or not isinstance(capacity,int) or not 0<=capacity<=profile.profile.max_capacity: raise BlockedError("capacity escalation")
        row=self.store.db.execute("SELECT * FROM af05_challenges WHERE challenge_id=?",(cid,)).fetchone()
        try: nonce_digest=hashlib.sha256(base64.b64decode(frame.get("nonce"),validate=True)).hexdigest()
        except Exception as exc: raise BlockedError("malformed challenge nonce") from exc
        if not row or row["consumed"] or row["revoked"] or row["worker_id"]!=worker or row["key_id"]!=key or row["profile_digest"]!=profile.digest or row["protocol"]!=frame.get("protocol_version") or row["nonce_digest"]!=nonce_digest or row["issued_at"]!=frame.get("issued_at") or row["expires_at"]!=frame.get("expires_at") or row["expires_at"]<=n or row["issued_at"]>n+1: raise BlockedError("challenge unavailable")
        self._verify(profile,"SESSION",frame)
        active=self.store.db.execute("SELECT session_id,last_heartbeat,state FROM af05_sessions WHERE worker_id=?",(worker,)).fetchone()
        if active and active["session_id"]!=session and active["state"]=="AUTHENTICATED" and n-active["last_heartbeat"]<=profile.profile.heartbeat_sla: raise BlockedError("simultaneous session takeover")
        self.store.db.execute("BEGIN IMMEDIATE")
        changed=self.store.db.execute("UPDATE af05_challenges SET consumed=1 WHERE challenge_id=? AND consumed=0 AND revoked=0 AND expires_at>?",(cid,n)).rowcount
        if changed!=1: self.store.db.execute("ROLLBACK"); raise BlockedError("challenge replay")
        self.store.db.execute("INSERT OR REPLACE INTO af05_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(worker,profile.profile.worker_kind,session,key,profile.fingerprint,profile.digest,AUTHENTICATION_SCOPE,n,0,n,capacity,"AUTHENTICATED",None))
        self.store.register_worker(worker_id=worker,kind=profile.profile.worker_kind,capabilities=profile.profile.capabilities,targets=profile.profile.allowed_targets,heartbeat_sla=profile.profile.heartbeat_sla,capacity=capacity,now=n)
        self.store.db.execute("COMMIT")

    def _message(self,domain,frame,*,now):
        common={"protocol_version","worker_id","key_id","session_id","message_id","sequence","observed_at","signature"}
        required={"HEARTBEAT":common|{"capacity"},"ACK":common|{"dispatch_id","task_id","lease_id"},"RESULT":common|{"dispatch_id","task_id","lease_id","status","evidence_id","evidence_sha256"}}[domain]
        if not isinstance(frame,dict) or set(frame)!=required: raise BlockedError("malformed signed frame")
        n=self.store.now(now); worker=identifier(frame.get("worker_id"),"worker_id"); key=identifier(frame.get("key_id"),"key_id"); sid=identifier(frame.get("session_id"),"session_id"); mid=identifier(frame.get("message_id"),"message_id"); profile=self._trusted(worker); row=self.store.db.execute("SELECT * FROM af05_sessions WHERE worker_id=?",(worker,)).fetchone(); seq=frame.get("sequence"); observed=self._time(frame.get("observed_at"))
        if not row or row["state"]!="AUTHENTICATED" or row["session_id"]!=sid or row["key_id"]!=key or row["profile_digest"]!=profile.digest or frame.get("protocol_version")!=AF05_PROTOCOL_VERSION or isinstance(seq,bool) or not isinstance(seq,int) or seq<=row["last_sequence"] or observed>n+1 or self.store.db.execute("SELECT 1 FROM af05_messages WHERE message_id=?",(mid,)).fetchone(): raise BlockedError("message replay or session binding failure")
        self._verify(profile,domain,frame); return n,profile,row,seq,observed,mid

    def _accept(self,mid,worker,sid,seq,domain,n,heartbeat=None,capacity=None):
        self.store.db.execute("INSERT INTO af05_messages VALUES(?,?,?,?,?,?)",(mid,worker,sid,seq,domain,n))
        if heartbeat is None: self.store.db.execute("UPDATE af05_sessions SET last_sequence=?,last_message_id=? WHERE worker_id=?",(seq,mid,worker))
        else: self.store.db.execute("UPDATE af05_sessions SET last_sequence=?,last_message_id=?,last_heartbeat=?,capacity=? WHERE worker_id=?",(seq,mid,heartbeat,capacity,worker))

    def heartbeat(self,frame,*,now):
        n,p,row,seq,observed,mid=self._message("HEARTBEAT",frame,now=now); capacity=frame.get("capacity")
        if observed<=row["last_heartbeat"] or n-observed>p.profile.heartbeat_sla or isinstance(capacity,bool) or not isinstance(capacity,int) or not 0<=capacity<=p.profile.max_capacity: raise BlockedError("stale heartbeat or capacity escalation")
        self.store.heartbeat_with_capacity(p.profile.worker_id,capacity=capacity,now=n,observed_at=observed); self._accept(mid,p.profile.worker_id,row["session_id"],seq,"HEARTBEAT",n,observed,capacity)

    def eligible_sessions(self,*,capability,target_project,now):
        n=self.store.now(now); result=[]
        for item in self.registry.all():
            p=item.profile; durable=self.store.db.execute("SELECT revoked FROM af05_profiles WHERE worker_id=?",(p.worker_id,)).fetchone()
            if not p.enabled or p.revoked or durable["revoked"] or capability not in p.capabilities or target_project not in p.allowed_targets: continue
            row=self.store.db.execute("SELECT * FROM af05_sessions WHERE worker_id=?",(p.worker_id,)).fetchone()
            if not row or row["state"]!="AUTHENTICATED" or n-row["last_heartbeat"]>p.heartbeat_sla: continue
            status=self.store.worker_status(p.worker_id,now=n)
            if status["status"]=="AVAILABLE" and status["active_lease_count"]<min(status["capacity"],row["capacity"]): result.append((p.worker_id,row["session_id"]))
        return sorted(result)

    def dispatch(self,task,lease,*,session_id,now):
        n=self.store.now(now); worker=identifier(lease.get("worker_id"),"worker_id"); tid=identifier(lease.get("task_id"),"task_id"); lid=identifier(lease.get("lease_id"),"lease_id"); session=self.store.db.execute("SELECT * FROM af05_sessions WHERE worker_id=?",(worker,)).fetchone(); current=self.store.task(tid)
        if not session or session["state"]!="AUTHENTICATED" or session["session_id"]!=session_id or current["state"]!="LEASED" or current["assigned_worker_id"]!=worker or current["lease_id"]!=lid or current["lease_expires_at"]<=n or task.get("capability")!=current["capability"] or task.get("target_project")!=current["target_project"]: raise BlockedError("dispatch authority unavailable")
        did=hashlib.sha256(f"AF05|{tid}|{worker}|{session_id}|{lid}".encode()).hexdigest(); existing=self.store.db.execute("SELECT * FROM af05_dispatches WHERE dispatch_id=?",(did,)).fetchone()
        if existing: return DispatchEnvelope(did,tid,worker,session_id,lid,existing["lease_expires_at"],existing["capability"],existing["target_project"],AF05_PROTOCOL_VERSION)
        envelope=DispatchEnvelope(did,tid,worker,session_id,lid,current["lease_expires_at"],current["capability"],current["target_project"],AF05_PROTOCOL_VERSION); body=asdict(envelope); body["message_type"]="DISPATCH"; self.transport.write_outbound(did,body)
        self.store.db.execute("INSERT INTO af05_dispatches VALUES(?,?,?,?,?,?,?,?,?,0,0,NULL)",(did,tid,worker,session_id,lid,current["lease_expires_at"],current["capability"],current["target_project"],AF05_PROTOCOL_VERSION)); self.store.audit(tid,"DISPATCHED",n,f"worker={worker};session={session_id};lease={lid}"); return envelope

    def _bound(self,frame):
        did=identifier(frame.get("dispatch_id"),"dispatch_id"); row=self.store.db.execute("SELECT * FROM af05_dispatches WHERE dispatch_id=?",(did,)).fetchone()
        if not row or any(frame.get(k)!=row[k] for k in ("task_id","worker_id","session_id","lease_id")): raise BlockedError("dispatch binding mismatch")
        return row

    def acknowledge(self,frame,*,now):
        n,p,row,seq,observed,mid=self._message("ACK",frame,now=now); dispatch=self._bound(frame)
        if dispatch["acknowledged"]: raise BlockedError("ack replay")
        self._accept(mid,p.profile.worker_id,row["session_id"],seq,"ACK",n); self.store.start_with_ack(dispatch["task_id"],p.profile.worker_id,dispatch["lease_id"],ack_details=f"signed_session={row['session_id']}",now=n); self.store.db.execute("UPDATE af05_dispatches SET acknowledged=1,ack_at=? WHERE dispatch_id=?",(observed,dispatch["dispatch_id"]))

    def result(self,frame,*,now):
        n,p,row,seq,observed,mid=self._message("RESULT",frame,now=now); dispatch=self._bound(frame)
        if not dispatch["acknowledged"] or dispatch["result_received"] or dispatch["lease_expires_at"]<=n or frame.get("status")!="SUCCEEDED": raise BlockedError("result out of order, expired or unsupported")
        eid=identifier(frame.get("evidence_id"),"evidence_id"); digest=frame.get("evidence_sha256")
        if not isinstance(digest,str) or len(digest)!=64 or any(ch not in "0123456789abcdef" for ch in digest): raise BlockedError("invalid evidence digest")
        if hashlib.sha256(self.transport.resolve_evidence(eid)).hexdigest()!=digest: raise BlockedError("evidence digest mismatch")
        self._accept(mid,p.profile.worker_id,row["session_id"],seq,"RESULT",n); self.store.submit_result(dispatch["task_id"],p.profile.worker_id,dispatch["lease_id"],evidence_id=eid,sha256=digest,now=n); self.store.db.execute("UPDATE af05_dispatches SET result_received=1 WHERE dispatch_id=?",(dispatch["dispatch_id"],))

    def revoke(self,worker_id):
        worker=identifier(worker_id,"worker_id")
        if not self.store.db.execute("UPDATE af05_profiles SET revoked=1 WHERE worker_id=?",(worker,)).rowcount: raise BlockedError("unknown worker")
        self.store.db.execute("UPDATE af05_sessions SET state='REVOKED' WHERE worker_id=?",(worker,))

    def session_projection(self,*,now):
        n=self.store.now(now); rows=[]
        for item in self.registry.all():
            p=item.profile; durable=self.store.db.execute("SELECT revoked FROM af05_profiles WHERE worker_id=?",(p.worker_id,)).fetchone(); session=self.store.db.execute("SELECT * FROM af05_sessions WHERE worker_id=?",(p.worker_id,)).fetchone(); revoked=p.revoked or bool(durable and durable["revoked"])
            status="REVOKED" if revoked else "UNAUTHENTICATED" if not session else "REAUTH_REQUIRED" if session["state"]=="REAUTH_REQUIRED" else "STALE" if n-session["last_heartbeat"]>p.heartbeat_sla else "AVAILABLE"
            rows.append({"worker_id":p.worker_id,"provider_kind":p.worker_kind,"status":status,"session_status":session["state"] if session else "UNAUTHENTICATED","freshness":None if not session else max(0,n-session["last_heartbeat"]),"capacity":None if not session else session["capacity"],"verification_scope":AUTHENTICATION_SCOPE if session and session["state"]=="AUTHENTICATED" and not revoked else "UNKNOWN","key_fingerprint":item.fingerprint,"transport_state":"LOCAL_DURABLE_SPOOL","revocation_state":"REVOKED" if revoked else "ENABLED","last_signed_sequence":None if not session else session["last_sequence"],"last_message_id":None if not session else session["last_message_id"]})
        return rows

    def dispatch_projection(self):
        rows=[]
        for row in self.store.db.execute("SELECT * FROM af05_dispatches ORDER BY dispatch_id"):
            item=dict(row)
            item["state"]="RUNNING" if item["acknowledged"] else "DISPATCHED"
            rows.append(item)
        return rows

    def verified_session_binding(self,worker_id,session_id,*,now):
        try:
            profile=self._trusted(worker_id)
        except BlockedError:
            return False
        row=self.store.db.execute("SELECT * FROM af05_sessions WHERE worker_id=?",(worker_id,)).fetchone()
        return bool(row and row["state"]=="AUTHENTICATED" and row["session_id"]==session_id
                    and row["profile_digest"]==profile.digest and row["key_id"]==profile.profile.key_id
                    and row["last_heartbeat"]<=now+1 and now-row["last_heartbeat"]<=profile.profile.heartbeat_sla)
