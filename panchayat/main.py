import os, random, string, hashlib, hmac, secrets
from datetime import datetime, timedelta
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Text, ForeignKey, UniqueConstraint, select, func
from sqlalchemy.pool import NullPool
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./panchayat.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")
DEFAULT_TITLES = "Panchayat Ratna,Chai Chor,Sabse Zyada Late,Gossip King,Meeting Ka Hero"

engine = create_engine(DB_URL, poolclass=NullPool)  # serverless-friendly
SessionLocal = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    pw_hash: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(30))
    face: Mapped[str] = mapped_column(Text)

class Group(Base):
    __tablename__ = "groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(6), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(40))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    titles: Mapped[str] = mapped_column(Text, default=DEFAULT_TITLES)

class Member(Base):
    __tablename__ = "members"
    __table_args__ = (UniqueConstraint("group_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(10))  # pending | in | declined

class Point(Base):
    __tablename__ = "points"
    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    to_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    from_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    month: Mapped[str] = mapped_column(String(7), index=True)
    reason: Mapped[str] = mapped_column(String(100), default="")
    ts: Mapped[datetime] = mapped_column(default=datetime.utcnow)

class Award(Base):
    __tablename__ = "awards"
    __table_args__ = (UniqueConstraint("group_id", "month", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    month: Mapped[str] = mapped_column(String(7))
    pts: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(60))

class DailyWinner(Base):
    __tablename__ = "daily_winners"
    __table_args__ = (UniqueConstraint("group_id", "day", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    day: Mapped[str] = mapped_column(String(10))
    pts: Mapped[int] = mapped_column(Integer)

Base.metadata.create_all(engine)
app = FastAPI(title="Panchayat")

def get_db():
    with SessionLocal() as db:
        yield db

def cur_month():  # IST
    return (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%Y-%m")

def ist(dt): return dt + timedelta(hours=5, minutes=30)

def finalize_days(db, g):
    """Roz shaam 7 baje (Sunday chhodke) us din ka winner save. Points 7 PM se pehle ke hi count hote hain."""
    now = ist(datetime.utcnow()); today = now.strftime("%Y-%m-%d"); after7 = now.hour >= 19
    done = {d for (d,) in db.execute(select(DailyWinner.day).where(DailyWinner.group_id == g.id).distinct())}
    tally = {}
    for to_id, ts in db.execute(select(Point.to_id, Point.ts).where(Point.group_id == g.id)):
        t = ist(ts)
        if t.weekday() == 6 or t.hour >= 19: continue
        day = t.strftime("%Y-%m-%d")
        if day in done or day > today or (day == today and not after7): continue
        tally.setdefault(day, {}); tally[day][to_id] = tally[day].get(to_id, 0) + 1
    for day, t in tally.items():
        top = max(t.values())
        for uid_, c in t.items():
            if c == top: db.add(DailyWinner(group_id=g.id, user_id=uid_, day=day, pts=c))
    if tally:
        try: db.commit()
        except IntegrityError: db.rollback()

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    h = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
    return f"{salt}${h}"

def check_pw(pw, stored):
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)

def make_token(uid):
    return jwt.encode({"uid": uid, "exp": datetime.utcnow() + timedelta(days=30)}, SECRET, algorithm="HS256")

def me(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    try:
        uid = jwt.decode((authorization or "").replace("Bearer ", ""), SECRET, algorithms=["HS256"])["uid"]
    except Exception:
        raise HTTPException(401, "Login karo")
    u = db.get(User, uid)
    if not u: raise HTTPException(401, "Login karo")
    return u

def udict(u): return {"id": u.public_id, "name": u.name, "face": u.face}

def new_public_id(db):
    while True:
        pid = "PAN-" + "".join(random.choices(string.digits, k=5))
        if not db.scalar(select(User).where(User.public_id == pid)): return pid

def new_code(db):
    while True:
        c = "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=6))
        if not db.scalar(select(Group).where(Group.code == c)): return c

def get_group(db, code):
    g = db.scalar(select(Group).where(Group.code == code.upper()))
    if not g: raise HTTPException(404, "Group nahi mila")
    return g

def membership(db, g, u):
    return db.scalar(select(Member).where(Member.group_id == g.id, Member.user_id == u.id))

def need_member(db, g, u):
    m = membership(db, g, u)
    if not m or m.status != "in": raise HTTPException(403, "Tum is group ke member nahi ho")

def need_owner(g, u):
    if g.owner_id != u.id: raise HTTPException(403, "Sirf owner ye kar sakta hai")

def finalize(db, g):
    """Pichle mahino ke winners ko award de do (idempotent)."""
    months = [m for (m,) in db.execute(select(Point.month).where(Point.group_id == g.id, Point.month < cur_month()).distinct().order_by(Point.month))]
    titles = [t.strip() for t in (g.titles or DEFAULT_TITLES).split(",") if t.strip()] or ["Winner"]
    done = {m for (m,) in db.execute(select(Award.month).where(Award.group_id == g.id).distinct())}
    for i, m in enumerate(months):
        if m in done: continue
        rows = db.execute(select(Point.to_id, func.count()).where(Point.group_id == g.id, Point.month == m).group_by(Point.to_id)).all()
        top = max(c for _, c in rows)
        title = titles[i % len(titles)]
        for uid_, c in rows:
            if c == top: db.add(Award(group_id=g.id, user_id=uid_, month=m, pts=c, title=title))
    db.commit()

def award_dict(db, a, g=None):
    g = g or db.get(Group, a.group_id)
    return {"id": a.id, "month": a.month, "pts": a.pts, "title": a.title, "group": g.name, "code": g.code, "user": udict(db.get(User, a.user_id))}

# ---------- auth ----------
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=6, max_length=100)
    name: str = Field(min_length=1, max_length=30)
    face: str = Field(max_length=300000)

class LoginIn(BaseModel):
    username: str
    password: str

@app.post("/api/register")
def register(b: RegisterIn, db: Session = Depends(get_db)):
    if not b.face.startswith("data:image/"): raise HTTPException(400, "Face photo chahiye")
    if db.scalar(select(User).where(func.lower(User.username) == b.username.lower())):
        raise HTTPException(400, "Ye username le liya gaya hai")
    u = User(public_id=new_public_id(db), username=b.username, pw_hash=hash_pw(b.password), name=b.name.strip(), face=b.face)
    db.add(u); db.commit()
    return {"token": make_token(u.id), "me": udict(u)}

@app.post("/api/login")
def login(b: LoginIn, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(func.lower(User.username) == b.username.lower()))
    if not u or not check_pw(b.password, u.pw_hash): raise HTTPException(401, "Username ya password galat hai")
    return {"token": make_token(u.id), "me": udict(u)}

@app.get("/api/me")
def get_me(u: User = Depends(me)): return udict(u)

# ---------- groups ----------
class NameIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)

class CodeIn(BaseModel):
    code: str

@app.get("/api/groups")
def my_groups(u: User = Depends(me), db: Session = Depends(get_db)):
    rows = db.execute(select(Group, Member.status).join(Member, Member.group_id == Group.id).where(Member.user_id == u.id)).all()
    return [{"code": g.code, "name": g.name, "status": s, "owner": g.owner_id == u.id} for g, s in rows]

@app.post("/api/groups")
def create_group(b: NameIn, u: User = Depends(me), db: Session = Depends(get_db)):
    g = Group(code=new_code(db), name=b.name.strip(), owner_id=u.id)
    db.add(g); db.flush()
    db.add(Member(group_id=g.id, user_id=u.id, status="in")); db.commit()
    return {"code": g.code}

@app.post("/api/groups/join")
def join_group(b: CodeIn, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, b.code)
    if not membership(db, g, u):
        db.add(Member(group_id=g.id, user_id=u.id, status="pending")); db.commit()
    return {"code": g.code}

@app.get("/api/groups/{code}")
def group_detail(code: str, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, code)
    m = membership(db, g, u)
    if not m: raise HTTPException(403, "Tum is group me nahi ho")
    base = {"code": g.code, "name": g.name, "my_status": m.status}
    if m.status != "in": return base
    finalize(db, g)
    finalize_days(db, g)
    cm = cur_month()
    pts = dict(db.execute(select(Point.to_id, func.count()).where(Point.group_id == g.id, Point.month == cm).group_by(Point.to_id)).all())
    members = []
    for mem, usr in db.execute(select(Member, User).join(User, User.id == Member.user_id).where(Member.group_id == g.id)).all():
        members.append({**udict(usr), "status": mem.status, "pts": pts.get(usr.id, 0), "owner": usr.id == g.owner_id})
    feed = []
    for p in db.scalars(select(Point).where(Point.group_id == g.id).order_by(Point.id.desc()).limit(10)):
        feed.append({"from": db.get(User, p.from_id).name, "to": db.get(User, p.to_id).name, "reason": p.reason, "ts": p.ts.isoformat()})
    awards = [award_dict(db, a, g) for a in db.scalars(select(Award).where(Award.group_id == g.id).order_by(Award.month.desc(), Award.id))]
    days = [{"day": w.day, "pts": w.pts, "user": udict(db.get(User, w.user_id))} for w in db.scalars(select(DailyWinner).where(DailyWinner.group_id == g.id).order_by(DailyWinner.day, DailyWinner.id))]
    today = ist(datetime.utcnow()).strftime("%Y-%m-%d")
    return {**base, "today": today, "days": days, "is_owner": g.owner_id == u.id, "titles": g.titles, "month": cm, "me": u.public_id, "members": members, "feed": feed, "awards": awards}

class EditIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=40)
    titles: Optional[str] = Field(None, max_length=500)

@app.patch("/api/groups/{code}")
def edit_group(code: str, b: EditIn, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, code); need_owner(g, u)
    if b.name: g.name = b.name.strip()
    if b.titles is not None: g.titles = b.titles.strip() or DEFAULT_TITLES
    db.commit(); return {"ok": True}

class AnswerIn(BaseModel):
    user: str
    status: str

@app.post("/api/groups/{code}/answer")
def answer(code: str, b: AnswerIn, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, code); need_owner(g, u)
    if b.status not in ("in", "declined"): raise HTTPException(400, "Galat status")
    t = db.scalar(select(User).where(User.public_id == b.user))
    m = t and membership(db, g, t)
    if not m: raise HTTPException(404, "Request nahi mili")
    m.status = b.status; db.commit(); return {"ok": True}

class InviteIn(BaseModel):
    user: str

@app.post("/api/groups/{code}/invite")
def invite(code: str, b: InviteIn, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, code); need_owner(g, u)
    t = db.scalar(select(User).where(User.public_id == b.user.strip().upper()))
    if not t: raise HTTPException(404, "Is ID ka koi user nahi mila")
    m = membership(db, g, t)
    if m: m.status = "in"
    else: db.add(Member(group_id=g.id, user_id=t.id, status="in"))
    db.commit(); return {"ok": True, "name": t.name}

@app.delete("/api/groups/{code}/members/{pid}")
def remove(code: str, pid: str, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, code); need_owner(g, u)
    t = db.scalar(select(User).where(User.public_id == pid))
    if not t or t.id == g.owner_id: raise HTTPException(400, "Owner ko remove nahi kar sakte")
    m = membership(db, g, t)
    if m: db.delete(m); db.commit()
    return {"ok": True}

class PointIn(BaseModel):
    to: str
    reason: str = Field("", max_length=100)

@app.post("/api/groups/{code}/points")
def add_point(code: str, b: PointIn, u: User = Depends(me), db: Session = Depends(get_db)):
    g = get_group(db, code); need_member(db, g, u)
    t = db.scalar(select(User).where(User.public_id == b.to))
    if not t or t.id == u.id: raise HTTPException(400, "Khud ko point nahi de sakte")
    need_member(db, g, t)
    db.add(Point(group_id=g.id, to_id=t.id, from_id=u.id, month=cur_month(), reason=b.reason.strip())); db.commit()
    return {"ok": True}

# ---------- public ----------
@app.get("/api/awards")
def all_awards(db: Session = Depends(get_db)):
    return [award_dict(db, a) for a in db.scalars(select(Award).order_by(Award.month.desc(), Award.id.desc()).limit(200))]

@app.get("/api/users/{pid}")
def public_profile(pid: str, db: Session = Depends(get_db)):
    t = db.scalar(select(User).where(User.public_id == pid.upper()))
    if not t: raise HTTPException(404, "User nahi mila")
    aw = [award_dict(db, a) for a in db.scalars(select(Award).where(Award.user_id == t.id).order_by(Award.month.desc()))]
    return {**udict(t), "awards": aw}

PUBLIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")

@app.get("/")  # local/Docker ke liye; Vercel pe public/ CDN se serve hota hai
def index(): return FileResponse(os.path.join(PUBLIC, "index.html"))
