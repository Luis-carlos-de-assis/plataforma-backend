import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (JSON, Column, ForeignKey, Integer, String,
                        create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

# --- Configurações de Segurança ---
# Chave secreta para "assinar" os tokens. Em um projeto real, isso viria de uma variável de ambiente.
SECRET_KEY = "uma-chave-secreta-muito-forte-e-dificil-de-adivinhar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Contexto para hashing de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema do OAuth2 para a documentação da API
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# --- Configuração do Banco de Dados ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./fallback.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Modelos de Tabela (Banco de Dados) ---

class Conta(Base):
    __tablename__ = "contas"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    agentes = relationship("Agente", back_populates="conta")

class Agente(Base):
    __tablename__ = "agentes"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, index=True, nullable=False)
    conta_id = Column(Integer, ForeignKey("contas.id"))
    conta = relationship("Conta", back_populates="agentes")
    itens_conhecimento = relationship("ItemConhecimento", back_populates="agente")

class ItemConhecimento(Base):
    __tablename__ = "itens_conhecimento"
    id = Column(Integer, primary_key=True, index=True)
    categoria = Column(String, index=True, nullable=False)
    nome = Column(String, index=True)
    dados_json = Column(JSON, nullable=False)
    agente_id = Column(Integer, ForeignKey("agentes.id"))
    agente = relationship("Agente", back_populates="itens_conhecimento")


# --- Schemas Pydantic (Formulários da API) ---

class ContaCreate(BaseModel):
    email: str
    password: str

class ContaSchema(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


# --- Funções de Segurança e Dependências ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_conta(db: Session, email: str):
    return db.query(Conta).filter(Conta.email == email).first()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_conta(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


# --- Criação da Aplicação FastAPI ---

app = FastAPI(
    title="Plataforma de Agentes Manus",
    description="API para gerenciar agentes de IA genéricos e suas bases de conhecimento.",
    version="1.0.0"
)


# --- Endpoints da API ---

@app.post("/token", response_model=Token, tags=["Autenticação"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Endpoint de Login. Recebe email (no campo username) e senha.
    Retorna um token de acesso.
    """
    user = get_conta(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/contas/", response_model=ContaSchema, tags=["Contas"])
def create_conta(conta: ContaCreate, db: Session = Depends(get_db)):
    """
    Cria uma nova conta de usuário (registro).
    """
    db_conta = get_conta(db, email=conta.email)
    if db_conta:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(conta.password)
    db_user = Conta(email=conta.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/contas/me/", response_model=ContaSchema, tags=["Contas"])
async def read_users_me(current_user: Conta = Depends(get_current_user)):
    """
    Retorna as informações do usuário atualmente logado.
    """
    return current_user

# --- Endpoints antigos (adaptados para exemplo) ---

class ItemConhecimentoCreate(BaseModel):
    categoria: str
    nome: str
    dados_json: dict
    agente_id: int

class ItemConhecimentoSchema(ItemConhecimentoCreate):
    id: int
    class Config:
        from_attributes = True

@app.get("/", tags=["Status"])
def read_root():
    return {"status": "Plataforma de Agentes Manus está no ar!"}

@app.post("/itens-conhecimento/", response_model=ItemConhecimentoSchema, tags=["Conhecimento"], dependencies=[Depends(get_current_user)])
def create_item_conhecimento(item: ItemConhecimentoCreate, db: Session = Depends(get_db)):
    # Este endpoint agora está protegido. Só usuários logados podem usá-lo.
    agente = db.query(Agente).filter(Agente.id == item.agente_id).first()
    if not agente:
        raise HTTPException(status_code=404, detail="Agente não encontrado")
    
    db_item = ItemConhecimento(
        categoria=item.categoria,
        nome=item.nome,
        dados_json=item.dados_json,
        agente_id=item.agente_id
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item
