from pydantic import BaseModel
from typing import Optional

# --- Adicione esta classe de modelo perto do topo do arquivo, junto com as outras classes Pydantic ---
# Se você já tem uma classe ItemConhecimentoBase ou similar, pode adicionar os campos opcionais a ela.
# Para garantir, vamos criar uma específica para atualização.
class ItemConhecimentoUpdate(BaseModel):
    nome: Optional[str] = None
    conteudo: Optional[str] = None
    tipo: Optional[str] = None
    # O conhecimento_id (categoria) não costuma ser alterado, mas podemos adicionar se necessário.

# --- Adicione este endpoint ao FINAL do arquivo ---
@app.put("/itens-conhecimento/{item_id}", response_model=schemas.ItemConhecimento)
def atualizar_item_conhecimento(item_id: int, item_atualizado: ItemConhecimentoUpdate, db: Session = Depends(get_db), usuario_id: int = Depends(get_current_user)):
    # Busca o item existente
    item_query = db.query(models.ItemConhecimento).filter(models.ItemConhecimento.id == item_id)
    item_db = item_query.first()

    # Verifica se o item existe
    if not item_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Item com id {item_id} não encontrado")

    # Verifica a permissão do usuário
    conhecimento_pai = db.query(models.Conhecimento).filter(models.Conhecimento.id == item_db.conhecimento_id).first()
    if conhecimento_pai.conta_id != usuario_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Não tem permissão para atualizar este item")

    # Converte os dados recebidos para um dicionário, excluindo os que não foram enviados
    update_data = item_atualizado.dict(exclude_unset=True)
    
    # Se não houver dados para atualizar, apenas retorna o item como está
    if not update_data:
        return item_db

    # Atualiza o item no banco de dados com os novos dados
    item_query.update(update_data, synchronize_session=False)
    db.commit()
    
    # Recarrega o item do banco para retornar os dados atualizados
    db.refresh(item_db)
    
    return item_db
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (JSON, Column, ForeignKey, Integer, String,
                        create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

SECRET_KEY = "uma-chave-secreta-muito-forte-e-dificil-de-adivinhar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

oauth2_scheme = HTTPBearer()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./fallback.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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

class LoginRequest(BaseModel):
    email: str
    password: str

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

def authenticate_user(db: Session, email: str, password: str):
    user = get_conta(db, email=email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
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

app = FastAPI(
    title="Plataforma de Agentes Manus",
    description="API para gerenciar agentes de IA genéricos e suas bases de conhecimento.",
    version="1.0.0",
    debug=True,
    reload=True
)

origins = [
    "http://localhost:3000",
    "https://plataforma-frontend-sooty.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
 )

@app.post("/token", response_model=Token, tags=["Autenticação"])
async def login_for_access_token(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, email=login_data.email, password=login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/contas/", response_model=ContaSchema, tags=["Contas"])
def create_conta(conta: ContaCreate, db: Session = Depends(get_db)):
    db_conta = get_conta(db, email=conta.email)
    if db_conta:
        raise HTTPException(status_code=400, detail="Email já registrado")
    
    hashed_password = get_password_hash(conta.password)
    db_user = Conta(email=conta.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/contas/me/", response_model=ContaSchema, tags=["Contas"])
async def read_users_me(current_user: Conta = Depends(get_current_user)):
    return current_user

@app.get("/", tags=["Status"])
def read_root():
    return {"status": "Plataforma de Agentes Manus está no ar!"}


@app.delete("/itens-conhecimento/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def deletar_item_conhecimento(item_id: int, db: Session = Depends(get_db), usuario_id: int = Depends(get_current_user)):
    # Primeiro, busca o item no banco de dados
    item_query = db.query(models.ItemConhecimento).filter(models.ItemConhecimento.id == item_id)
    item = item_query.first()

    # Verifica se o item existe
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Item com id {item_id} não encontrado")

    # Verifica se o item pertence à conta do usuário logado
    # (Importante para segurança em um ambiente multi-usuário)
    conhecimento_pai = db.query(models.Conhecimento).filter(models.Conhecimento.id == item.conhecimento_id).first()
    if conhecimento_pai.conta_id != usuario_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Não tem permissão para deletar este item")

    # Se tudo estiver certo, deleta o item e salva a mudança
    item_query.delete(synchronize_session=False)
    db.commit()

    # Retorna uma resposta vazia, indicando sucesso
    return Response(status_code=status.HTTP_204_NO_CONTENT)



