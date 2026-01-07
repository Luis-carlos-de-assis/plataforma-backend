import os
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine, Column, Integer, String, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from typing import List, Optional

# --- Configuração do Banco de Dados ---
# Pega o endereço do banco de dados da "etiqueta" de ambiente.
DATABASE_URL = os.getenv("DATABASE_URL")

# Se a etiqueta não existir, usa um banco de dados local sqlite para emergências.
if DATABASE_URL is None:
    DATABASE_URL = "sqlite:///./fallback.db"

# Cria o "motor" que conecta ao banco de dados.
engine = create_engine(DATABASE_URL)

# Cria uma "fábrica de sessões" para conversar com o banco de dados.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# A base para todos os nossos modelos de tabela.
Base = declarative_base()

# --- Modelos de Tabela (A Planta do nosso Depósito) ---

class Conta(Base):
    __tablename__ = "contas"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    # Em um projeto real, a senha seria um hash seguro.
    senha_simplificada = Column(String, nullable=False)
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

# --- Schemas Pydantic (Os "Formulários" da nossa API) ---

class ItemConhecimentoCreate(BaseModel):
    categoria: str
    nome: str
    dados_json: dict
    agente_id: int

class ItemConhecimentoSchema(ItemConhecimentoCreate):
    id: int
    class Config:
        orm_mode = True

# --- Funções de Dependência ---

def get_db():
    """Função para fornecer uma sessão de banco de dados para cada requisição."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Criação da Aplicação FastAPI ---

app = FastAPI(
    title="Plataforma de Agentes Manus",
    description="API para gerenciar agentes de IA genéricos e suas bases de conhecimento.",
    version="1.0.0"
)

# --- Endpoints da API ---

@app.get("/", tags=["Status"])
def read_root():
    """Verifica se a API está no ar."""
    return {"status": "Plataforma de Agentes Manus está no ar!"}

@app.post("/itens-conhecimento/", response_model=ItemConhecimentoSchema, tags=["Conhecimento"])
def create_item_conhecimento(item: ItemConhecimentoCreate, db: Session = Depends(get_db)):
    """
    Cria um novo item de conhecimento para um agente.
    Este é um endpoint genérico para adicionar qualquer tipo de dado
    (sabores, planos, FAQs, etc.) a um agente.
    """
    # Verifica se o agente existe (simplificado)
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

@app.get("/agentes/{agente_id}/conhecimento/", response_model=List[ItemConhecimentoSchema], tags=["Conhecimento"])
def get_itens_por_categoria(agente_id: int, categoria: str, db: Session = Depends(get_db)):
    """
    Busca todos os itens de conhecimento de um agente para uma categoria específica.
    Ex: /agentes/1/conhecimento/?categoria=Sabores
    """
    itens = db.query(ItemConhecimento).filter(
        ItemConhecimento.agente_id == agente_id,
        ItemConhecimento.categoria == categoria
    ).all()
    return itens

# --- Outros endpoints (contas, agentes, etc.) seriam adicionados aqui ---

