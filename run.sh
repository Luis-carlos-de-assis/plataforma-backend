#!/bin/bash

# Este script agora só inicia o servidor.
# A instalação e a migração do banco de dados serão feitas no Build Command.

echo "--- Iniciando o servidor Uvicorn ---"
uvicorn main:app --host 0.0.0.0 --port $PORT
