# Usa uma imagem base oficial do Python
FROM python:3.10-slim

# Instala dependências do sistema necessárias para o libtorrent e compilação
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libboost-all-dev \
    libtorrent-rasterbar-dev \
    && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho
WORKDIR /app

# Instala as dependências Python
# Usamos lbry-libtorrent que é mais compatível com Linux/Docker que o pacote padrão
RUN pip install --no-cache-dir lbry-libtorrent flask mysql-connector-python cryptography werkzeug gunicorn google-generativeai

# Copia o código da aplicação
COPY . .

# Comando para iniciar o servidor
# O Render define a variável de ambiente PORT, que Gunicorn deve usar.
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 4 app:app