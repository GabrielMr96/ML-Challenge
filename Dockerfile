# A versão slim remove dependências desnecessárias do Debian, reduzindo drasticamente a superfície de ataque e o tempo de build.
FROM python:3.11-slim

WORKDIR /app

# libpcap-dev e gcc são obrigatórios para compilar os bindings em C que o Scapy usa para se comunicar direto com a placa de rede.
# O rm -rf /var/lib/apt/lists/* na mesma instrução RUN impede que os índices do apt fiquem salvos no layer do Docker, economizando preciosos megabytes.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Usar cache num container descartável é inútil. --no-cache-dir mantém a imagem limpa.
RUN pip install --no-cache-dir scapy==2.5.0

COPY sniffer.py .

# O ENTRYPOINT trava o container para rodar apenas o script Python. O CMD fornece o argumento padrão (-i eth0), mas permite que quem execute o container sobrescreva passando no final do comando docker run.
ENTRYPOINT ["python", "sniffer.py"]
CMD ["-i", "eth0"]
