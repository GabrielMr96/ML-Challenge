# Analisador de Tráfego de Rede (Infra & Sistemas)

Aplicação desenvolvida em Python para captura passiva de tráfego de rede, processamento assíncrono e geração de estatísticas em tempo real, utilizando Scapy e SQLite.

## Decisões Arquiteturais

Para garantir alta disponibilidade e evitar o descarte de pacotes (packet loss) por exaustão de I/O em ambientes de alto volume, a aplicação adota o padrão Produtor-Consumidor:

- **Desacoplamento via Fila (Queue)**: A thread do sniffer captura o pacote em Kernel-space via BPF (`filter="ip"`), monta o dicionário mínimo em memória e o insere em uma fila elástica (`queue.Queue`). Ela nunca acessa o disco.
- **Batch Insert no SQLite**: Uma thread secundária consome a fila e realiza inserções em lote (`executemany`), abrindo apenas uma transação no disco a cada 100 pacotes. Isso reduz o overhead do I/O drasticamente.
- **SQLite em Modo WAL (Write-Ahead Logging)**: Permite que o motor de estatísticas leia o banco de dados exatamente ao mesmo tempo em que a thread consumidora está gravando, sem travamentos (locks).
- **Índices B-Tree**: Foram criados índices explícitos para `src_ip` e `dst_ip`. Os cálculos de "Top 5" com `GROUP BY` operam em tempo logarítmico O(log N) nas consultas SQL, utilizando o motor em C do SQLite em vez de estourar a RAM do Python.
- **Defesa contra OOM**: O Scapy opera com `store=False`, garantindo que a memória RAM não seja devorada pelo histórico de rede.

## Como Executar

### 1. Build da Imagem

Compile a imagem isolada localmente:

```bash
docker build -t ml-sniffer-app .
```

### 2. Execução Segura (Least Privilege)

Nunca utilize a flag `--privileged` para containers de rede, pois ela concede acesso administrativo root total ao host. Em vez disso, utilizamos as Linux Capabilities modulares:

```bash
docker run -it --rm \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  ml-sniffer-app -i eth0
```

**Anatomia do Comando:**

- `--network host`: Fura a bolha de rede do Docker, permitindo que a aplicação escute as interfaces reais da máquina (eth0, wlan0).
- `--cap-add=NET_RAW`: Dá a autoridade estrita para o Scapy abrir sockets brutos (raw sockets) e farejar a rede.
- `--cap-add=NET_ADMIN`: Permite a interação administrativa com as interfaces lógicas do sistema.
- `-i eth0`: Argumento dinâmico. Substitua pelo nome da sua interface ativa (verifique com `ip a` no host).

### 3. Encerramento Elegante

Pressione `Ctrl+C`. O sinal `SIGINT` é capturado por um evento de sincronização do Python (`threading.Event`), que orienta as threads a descarregarem os buffers restantes no disco de forma segura antes de fechar o banco de dados.

### 4. Visualização de Estatísticas

A aplicação não necessita de painéis externos ou consultas manuais. Uma *daemon thread* independente (motor analítico) faz um *polling* passivo no SQLite a cada **10 segundos** e imprime o relatório consolidado diretamente no console (stdout), exibindo:

- Total absoluto de pacotes capturados.
- Distribuição quantitativa por protocolos.
- Top 5 Endereços IP de Origem (maior volume).
- Top 5 Endereços IP de Destino (maior volume).
