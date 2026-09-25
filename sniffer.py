import sys
import logging
import argparse
import sqlite3
import queue
import threading
import time
from scapy.all import get_if_list, conf

# Redirecionado para stdout para garantir que os logs não fiquem presos no buffer do SO quando a aplicação for empacotada no Docker.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Constantes globais
DB_PATH = "traffic_stats.db"
PACKET_QUEUE = queue.Queue(maxsize=10000) # Limite para evitar Out Of Memory caso o throughput de rede sufoque o I/O de disco.
STOP_EVENT = threading.Event() # Mecanismo global non-blocking para matar as threads filhas graciosamente no CTRL+C.

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        # O modo WAL (Write-Ahead Logging) desativa o file-level lock padrão do SQLite.
        # Permite leitura das estatísticas simultânea à escrita de pacotes em disco.
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS captured_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                size INTEGER
            )
        ''')

        # B-Tree Indexes reduzem consultas O(N) para O(log N). 
        # Isso evita derretimento de CPU e lentidão quando as consultas de Top 5 IPs rodarem em bases com milhões de linhas.
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON captured_packets(src_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON captured_packets(dst_ip)")

        conn.commit()
        conn.close()
        logger.info(f"Banco de dados inicializado em '{DB_PATH}' com modo WAL ativado.")
    except Exception as e:
        logger.critical(f"Falha letal ao criar banco de dados: {e}")
        sys.exit(1)

def db_writer_worker():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    while not STOP_EVENT.is_set():
        batch = []
        try:
            # Inserção em batch (lotes de 100): reduz drasticamente o overhead de abrir/fechar transações no disco.
            while len(batch) < 100:
                pkt = PACKET_QUEUE.get(timeout=1)
                batch.append((pkt['src_ip'], pkt['dst_ip'], pkt['protocol'], pkt['size']))
        except queue.Empty:
            pass # Timeout estourou porque a fila tá vazia. Foda-se, segue o baile e commita o que já juntou.
        except Exception as e:
            logger.error(f"Erro ao retirar evento da fila de memoria: {e}")

        if batch:
            try:
                cursor.executemany('''
                    INSERT INTO captured_packets (src_ip, dst_ip, protocol, size)
                    VALUES (?, ?, ?, ?)
                ''', batch)
                conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Falha grave de I/O ao persistir o batch no SQLite: {e}")

    conn.close()
    logger.info("Consumidor do SQLite desligado com seguranca.")

def resolve_interface(target_iface):
    """
    Valida a existência da placa de rede no SO antes de engatilhar o motor de captura.
    """
    try:
        available_ifaces = get_if_list()
        
        # Fallback essencial porque o get_if_list() do Scapy no Windows frequentemente buga e retorna lista vazia dependendo do driver NDIS.
        if not available_ifaces:
            available_ifaces = [iface.name for iface in conf.ifaces.values()]
            
        # Fallback 2: Se ainda estiver vazio (ex: sem Npcap), tenta buscar direto da API do Windows
        if not available_ifaces and sys.platform.startswith('win'):
            from scapy.arch.windows import get_windows_if_list
            available_ifaces = [iface["name"] for iface in get_windows_if_list()]

        if target_iface in available_ifaces:
            logger.info(f"Interface '{target_iface}' validada com sucesso no sistema.")
            return target_iface
        
        # Previne que o script continue rodando cego e exploda o log de erros do Scapy.
        logger.error(f"Interface '{target_iface}' nao encontrada.")
        logger.error(f"Interfaces disponiveis no seu SO: {', '.join(available_ifaces)}")
        sys.exit(1)
        
    except Exception as e:
        logger.critical(f"Falha catastrofica ao enumerar interfaces de rede: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analisador de Trafego de Rede (Challenge Mercado Livre)")
    parser.add_argument("-i", "--interface", required=True, help="Interface de rede para escuta (ex: eth1, Wi-Fi)")
    args = parser.parse_args()

    active_iface = resolve_interface(args.interface)
    logger.info(f"Motor engatilhado para escutar a interface: {active_iface}")

    init_db()

    # Inicia a thread que consome os dados em background
    writer_thread = threading.Thread(target=db_writer_worker, daemon=True)
    writer_thread.start()

    try:
        # Mantenha a thread principal viva artificialmente por enquanto, pois o Scapy ainda nao ta aqui
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Recebido CTRL+C. Iniciando desligamento coordenado...")
        STOP_EVENT.set()
        writer_thread.join()
        logger.info("Processo finalizado sem corrupcao de disco.")
        sys.exit(0)
