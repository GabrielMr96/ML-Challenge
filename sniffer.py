import sys
import logging
import argparse
import sqlite3
import queue
import threading
import time
from datetime import datetime
from scapy.all import get_if_list, conf, sniff, IP, TCP, UDP, ICMP

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

def parse_protocol(packet):
    """
    Padroniza a leitura da Camada 4 OSI.
    Usa fallback no pacote IP para evitar perdas analiticas caso o trafego nao seja TCP/UDP/ICMP.
    """
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif packet.haslayer(IP):
        proto_num = packet[IP].proto
        return f"OTHER({proto_num})"
    return "UNKNOWN"

def process_packet(packet):
    """
    Callback de altissima velocidade acionado pelo kernel via Scapy.
    Delega o I/O imediatamente para a fila assincrona para nao gargalar o motor de captura.
    """
    if IP in packet:
        packet_info = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": parse_protocol(packet),
            "size": len(packet)
        }
        try:
            # put_nowait garante que a thread do sniffer volte a ouvir a placa no microssegundo seguinte.
            PACKET_QUEUE.put_nowait(packet_info)
        except queue.Full:
            # Em cenarios de DDoS ou rajadas brutais, descartamos o pacote na RAM em vez de travar o SO.
            pass

def start_sniffer(interface):
    """
    Engatilha o motor do Scapy com filtragem otimizada.
    """
    logger.info(f"Iniciando interceptacao passiva de pacotes na interface: {interface}")
    try:
        # filter="ip" (Sintaxe BPF) instrui a libpcap a ignorar lixo de Camada 2 (ex: ARP, STP) antes mesmo de subir pro Python, economizando CPU.
        # stop_filter avalia constantemente a flag do evento global para interromper o laço bloqueante do sniff.
        sniff(
            iface=interface,
            filter="ip",
            prn=process_packet,
            store=False,
            stop_filter=lambda x: STOP_EVENT.is_set()
        )
    except Exception as e:
        logger.error(f"Quebra fatal no subsistema de captura do Scapy: {e}")
        STOP_EVENT.set()

def display_statistics():
    """
    Gera estatísticas consolidadas consultando o banco periodicamente.
    """
    while not STOP_EVENT.is_set():
        try:
            # Por que: O sleep fora do processamento alivia a CPU e dá tempo para o banco aglomerar dados estatiscamente relevantes.
            time.sleep(10)
            if STOP_EVENT.is_set():
                break
                
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            logging.info(f"\n--- Estatísticas de Tráfego: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
            
            # Por que: SELECT COUNT(1) consulta os metadados da tabela, tornando-se instantâneo independente do gigantismo do banco.
            cursor.execute("SELECT COUNT(1) FROM captured_packets")
            total = cursor.fetchone()[0]
            logging.info(f"Total de Pacotes Capturados: {total}")
            
            # Por que: Delegar o GROUP BY ao motor em C do SQLite anula o uso de memória RAM do interpretador Python.
            cursor.execute("SELECT protocol, COUNT(1) as cnt FROM captured_packets GROUP BY protocol ORDER BY cnt DESC")
            logging.info("\nDistribuição por Protocolo:")
            for proto, count in cursor.fetchall():
                logging.info(f"  - {proto}: {count} pacotes")
                
            # Por que: A indexação B-Tree transforma a ordenação temporal numa operação logarítmica O(log N).
            cursor.execute("SELECT src_ip, COUNT(1) as cnt FROM captured_packets GROUP BY src_ip ORDER BY cnt DESC LIMIT 5")
            logging.info("\nTop 5 Origens (Mais Tráfego):")
            for idx, (ip, count) in enumerate(cursor.fetchall(), 1):
                logging.info(f"  {idx}. {ip} -> {count} pacotes")
                
            cursor.execute("SELECT dst_ip, COUNT(1) as cnt FROM captured_packets GROUP BY dst_ip ORDER BY cnt DESC LIMIT 5")
            logging.info("\nTop 5 Destinos (Mais Tráfego):")
            for idx, (ip, count) in enumerate(cursor.fetchall(), 1):
                logging.info(f"  {idx}. {ip} -> {count} pacotes")
                
            logging.info("-" * 50)
            
        except sqlite3.Error as e:
            logging.error(f"Erro na extração de estatísticas: {e}")
        finally:
            if 'conn' in locals() and conn:
                conn.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analisador de Trafego de Rede (Challenge Mercado Livre)")
    parser.add_argument("-i", "--interface", required=True, help="Interface de rede para escuta (ex: eth0, Wi-Fi)")
    args = parser.parse_args()

    # Mantendo a validação robusta das placas antes de iniciar
    INTERFACE = resolve_interface(args.interface)

    init_db()
    
    # Por que: Threads daemon são destruídas pelo SO quando o processo pai morre, prevenindo corrupção de transações no SQLite.
    writer_thread = threading.Thread(target=db_writer_worker, daemon=True)
    stats_thread = threading.Thread(target=display_statistics, daemon=True)
    
    writer_thread.start()
    stats_thread.start()
    
    try:
        start_sniffer(INTERFACE)
    except KeyboardInterrupt:
        logging.info("\nSinal SIGINT detectado. Derrubando o boteco e descarregando as filas no disco...")
        STOP_EVENT.set()
        writer_thread.join()
        stats_thread.join()
        sys.exit(0)
