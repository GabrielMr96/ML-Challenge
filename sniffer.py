import sys
import logging
import argparse
from scapy.all import get_if_list, conf

# Redirecionado para stdout para garantir que os logs não fiquem presos no buffer do SO quando a aplicação for empacotada no Docker.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

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
    # O motor de captura e o banco de dados entram no proximo passo
