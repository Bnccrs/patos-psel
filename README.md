# 🛡️ Firewall em C com Interface TUN & Deep Packet Inspection (DPI)

Projeto de firewall funcional desenvolvido em espaço de usuário (*userspace*) utilizando a linguagem C e a interface de rede virtual **TUN** no Linux. O sistema é capaz de interceptar pacotes IPv4, responder autonomamente a solicitações ICMP (PING) e realizar filtragem de tráfego por IP de destino e palavras proibidas (DPI) nos protocolos TCP e UDP.

---

## 🚀 Funcionalidades

* **Alocação de Interface TUN:** Criação e vínculo com o arquivo de controle `/dev/net/tun`.
* **Filtro de IP de Destino:** Regra de descarte (DROP) dinâmica configurável via CLI (`--block`).
* **Deep Packet Inspection (DPI):** Inspeção do payload de pacotes **TCP** e **UDP** para bloqueio por palavra-chave via CLI (`--word`).
* **Resposta Automatizada a PING (ICMP):** Forjamento de respostas ICMP Echo Reply diretamente na camada do firewall.

---

## 📅 Diário de Desenvolvimento 

Sintetizando... Em Breve...

---

## 🧪 Guia de Testes

Para validar a execução do projeto, utilize dois terminais no Linux:

### Terminal 1 — Compilação e Execução
```bash
# Compilar o código
make

# Iniciar o firewall bloqueando o IP 10.0.0.99 e a palavra "virus"
sudo ./firewall --block 10.0.0.99 --word virus
```
### Terminal 2 — Compilação de Rede e Disparo de Tráfego
```bash
# 1. Ativar a interface tun0
sudo ip link set dev tun0 up

# 2. Atribuir o IP 10.0.0.1/24 à interface
sudo ip addr add 10.0.0.1/24 dev tun0

# 3. Teste de PING normal (ICMP Reply funcional)
ping -c 3 10.0.0.2

# 4. Teste de PING para IP bloqueado (DROP)
ping -c 3 10.0.0.99

# 5. Teste de DPI - Envio de texto normal (Permitido)
echo "mensagem normal" | nc -u -w1 10.0.0.2 8080

# 6. Teste de DPI - Envio de texto contendo palavra proibida (DROP)
echo "mensagem contém virus" | nc -u -w1 10.0.0.2 8080
```
