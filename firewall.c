// Bibliotecas padrão do C e cabeçalhos do Kernel Linux para manipulação de rede
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Para funções de I/O e manipulação de arquivos
#include <fcntl.h> // Para manipulação de arquivos (open, close, etc)
#include <sys/ioctl.h>  // Para manipulação de dispositivos de rede (ioctl)
#include <sys/socket.h> // Para manipulação de sockets
#include <linux/if.h> // Para manipulação de interfaces de rede
#include <linux/if_tun.h> // Para manipulação de interfaces TUN/TAP
#include <netinet/ip.h> // Para manipulação de pacotes IP
#include <netinet/ip_icmp.h> // Para manipulação de pacotes ICMP (ping)
#include <arpa/inet.h> // Para conversão de endereços IP entre binário e string

#define MAX_BLOCKED 100 // Define o tamanho máximo do array de IPs bloqueados

// Função para alocar uma interface TUN
int alocar_tun(char *dev) {
    struct ifreq ifr; // Variável para configurar a placa de rede
    int fd, err; // Variáveis para o "File Descriptor" e para capturar erros

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) { // Abre o arquivo de controle do TUN no Linux e verifica possíveis erros
        perror("Erro ao abrir /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr)); // Zera a estrutura para evitar lixo de memória

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // Define um TUN na camada 3 (IP) sem cabeçalhos extras do kernel

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ); // Se o usuário especificou um nome de interface, copia para a estrutura
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {     // Pega o arquivo 'fd' e configura a interface TUN com o comando 'TUNSETIFF'
        perror("Erro ao criar a interface ioctl(TUNSETIFF)"); //  e verifica possíveis erros
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name); // Copia o nome que o linux deu pra interface criada para a variável 'dev' (isso se o usuário não deu um nome específico)
    return fd; // Retorna o "File Descriptor" que é o ID da interface criada
}

// Checksum para pacotes IPv4
// Função que calcula a verificação de integridade dos pacotes IPv4, retornando o valor do checksum
unsigned short calcular_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;           // Acumulador de 32 bits para evitar overflow durante a soma
    unsigned short oddbyte; // Variável temporária para tratar pacotes com número ímpar de bytes
    short answer;           // Resultado final comprimido em 16 bits

    // Loop para somar os bytes do buffer em pares de 16 bits
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    // Se sobrou 1 byte isolado no final, ajusta e soma ao total
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    // Dobra os bits excedentes de 32 bits de volta para 16 bits (soma de complemento de 1)
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    // Inverte todos os bits (~sum) e retorna o checksum final
    answer = (short)~sum;
    return answer;
}


// Entrada principal do programa recebendo parâmetros
int main(int argc, char *argv[]) {
    // Aloca um vetor de caracteres para definir o nome da interface
    // Define "tun0" como o nome padrão da interface virtual.
    char tun_name[IFNAMSIZ] = "tun0";
    
    int tun_fd; // Variável para armazenar o fd
    
    unsigned char buffer[1500]; // Define um buffer de 1500 bytes para os pacotes IP
    
    int nread; // Armazena a quantidade de bytes lidos a cada pacote entregue pelo sistema operacional

    char blocked_ips[MAX_BLOCKED][INET_ADDRSTRLEN]; // Vetor para armazenar os IPs bloqueados dinamicamente

    int blocked_count = 0; // Contador para o número de IPs bloqueados

    // Varre os argumentos para capturar a flag --block e o nome da interface
    for (int i = 1; i < argc; i++) { // Começa do índice 1 para ignorar o nome do programa (argv[0])
        if (strcmp(argv[i], "--block") == 0 && i + 1 < argc) { // Verifica se a flag --block foi passada e se há um ip seguinte
            if (blocked_count < MAX_BLOCKED) { // Verifica se ainda há espaço no array de IPs bloqueados
                strncpy(blocked_ips[blocked_count], argv[i + 1], INET_ADDRSTRLEN - 1); // Copia o IP para o array de IPs bloqueados
                blocked_ips[blocked_count][INET_ADDRSTRLEN - 1] = '\0'; // Garante que a string esteja terminada com '\0' para evitar overflow
                printf("[CONFIG] IP Bloqueado adicionado: %s\n", blocked_ips[blocked_count]); // Confirma os ips bloqueados no terminal
                blocked_count++; // Incrementa o contador de IPs bloqueados
                i++; // Avança para o próximo argumento (pula o valor do IP)
            }
        } else if (argv[i][0] != '-') {
            // Se o argumento não for uma flag, assume que é o nome da interface 
            strncpy(tun_name, argv[i], IFNAMSIZ - 1);
        }
    }

    tun_fd = alocar_tun(tun_name); // Chama a função pra criar a TUN e retorna o FD para a variável tun_fd
    
    if (tun_fd < 0) { // Verifica se deu algum erro na criação da TUN (fd negativo)
        // Exibe a mensagem de erro e fecha o processo.
        fprintf(stderr, "Erro ao alocar interface %s\n", tun_name);
        exit(1);
    }

    // Se deu certinho, confirma no terminal a criação da interface e exibe o número do File Descriptor obtido
    printf("Interface %s inicializada com sucesso (File Descriptor: %d)\n", tun_name, tun_fd);
    printf("Aguardando pacotes enviados pelo Kernel...\n");

    // Loop infinito para o I/O de pacotes no Userspace.
    while (1) {
        nread = read(tun_fd, buffer, sizeof(buffer)); // A função read() retorna a quantidade de bytes lidos e armazena no buffer.
        
        if (nread < 0) { // Se a leitura retornar valor negativo, ocorreu um erro, então ele fecha a interface.
            perror("Erro ao ler da interface TUN");
            close(tun_fd); // Libera o File Descriptor no sistema operacional antes de fechar.
            exit(1);
        }

        struct iphdr *iph = (struct iphdr *) buffer; // Pointer Casting, ele converte o buffer em ipv4 (struct iphdr)

        if (iph->version == 4) { // Filtra apenas pacotes IPv4, ignorando outros protocolos (ex: IPv6, ARP, etc)
            // Arrays temporários para guardar os endereços IP convertidos em texto (INET_ADDRSTRLEN = tamanho de 16 bytes para IPv4)
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN); // Converte os 32 bits do IP de origem (saddr = Source IP) para string.
            inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN); // Converte os 32 bits do IP de destino (daddr = Destination IP) para string.

            int is_blocked = 0; // Regra de Bloqueio (contador) para verificar se o IP de destino está na lista de bloqueio
            for (int i = 0; i < blocked_count; i++) { // Confere se o IP de destino está na lista de bloqueio
                if (strcmp(dst_ip, blocked_ips[i]) == 0) {
                    is_blocked = 1;
                    break;
                }
            }

            if (is_blocked) { // Se o IP tiver bloqueado, passa pro próximo pacote sem enviar para o Kernel
                printf("[DROP] Pacote destinado a %s foi descartado pelo firewall!\n", dst_ip); // Mensagem de log
                continue; // Descarta o pacote e volta pro topo do loop
            }

            // Exibe os pacotes permitidos que passaram pelo filtro de bloqueio
            printf("[PERMITIDO] Lidos %d bytes | %s -> %s | Proto: %d\n",  // Exibe no terminal os pacotes permitidos
                   nread, src_ip, dst_ip, iph->protocol);

            // Regra de resposta ao PING: verifica se o pacote permitido é do protocolo ICMP
            if (iph->protocol == IPPROTO_ICMP) {
                int ip_hdr_len = iph->ihl * 4; // Calcula o tamanho real do cabeçalho IP em bytes (ihl * 4)

                // Mapeia a estrutura do ICMP apontando para a posição da memória logo após o cabeçalho IP
                struct icmphdr *icmph = (struct icmphdr *)(buffer + ip_hdr_len);

                // Verifica se o pacote é uma solicitação de PING (ICMP Echo Request - Tipo 8)
                if (icmph->type == ICMP_ECHO) {
                    icmph->type = ICMP_ECHOREPLY; // Altera o tipo da mensagem de Requisição (8) para Resposta (0 = ICMP Echo Reply)
                    icmph->checksum = 0; // Zera o checksum do ICMP antes de recalcular

                    int icmp_len = nread - ip_hdr_len; // Recalcula o checksum do ICMP considerando apenas o tamanho total menos a parte do IP
                    icmph->checksum = calcular_checksum((unsigned short *)icmph, icmp_len); // Recalcula o checksum do ICMP após alterar o tipo da mensagem

                    // Inverte os endereços IP (o IP de destino vira a origem e a origem vira o destino)
                    uint32_t temp_ip = iph->saddr;
                    iph->saddr = iph->daddr;
                    iph->daddr = temp_ip;

                    // Zera e recalcula o checksum do cabeçalho IP após alterar os endereços
                    iph->check = 0;
                    iph->check = calcular_checksum((unsigned short *)iph, ip_hdr_len);

                    // Devolve o pacote modificado (resposta de PING) para o Kernel via interface TUN
                    write(tun_fd, buffer, nread); // metodo write() envia o pacote de volta para o Kernel, que então encaminha para a rede
                    printf("  └─> [ICMP REPLY] Resposta de PING enviada de volta para %s!\n", src_ip);
                }
            }
        }
    }

    close(tun_fd);
    return 0;
}