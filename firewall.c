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

    
    if (argc > 1) { // Verifica se o usuário passou um argumento ao executar 
        strncpy(tun_name, argv[1], IFNAMSIZ - 1); // Copia o nome informado para tun_name pra não dar overflow
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

        if (iph->version == 4) { // filtra apenas pacotes IPv4, ignorando outros protocolos (ex: IPv6, ARP, etc)
            // Arrays temporários para guardar os endereços IP convertidos em texto (INET_ADDRSTRLEN = tamanho de 16 bytes para IPv4)
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN); // Converte os 32 bits do IP de origem (saddr = Source IP) para string.
            
            inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);// Converte os 32 bits do IP de destino (daddr = Destination IP) para string.

            printf("[SIMPLETUN] Lidos %d bytes | %s -> %s | Proto: %d\n", // printa no terminal a quantidade de bytes lidos, o IP de origem
                   nread, src_ip, dst_ip, iph->protocol);                 // o IP de destino e o protocolo do pacote
        }
    }

    close(tun_fd);
    return 0;
}