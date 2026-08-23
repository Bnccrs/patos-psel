// Bibliotecas padrão do C e cabeçalhos do Kernel Linux para manipulação de rede
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

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