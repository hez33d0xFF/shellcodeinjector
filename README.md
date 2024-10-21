![Shellcode Injector em ação](test.png)


**Shellcode Injector** 

## Funcionalidade

- Verifica se o arquivo fornecido é um ELF.
- Localiza seções executáveis dentro do arquivo ELF.
- Injeta um shellcode específico em uma seção executável.
- Modifica o ponto de entrada do ELF para redirecionar a execução para o shellcode injetado.

## Shellcode

O shellcode implementado neste projeto realiza as seguintes operações:
1. Cria um socket.
2. Conecta-se a um servidor em `127.0.0.1` na porta `4444`.
3. Executa um shell (`/bin/sh`).

```bash
gcc -o shellcode_injector shellcode_injector.c
```

```bash
./shellcode_injector <arquivo_elf>
```

## Link do VirusTotal

[Link do VirusTotal após a injeção do shellcode](https://www.virustotal.com/gui/file/3c8915d4957fd3e274939cafe43b904208f954b38ac30ef7ac3d97f7f64be1f8?nocache=1)

## To-do list

- [ ] Adicionar suporte para injetar diferentes tipos de shellcode.
- [ ] Obfuscar o shellcode.
- [ ] Adicionar exemplos de uso para diferentes cenários.
- [ ] Implementar a capacidade de reverter a injeção de shellcode

