# OpenCE

**Scanner e editor de memória open-source, em Rust, com interface gráfica.**
Uma alternativa gratuita ao Cheat Engine para analisar a memória de um processo,
procurar valores, alterá-los e injetar código — com foco em ser simples de usar.

> ⚠️ **Uso responsável.** Esta ferramenta é para jogos **single-player**, seus
> próprios programas e estudo de engenharia reversa. **Não use em jogos online
> ou competitivos** com anti-cheat (BattlEye, EAC, VAC, etc.): além de violar os
> termos de uso e resultar em banimento, esses sistemas protegem o processo e
> podem travar a aplicação. Use por sua conta e risco.

---

## Recursos

| Aba | O que faz |
|-----|-----------|
| **Busca** | First/Next scan em thread de fundo (com barra de progresso e cancelar). Tipos `i8`–`u64`, `f32`, `f64` e **strings** (UTF-8/ASCII e UTF-16/Unicode). Comparações: valor exato, maior/menor, mudou, não mudou, aumentou, diminuiu. |
| **Cheat Table** | Salva endereços, mostra o valor em tempo real, escreve e **congela** valores. |
| **Pointer Scan** | Encontra cadeias de ponteiros estáveis (`["game.exe"+1A2B]+10+8`) que sempre levam ao endereço, mesmo após reiniciar o jogo — e as resolve dinamicamente. |
| **Auto Assembler** | Scripts estilo Cheat Engine (`[ENABLE]`/`[DISABLE]`): `aobscanmodule`, `alloc` de code cave perto do alvo, `label`, `db`, `jmp`/`call`/`jmp64`, `dq`/`dd`, `dealloc`. Aplica e desfaz patches. |
| **Injeção** | Lista módulos, AOB scan (com curinga `??`), patch de bytes, NOP e injeção de DLL (`LoadLibraryW` + `CreateRemoteThread`). |

## Por que pointer scan importa

O endereço de um valor (ex: a vida) muda toda vez que o jogo é reaberto. O que
**não** muda é o caminho de ponteiros, ancorado em um módulo do processo
(`game.exe`, uma DLL). O OpenCE monta um mapa reverso de ponteiros e faz uma
busca a partir do alvo até encontrar uma âncora estática, gerando cadeias que
funcionam de forma confiável entre execuções.

## Requisitos

- Windows (x64)
- [Rust](https://www.rust-lang.org/tools/install) 1.75 ou superior

> O pointer scan e a injeção assumem ponteiros de **8 bytes (x64)**. Compile como
> x64 para alvos x64. Suporte a processos 32-bit está no roadmap.

## Compilar e rodar

```powershell
git clone https://github.com/Poluxin21/opence.git
cd opence
cargo run --release
```

Use `--release` para que a varredura de memória fique muito mais rápida.

> Para anexar à maioria dos jogos é preciso rodar o OpenCE **como
> Administrador**.

## Como usar (exemplo rápido)

1. Clique em **Selecionar processo** e escolha o alvo (ou abra a Calculadora
   para testar sem jogo).
2. Na aba **Busca**, digite um valor que você vê na tela e clique **First Scan**.
3. Mude o valor no jogo, ajuste a comparação e clique **Next Scan** para
   restringir até sobrar o endereço certo.
4. Clique em **+ tabela** para salvá-lo. Na Cheat Table você pode **escrever** ou
   **congelar** o valor.
5. (Opcional) Clique em **pointer scan deste endereço** para achar uma cadeia
   estável e adicioná-la à tabela — assim o cheat continua funcionando depois de
   reabrir o jogo.

## Estrutura do projeto

```
src/
  main.rs      GUI (egui/eframe), cheat table e thread de freeze
  process.rs   enumerar e abrir processos
  memory.rs    ler/escrever memória e enumerar regiões
  value.rs     tipos de valor (parse/format)
  scan.rs      motor de busca (first/next scan)
  pointer.rs   pointer scanner (busca reversa de cadeias)
  assembler.rs auto assembler (scripts de code cave / patch)
  inject.rs    módulos, AOB scan, patch/NOP, injeção de DLL
```

## Auto Assembler

Exemplo de script (god mode trocando a instrução que tira vida por um code cave):

```
[ENABLE]
aobscanmodule(inject, jogo.exe, 89 83 A4 00 00 00)
alloc(newmem, 0x1000, inject)

newmem:
  db 89 83 A4 00 00 00   // instrução original
  jmp return

inject:
  jmp newmem
  nop                    // completa o tamanho da instrução original
return:

[DISABLE]
inject:
  db 89 83 A4 00 00 00   // restaura os bytes originais
dealloc(newmem)
```

Números: `0x..` ou `$..` = hex, sem prefixo = decimal. Para instruções que o
montador não gera, use `db` com os bytes crus.

## Roadmap

- [ ] Salvar/carregar a cheat table em arquivo
- [ ] Scan de "valor inicial desconhecido"
- [ ] Suporte a ponteiros de 32-bit
- [ ] AOB scan em thread de fundo
- [ ] Montador completo de mnemônicos (hoje o Auto Assembler usa `db` + diretivas)

## Tecnologias

- [Rust](https://www.rust-lang.org/)
- [egui / eframe](https://github.com/emilk/egui) — interface gráfica
- [windows](https://github.com/microsoft/windows-rs) — WinAPI

## Licença

[MIT](LICENSE)
