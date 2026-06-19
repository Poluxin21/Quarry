# Quarry

**Ferramenta de análise de jogos e software, em Rust, com interface gráfica.**
Um "Burp Suite para software": scanner/editor de memória (estilo Cheat Engine)
na seção **General Exploring**, e proxy de interceptação HTTPS — histórico,
intercept, repeater e match & replace — na seção **Kernel Exploring** (que não
toca no processo e funciona mesmo com anti-cheat kernel).

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
| **Proxy HTTPS** *(Kernel Exploring)* | Proxy de interceptação com CA própria: **Histórico**, **Intercept** (pausar/editar/forward), **Repeater** e **Match & Replace**. Não toca no processo. Veja [Proxy HTTPS](#proxy-https-kernel-exploring). |

> O Quarry separa as funções em duas seções: **General Exploring** (acessa o
> processo: busca, pointer scan, assembler, injeção) e **Kernel Exploring**
> (não toca no processo: proxy HTTPS), com detecção de anti-cheat que bloqueia a
> injeção e roteia para a seção segura quando detecta um anti-cheat kernel.

## Por que pointer scan importa

O endereço de um valor (ex: a vida) muda toda vez que o jogo é reaberto. O que
**não** muda é o caminho de ponteiros, ancorado em um módulo do processo
(`game.exe`, uma DLL). O Quarry monta um mapa reverso de ponteiros e faz uma
busca a partir do alvo até encontrar uma âncora estática, gerando cadeias que
funcionam de forma confiável entre execuções.

## Requisitos

- Windows (x64)
- [Rust](https://www.rust-lang.org/tools/install) 1.75 ou superior

> O pointer scan e a injeção assumem ponteiros de **8 bytes (x64)**. Compile como
> x64 para alvos x64. Suporte a processos 32-bit está no roadmap.

## Compilar e rodar

```powershell
git clone https://github.com/Poluxin21/quarry.git
cd quarry
cargo run --release
```

Use `--release` para que a varredura de memória fique muito mais rápida.

> Para anexar à maioria dos jogos é preciso rodar o Quarry **como
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
  anticheat.rs detecção de anti-cheat e roteamento Kernel/General
  proxy.rs     proxy HTTPS de interceptação (MITM com CA própria)
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

## Proxy HTTPS (Kernel Exploring)

A seção **Kernel Exploring** traz um proxy de interceptação estilo Burp que
**não toca no processo** — funciona com qualquer alvo, inclusive sob anti-cheat
kernel. Ele intercepta apenas tráfego **HTTP(S)** (login, loja, matchmaking,
APIs); o tráfego de jogo em tempo real (UDP/binário próprio) não passa por aqui.

### 1. Iniciar o proxy

Aba **Proxy HTTPS** → defina a porta (padrão `8080`) → **Iniciar**. Na primeira
execução o Quarry gera, no diretório de trabalho:

- **`quarry-ca.pem`** — o certificado da CA (é este que você instala);
- **`quarry-ca.key.pem`** — a chave privada da CA (**mantenha em segredo, nunca
  compartilhe**: quem tiver ela consegue forjar HTTPS para quem confia na sua CA).

### 2. Instalar a CA (`quarry-ca.pem`)

Para ler HTTPS o proxy faz MITM: apresenta ao alvo um certificado *daquele host*
assinado pela sua CA. O cliente só aceita se **confiar na CA** — por isso a
instalação. Sem ela, o TLS quebra com erro de certificado.

```powershell
# Por usuário (não precisa de admin) — basta se o jogo roda com o seu usuário:
certutil -addstore -user Root quarry-ca.pem

# Para a máquina inteira (precisa de admin):
certutil -addstore Root quarry-ca.pem
```

Ou pela interface gráfica: renomeie para `quarry-ca.crt`, duplo-clique →
*Instalar Certificado* → *Autoridades de Certificação Raiz Confiáveis*.

Quando terminar, **remova a CA** (recomendado — é um root CA poderoso):

```powershell
certutil -delstore -user Root "Quarry Proxy CA"
```

### 3. Apontar o jogo para o proxy

O proxy escuta em `127.0.0.1:<porta>`. Para mirar **só um jogo/processo**:

| Método | Mira 1 processo? | Como |
|--------|------------------|------|
| **Proxifier / ProxyCap** | ✅ Sim (recomendado) | Crie uma regra `jogo.exe → proxy HTTP 127.0.0.1:8080`. Força o TCP daquele executável pelo proxy mesmo que o jogo não tenha configuração de proxy. |
| Proxy do sistema (Configurações → Rede → Proxy) | ❌ Pega tudo | Rápido para teste amplo, mas muitos jogos ignoram o proxy do sistema. |
| `HTTP_PROXY` / `HTTPS_PROXY` | ⚠️ Só se o app respeitar | Útil para launchers Chromium e SDKs; jogos raramente honram. |

Com a CA instalada e o tráfego apontado, o **Histórico** enche com as
requisições; ligue o **Intercept** para pausar/editar antes de enviar (botão
direito no *Forward* para interceptar também a resposta), use o **Repeater**
para reenviar requisições editadas, ou crie regras automáticas em
**Match & Replace**.

### Limitações

- **Certificate pinning**: vários jogos competitivos ignoram a trust store e só
  aceitam o próprio certificado — o MITM falha mesmo com a CA instalada.
- **Tráfego não-HTTP** (a maior parte do gameplay, em UDP) não passa por um proxy
  HTTP e não aparece aqui.

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

Source-available **proprietária** — o código é público para estudo, pesquisa de
segurança e contribuição, mas a propriedade do Quarry é do autor (modelo
semelhante ao Burp Suite). Veja [LICENSE](LICENSE). Uso somente contra alvos
próprios ou autorizados.
