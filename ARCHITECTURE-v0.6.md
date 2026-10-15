# apkator v0.6 — Arquitetura

Objetivo: sair do "raso" (lista de permissões + grep) para análise com profundidade real,
sem virar MobSF (lento, verboso, feito pra especialista). Princípio: cada feature nova
precisa ser ou mais profunda, ou mais rápida, ou as duas. Nada de peso morto.

Decisões técnicas abaixo são específicas e implementáveis. O que for inviável está
marcado como tal, sem eufemismo.

---

## 1. Data flow mapping: permissão → API → domínio

### O problema
Hoje a ferramenta lista "RECORD_AUDIO" e "api.groq.com" como fatos isolados.
O que importa é a conexão: o microfone alimenta aquele domínio? Isso é o diferencial
contra MobSF, que também não faz isso bem em análise estática pura.

### Abordagem honesta: co-ocorrência com nível de confiança
Taint tracking real (estilo FlowDroid) é **inviável** aqui: exige Soot/JVM, 10+ min
por APK, memória absurda. Não vamos fingir que fazemos isso.

O que fazemos: heurística de co-ocorrência em nível de método, com confiança
explicitada. É o 80/20 que roda em segundos e raramente mente quando diz "method".

### Mecânica específica (eficiente)

**Passo 1 — Tabela permissão → assinaturas smali** (`flows.json`, versionado):
```json
{
  "RECORD_AUDIO": [
    "Landroid/media/MediaRecorder;->start()",
    "Landroid/media/AudioRecord;->startRecording()",
    "Landroid/speech/SpeechRecognizer;->startListening("
  ],
  "CAMERA": [
    "Landroid/hardware/Camera;->open(",
    "Landroid/hardware/camera2/CameraManager;->openCamera("
  ],
  "READ_CONTACTS": ["Landroid/provider/ContactsContract", "content://com.android.contacts"],
  "ACCESS_FINE_LOCATION": [
    "Landroid/location/LocationManager;->requestLocationUpdates(",
    "Lcom/google/android/gms/location/"
  ],
  "READ_PHONE_STATE": [
    "Landroid/telephony/TelephonyManager;->getDeviceId(",
    "Landroid/telephony/TelephonyManager;->getImei("
  ]
}
```

**Passo 2 — Um único grep combinado** acha arquivos candidatos:
```bash
grep -rl -e "pattern1" -e "pattern2" ... smali/ > candidates.txt
```
Um pass, não N greps. Isso poda 95%+ dos arquivos (num APK típico, poucas centenas
de arquivos tocam APIs sensíveis).

**Passo 3 — Parser de chunks de método** (Node, só nos candidatos):
- Lê o arquivo, divide em chunks por `/^\.method /m`.
- Em cada chunk, testa três coisas:
  a. `apiHit`: alguma assinatura da tabela (regex escapada, match literal).
  b. `domains`: `/const-string[^,]+,\s*"https?:\/\/([^"\/]+)/g` → captura domínios.
  c. `netSink`: `/Lokhttp3\/|Lretrofit2\/|Ljava\/net\/HttpURLConnection|Lcom\/android\/volley\//`.
- Se chunk tem `apiHit` + (`domains` ou `netSink`) → flow nível **method**.
- Senão, se o *arquivo* tem `apiHit` num método e `domains`/`netSink` em outro → flow nível **class**.

**Passo 4 — Agregação e output:**
```json
{ "permission": "RECORD_AUDIO",
  "api": "Landroid/speech/SpeechRecognizer;->startListening(",
  "via": "Lcom/orion/assistant/service/voice/VoiceRecognitionService;->onCreate()",
  "domains": ["api.groq.com"],
  "confidence": "method" }
```
No terminal:
```
  DATA FLOWS
    RECORD_AUDIO --[SpeechRecognizer.startListening]--> api.groq.com
      via VoiceRecognitionService.onCreate()  [method]
    CAMERA --[CameraManager.openCamera]--> (no network in scope)  [class]
```

### Bônus barato com a mesma infra: over-declaration
Permissão declarada no manifest mas **zero** hits nas assinaturas correspondentes
no smali → finding: "READ_CONTACTS declared but never used in code".
É sinal de privacidade real (menos permissão = menos risco) e o MobSF não destaca isso.
Custo: zero, os greps já rodaram.

### Limites declarados
- `confidence: method` = mesma função toca API sensível e rede. Forte indício, não prova.
- `confidence: class` = mesma classe, métodos diferentes. Sugestivo, fraco.
- Nunca afirmar "o app envia X para Y". Afirmar "X e Y co-ocorrem em [escopo]".
- Ofuscação pesada (nomes de método ofuscados) degrada `via` mas não quebra `apiHit`
  (chamadas ao framework Android não são ofuscáveis).

---

## 2. AI synthesis layer: findings → narrativa

### Por que
Score + lista de findings não contam história. "Este é um assistente de voz que
transcreve teu áudio via Groq e busca via Perplexity; o acesso a contatos não tem
justificativa visível no código" — isso é o que o usuário leigo entende e o que
torna a ferramenta compartilhável.

### Design: LLM só no final, com input mínimo
Nada de jogar dump bruto no LLM. O input é um **digest compacto** (~400 tokens):

```json
{
  "package": "com.orion.assistant.debug",
  "category": {"guess": "voice-assistant", "confidence": 0.82},
  "flows": [
    {"permission": "RECORD_AUDIO", "api": "SpeechRecognizer.startListening", "domains": ["api.groq.com"], "confidence": "method"},
    {"permission": "CAMERA", "api": "CameraManager.openCamera", "domains": [], "confidence": "class"}
  ],
  "permissions": {"critical": ["RECORD_AUDIO", "CAMERA", "READ_CONTACTS"], "warning": ["SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES"]},
  "domains": ["api.groq.com", "api.openai.com", "api.perplexity.ai"],
  "trackers": [],
  "anomalies": ["READ_CONTACTS unusual for voice-assistant"],
  "top_findings": ["Debuggable enabled in release", "11 exported components"]
}
```

System prompt (~110 tokens, PT):
> "Você é um analista de segurança Android. Dado este resumo estruturado de um APK,
> escreva 3 a 5 frases em português direto explicando o que o app faz e apontando
> o que é suspeito ou anômalo. Sem jargão, sem emoji, sem rodeio."

### Execução
- Modelo: `z-ai/glm-5.3-flash` via `nim.py chat` (confirmado funcionando no ambiente).
- **Atenção técnica**: o GLM 5.3 emite `reasoning_content` antes do `content`.
  Setar `max_tokens: 400` com folga — com limite baixo o output corta no reasoning
  e `content` vem null. Não é bug do nim.py, é comportamento do modelo.
- Flag `--explain` (default **off**): mantém o run padrão rápido e sem custo.
- Cache: `~/.cache/apkator/narrative/<sha256(digest)>.txt` — mesma análise,
  mesma narrativa, zero custo repetido.
- Output: seção `ANALYSIS` após o summary; incluído no `--json` como `narrative`.
- Orçamento: ~500 tokens in, ~150 out por análise. Irrelevante em custo.

---

## 3. Category detection + anomaly

### Detecção (3 sinais, offline-first)
```
score(cat) = 0.4 * keywordHit + 0.4 * permOverlap + 0.2 * apiSignal
```
- **keywordHit**: package/label contém token da categoria
  (`assistant`, `voice` → voice-assistant; `bank`, `nubank` → banking; etc.)
- **permOverlap**: Jaccard entre permissões do app e `expected` da categoria.
- **apiSignal**: APIs distintivas (`SpeechRecognizer` → voice; `CameraX` → camera;
  `ExoPlayer` → media; `BillingClient` → shopping/game).
- Se melhor score < 0.35 → categoria `unknown`, sem anomaly (não inventar).

### Baselines: de onde vêm
`baselines.json` com 10 categorias iniciais:
`voice-assistant, messaging, banking, game, camera, fitness, shopping, social, navigation, utility`.

Cada categoria:
```json
{
  "voice-assistant": {
    "keywords": ["assistant", "voice", "jarvis"],
    "expected": ["RECORD_AUDIO", "INTERNET", "FOREGROUND_SERVICE", "POST_NOTIFICATIONS"],
    "common": ["ACCESS_FINE_LOCATION", "READ_CONTACTS", "BLUETOOTH"],
    "rare": ["READ_SMS", "READ_CALL_LOG", "SEND_SMS", "CAMERA"],
    "apis": ["SpeechRecognizer", "TextToSpeech"]
  }
}
```
Fonte honesta da v1: curadoria manual a partir de dados públicos (stats do
Exodus Privacy, níveis de proteção da documentação Android, pesquisa publicada
sobre uso de permissões por categoria). **Não** é baseline treinada em corpus —
isso é o caminho de evolução (seção 6), não a promessa da v0.6.

### Anomaly
Permissão `critical`/`warning` que cai em `rare` da categoria detectada, ou que
não está em `expected`+`common` → finding:
```
[ANOMALY] READ_CONTACTS is unusual for voice-assistant
```
Severidade: medium por padrão; high se a permissão for `critical` E `rare`.

---

## 4. Otimização: matar o gargalo do decode

### Diagnóstico
Num APK de 129MB: ~60s+ dos ~90s totais é o apktool decodificando, e a maior
fatia disso é o **baksmali** (conversão dex→smali, visível no log como
"Baksmaling classesN.dex"). A fase de análise (greps) é ~20-30s.

### Decisão central: two-tier
| Modo | Comando apktool | Conteúdo | Tempo alvo | Uso |
|------|----------------|----------|------------|-----|
| fast (default) | `apktool d -s` (`--no-src`) | manifest + resources, **sem** baksmali | ~15s | permissões, componentes, manifest checks, domínios de res/assets |
| deep (`--deep`) | `apktool d` (full) | + smali completo | ~90s | flows, secrets, crypto, trackers, over-declaration |

Justificativa: 80% das perguntas ("quais permissões?", "tem debuggable?", "fala com
quais domínios?") não precisam de smali. Quem quer profundidade paga o custo
explicitamente. Isso também resolve a queixa de "lento" sem perder a de "raso" —
são dois modos honestos, não um meio-termo ruim.

Flag `-s/--no-src` confirmada disponível no apktool do ambiente.

### Paralelização da fase de análise
Hoje: greps sequenciais (secrets = 5 greps em loop, crypto, domains, httpCount...).
Mudança:
- Combinar padrões de secrets num único `grep -rl -e ... -e ...`.
- Rodar blocos independentes via `Promise.all`: [secrets+crypto], [domains+http],
  [trackers], [flows]. Economia estimada: 10-15s na fase de análise.
- O parser de flows processa arquivos candidatos em batches (ex: 50 arquivos por
  vez, sem limite de concorrência cego que estoura file descriptors).

### Cache de decode
`~/.cache/apkator/decode/<sha256(apk)>/` — se o diretório existe e tem
`AndroidManifest.xml`, pula o apktool. Efeitos:
- Re-análise do mesmo APK: ~2s.
- `--diff old.apk new.apk`: baseline decodificado uma vez, reutilizado sempre.
- Invalidação: chave é o hash do arquivo; APK diferente = cache diferente. Sem
  lógica de expiração necessária (conteúdo é determinístico por hash).

### Domínios no modo fast
Sem smali, extrair URLs de `res/` + `assets/` + `AndroidManifest.xml`.
Menos domínios que no deep, mas os declarativos (endpoints em XML/resources)
aparecem. Documentar a diferença no output: `domains (res only, use --deep for code)`.

---

## 5. O que é inviável / fora de escopo (explícito)

- **Taint tracking real** (FlowDroid/Soot): 10+ min/APK, GBs de RAM. A heurística
  de co-ocorrência com nível de confiança é o teto honesto para um CLI.
- **Análise dinâmica** (rodar o APK): sem emulador instalado/testado neste VM.
  Requer Android emulator + instrumentação (Frida/DroidBot). Futuro, não v0.6.
- **Scraping da Play Store** para categoria: frágil, quebra com layout, depende de
  rede. Detecção heurística offline é a escolha; `--play` fica como ideia futura.
- **iOS/IPA**: outro formato, outro toolchain. Fora de escopo.

---

## 6. Plano de implementação (fases)

**Fase A — fundação (otimização)**
- Two-tier decode (`-s` default, `--deep` full).
- `Promise.all` na fase de análise + grep combinado de secrets.
- Cache de decode por SHA256 em `~/.cache/apkator/decode/`.
- Estimativa: ~2h. Resultado: default em ~15s, sem perda no modo deep.

**Fase B — data flows**
- `flows.json` (tabela permissão→assinaturas, ~8 permissões iniciais).
- Grep combinado → candidatos → parser de chunks `.method` → agregação.
- Seção `DATA FLOWS` no output + `flows` no JSON.
- Over-declaration como subproduto (custo zero).
- Estimativa: ~3h. É a feature mais ambiciosa; testar no APK do Orion
  (esperado: `RECORD_AUDIO --[SpeechRecognizer]--> api.groq.com [method]`).

**Fase C — categoria + anomalia**
- `baselines.json` (10 categorias, curadoria manual documentada).
- `categoryDetect()` com os 3 sinais; findings de anomalia.
- Estimativa: ~2h (o trabalho é a curadoria, não o código).

**Fase D — narrativa IA**
- Digest builder + `--explain` via GLM 5.3 Flash + cache de narrativa.
- `max_tokens: 400` (não menos — o reasoning consome o orçamento).
- Estimativa: ~1h.

**Evolução pós-v0.6** (não prometer agora): corpus de APKs para calibrar
baselines com dados reais; modo `--watch` (re-analisa em CI); Frida hooks
sugeridos a partir dos flows ("se quiser confirmar dinamicamente, intercepte X").

---

## Resumo das decisões

1. Flows por **co-ocorrência em nível de método** com confiança explícita, nunca
   alegando taint tracking real.
2. LLM (**GLM 5.3 Flash**) só na camada final, input digest de ~400 tokens,
   flag `--explain`, com cache.
3. Categorias por **3 sinais heurísticos** + `baselines.json` curado manualmente;
   anomalia = permissão `rare` para a categoria.
4. **Two-tier decode** (`-s` default ~15s, `--deep` ~90s) + paralelização +
   cache por SHA256.
5. Fora de escopo: taint real, dinâmica, Play Store scraping, iOS.
