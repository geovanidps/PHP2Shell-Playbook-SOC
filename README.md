# PHP2Shell-Playbook-de-SOC-e-Detec-o-de-Webshell

# PHP2Shell: Playbook de SOC e Detecção de Webshell

Material defensivo para equipes de SOC e resposta a incidentes identificarem, investigarem e conterem a exploração do **PHP2Shell** (**CVE-2026-109618** e **CVE-2026-109619**), com foco em **execução de comandos e webshells em aplicações web PHP**.

> **Status:** v1.0, elaborado em 22/10/2026, dias após a divulgação da vulnerabilidade. O cenário muda rápido (exploração, assinaturas, IOCs). Confira sempre o [aviso oficial do PHP](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) antes de usar este material.

> **Escopo:** conteúdo **somente defensivo**. Este repositório não contém exploit, prova de conceito nem procedimento de exploração.

---

## Sumário

- [Sobre a vulnerabilidade](#sobre-a-vulnerabilidade)
- [O que há neste repositório](#o-que-há-neste-repositório)
- [Abordagem de detecção](#abordagem-de-detecção)
- [Como começar](#como-começar)
- [Regras Sigma](#regras-sigma)
- [Mapa de cobertura](#mapa-de-cobertura)
- [Testes de validação](#testes-de-validação)
- [Limitações](#limitações)
- [Fontes](#fontes)
- [Autor](#autor)
- [Licença e uso](#licença-e-uso)

---

## Sobre a vulnerabilidade

PHP2Shell é o nome público de duas falhas críticas no próprio runtime do PHP, que podem permitir **execução remota de código sem autenticação**.

| Item | Detalhe |
| --- | --- |
| CVEs | CVE-2026-109618 (RCE por corrupção de memória após falta de memória) e CVE-2026-109619 (RCE por estado global obsoleto após erro fatal) |
| Severidade | CVSS v4.0 9.2 (crítica) |
| Componentes afetados | PHP-FPM, Apache `mod_php`, `php-cgi`, FrankenPHP e LiteSpeed. Maior risco demonstrado: `mod_php` |
| Pré-requisito do atacante | Acesso de rede ao servidor. Sem autenticação e sem interação do usuário |
| Correção | PHP **8.5.12**, **8.4.27**, **8.3.36** ou **8.2.35** (ou backport da distribuição), com **reinício de todos os workers** |
| Ramos sem suporte | PHP 8.1, 8.0 e 7.4 só têm backports limitados; PHP 5.x e 7.x não têm correção oficial. Migrar ou isolar |

**Ponto central para o SOC:** em vários cenários a falha ocorre **antes do código da aplicação executar**, então os logs da aplicação podem ter pouco contexto. Os sinais mais úteis ficam em logs de servidor web, WAF/CDN, logs de erro do PHP, telemetria de processos, arquivos e rede.

> Mitigações por configuração (por exemplo, desativar `session.upload_progress` ou o OPcache) têm eficácia contestada entre as fontes e **não substituem a atualização**. O PHP afirma que somente o patch é uma mitigação completa.

---

## O que há neste repositório

```
PHP2Shell/
├── README.md
├── 01_Documentos/
│   ├── 01_PHP2Shell_Playbook_SOC.docx          # Vulnerabilidade, playbook e tutorial passo a passo
│   ├── 02_PHP2Shell_Guia_Sentinel_KQL.docx     # Microsoft Sentinel: KQL, regras, watchlist, automação
│   ├── 03_PHP2Shell_Guia_AWS.docx              # AWS: CloudWatch, Athena, GuardDuty, contenção
│   └── 04_PHP2Shell_Guia_SIEM_Generico.docx    # Qualquer SIEM: Sigma, mapeamento, SPL/EQL, correlação
└── 02_Regras_Sigma_YAML/
    ├── LEIAME.md
    ├── php2shell_s1 ... s7_*.yaml              # 7 regras de detecção
    └── php2shell_c1 ... c3_*.yaml              # 3 regras de correlação
```

| Documento | Conteúdo |
| --- | --- |
| **Playbook de SOC** | Ficha técnica, causa raiz, versões afetadas, papéis, classificação (tentativa x comprometimento), fases de resposta, matriz de indicadores e **tutorial em 10 passos** com comandos de caça, preservação de evidências, contenção e endurecimento |
| **Guia Microsoft Sentinel** | Consultas de hunting H1 a H9, regras analíticas A1 a A7 (com modelo YAML), regra de correlação, watchlist `PHP_Assets`, playbook de automação com aprovação humana, workbook e testes |
| **Guia AWS** | Inventário (SSM e Inspector), ingestão de logs, consultas em CloudWatch Logs Insights e Athena, caça a uso indevido de credenciais da role da instância, GuardDuty, EventBridge e comandos de contenção |
| **Guia SIEM genérico** | Fontes de log mínimas, mapeamento de campos (Sigma, ECS, CIM, CEF), regras Sigma, exemplos SPL e EQL, pontuação de correlação e testes |

---

## Abordagem de detecção

O foco é o **resultado da exploração**, não a assinatura do exploit, que pode mudar. A confiança aumenta quando vários sinais se correlacionam no mesmo host:

```
Tentativa na borda ──► Preparação ──────────► Execução ───────────► Webshell em disco ──► Rede / Persistência
(POST multipart,       (memory exhausted,     (shell ou utilitário   (.php novo em          (conexão de saída
 HTTP 500)              segfault de worker)    filho do servidor web)  uploads/cache)         inédita, cron, conta)
```

Princípios:

- **Tentativa x comprometimento:** atividade parecida com a técnica não prova sucesso. Evidência de execução, acesso, divulgação ou persistência é o que confirma o incidente.
- **A ausência de artefatos não prova que o ataque falhou.**
- **Preserve antes de mudar:** logs, configurações e arquivos suspeitos antes de patch ou reinício.
- **Não apague webshells de imediato:** copie, calcule o hash, registre e só então remova.
- **Janela de caça:** a partir de **17/10/2026** (primeira tentativa reportada), ou 30 dias se houver retenção.

---

## Como começar

1. **Inventarie** os servidores PHP e priorize os expostos à internet, em especial Apache com `mod_php`.
2. **Preserve evidências** (logs, configurações, snapshot) antes de qualquer alteração.
3. **Atualize** o PHP para a versão corrigida e **reinicie todos os workers**.
4. **Cace** webshells, processos filhos suspeitos, persistência e conexões de saída na janela retroativa.
5. **Implante detecção contínua** com as regras Sigma ou com o guia da sua plataforma (Sentinel, AWS ou genérico).
6. **Teste** as regras em homologação com os testes seguros dos guias.

Leitura sugerida: comece pelo **Playbook de SOC** e depois use o guia da sua plataforma.

---

## Regras Sigma

Pasta [`02_Regras_Sigma_YAML`](02_Regras_Sigma_YAML). As regras são independentes de SIEM e podem ser convertidas com o [sigma-cli](https://github.com/SigmaHQ/sigma-cli) e o backend da sua plataforma.

| Arquivo | Tipo | Nível | Detecta |
| --- | --- | --- | --- |
| `php2shell_s1_web_process_spawns_shell` | Regra | alto | Shell ou utilitário filho de processo web |
| `php2shell_s2_php_file_written_by_web_process` | Regra | alto | Arquivo PHP gravado por processo web em diretório de mídia ou cache |
| `php2shell_s3_web_process_outbound_public` | Regra | médio | Conexão de saída de processo web para IP público |
| `php2shell_s4_php_memory_exhausted_or_worker_crash` | Regra | médio | Estouro de memória ou queda de worker PHP |
| `php2shell_s5_post_http500_php_route` | Regra | baixo | POST com HTTP 500 em rota PHP (base para correlação) |
| `php2shell_s6_php_access_in_media_dir` | Regra | alto | Acesso a PHP em diretório de mídia ou cache (webshell) |
| `php2shell_s7_web_user_persistence` | Regra | alto | Cron ou conta criada pelo usuário do serviço web |
| `php2shell_c1_post500_burst` | Correlação | médio | 10 ou mais POST 500 por origem em 5 min |
| `php2shell_c2_php_errors_burst` | Correlação | médio | 5 ou mais erros PHP por host em 15 min |
| `php2shell_c3_errors_then_shell` | Correlação | crítico | Erros PHP seguidos de shell filho no mesmo host em 1 h |

Exemplo de conversão (com o sigma-cli e o backend do Splunk instalados):

```bash
sigma convert -t splunk -p splunk_windows 02_Regras_Sigma_YAML/php2shell_s1_web_process_spawns_shell.yaml
```

> Ajuste o pipeline de mapeamento de campos ao seu ambiente. As regras de correlação (C1 a C3) exigem suporte ao formato de correlação do Sigma v2; sem ele, implemente a lógica nativamente (contagem por origem ou host, e sequência ordenada por host).

---

## Mapa de cobertura

| Etapa do ataque | Fontes principais | Regras Sigma | Técnica MITRE ATT&CK |
| --- | --- | --- | --- |
| Tentativa na borda | WAF, proxy, CDN, logs de acesso | S5, C1 | T1190 |
| Preparação (OOM, crash) | Logs de erro do PHP, syslog/kernel | S4, C2 | T1190 |
| Execução de comando | EDR, auditd, eBPF | S1, C3 | T1059.004 |
| Webshell em disco / uso | EDR, FIM, logs de acesso | S2, S6 | T1505.003 |
| Download de carga / canal reverso | EDR, flow logs, DNS | S3 | T1071, T1105 |
| Persistência | EDR, auditd, syslog | S7 | T1053.003, T1136.001 |

---

## Testes de validação

Cada guia traz testes **seguros** que simulam apenas o **comportamento** detectado (por exemplo, gravar um `teste.php` inofensivo em um diretório de uploads de homologação, ou provocar estouro de `memory_limit` controlado). **Não explore a vulnerabilidade** para testar regras. Faça tudo em ambiente de homologação e documente alertas gerados, tempo até o alerta e falsos positivos.

---

## Limitações

- Não havia lista pública consolidada e verificada de **IOCs** específicos do PHP2Shell na data de elaboração. A detecção é **comportamental**.
- Fontes divergem sobre o estado de exploração e sobre a eficácia de mitigações. Priorize o aviso oficial do PHP.
- Logs de acesso padrão **não registram o corpo** da requisição. Buscar `PHP_SESSION_UPLOAD_PROGRESS` exige WAF ou proxy que registre os dados casados.
- Regras comportamentais podem gerar **falsos positivos** em aplicações que usam utilitários do sistema. Crie exceções por comando completo e host.
- Nomes de tabelas, campos e achados variam por ambiente. As consultas e regras são **modelos** e **não foram executadas em ambiente real** durante a elaboração; as regras Sigma tiveram apenas a sintaxe YAML validada.

---

## Fontes

- [Aviso oficial do PHP (GHSA-6wmf-4rv5-p3rp)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Imperva: PHP2Shell](https://www.imperva.com/blog/php2shell-vulnerability-updates/)
- [watchTowr: PHP2Shell](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)
- [Armis: como encontrar, priorizar e corrigir](https://www.armis.com/blog/php2shell-how-to-find-prioritize-and-patch-affected-systems/)
- [Check Point: o que caçar](https://blog.checkpoint.com/security/php2shell-what-we-know-about-the-leaked-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619/)
- [Elastic Security Labs: cobertura de detecção](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection)
- [SentinelOne: Stopping PHP2SHELL](https://www.sentinelone.com/blog/stopping-php2shell-how-sentinelone-protects-customers-from-this-attack-technique/)
- [Qualys: como encontrar, mitigar e corrigir](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)

---

## Autor

**Geovane da Costa Oliveira**

Professor universitário, palestrante e pesquisador na área de Segurança da Computação, com atuação em Cibersegurança, gestão de TI e segurança da informação, e pesquisas em inteligência artificial e privacidade.

---

## Licença e uso

Defina a licença do repositório antes de publicar (por exemplo, MIT ou CC BY 4.0 para o conteúdo documental). Enquanto isso, o material é fornecido **como está**, sem garantias, para uso defensivo e educacional. Teste em homologação antes de usar em produção e respeite a legislação aplicável e as políticas da sua organização.
