# PHP2Shell: regras Sigma (CVE-2026-109618 e CVE-2026-109619)

Regras de deteccao em formato Sigma (YAML), independentes de SIEM. Convertem-se para Splunk, Elastic, QRadar, Chronicle, Sentinel (KQL), Wazuh, Graylog e outros com o sigma-cli e o backend correspondente.

## Arquivos

| Arquivo | Tipo | Nivel | O que detecta |
| --- | --- | --- | --- |
| php2shell_s1_web_process_spawns_shell.yaml | Regra | alto | Shell ou utilitario filho de processo web |
| php2shell_s2_php_file_written_by_web_process.yaml | Regra | alto | Arquivo PHP gravado por processo web em diretorio de midia/cache |
| php2shell_s3_web_process_outbound_public.yaml | Regra | medio | Conexao de saida de processo web para IP publico |
| php2shell_s4_php_memory_exhausted_or_worker_crash.yaml | Regra | medio | Estouro de memoria ou queda de worker PHP |
| php2shell_s5_post_http500_php_route.yaml | Regra | baixo | POST com HTTP 500 em rota PHP (base para correlacao) |
| php2shell_s6_php_access_in_media_dir.yaml | Regra | alto | Acesso a PHP em diretorio de midia/cache (webshell) |
| php2shell_s7_web_user_persistence.yaml | Regra | alto | Cron ou conta criada pelo usuario do servico web |
| php2shell_c1_post500_burst.yaml | Correlacao | medio | 10 ou mais POST 500 por origem em 5 min (usa S5) |
| php2shell_c2_php_errors_burst.yaml | Correlacao | medio | 5 ou mais erros PHP por host em 15 min (usa S4) |
| php2shell_c3_errors_then_shell.yaml | Correlacao | critico | Erros PHP seguidos de shell filho no mesmo host em 1 h (S4 e S1) |

## Como usar

1. Instale o sigma-cli e o backend do seu SIEM (por exemplo, Splunk ou Elasticsearch).
2. Converta as regras base (S1 a S7) com o pipeline de mapeamento de campos do seu ambiente.
3. As regras de correlacao (C1 a C3) exigem suporte a correlacao do Sigma v2 no conversor. Sem esse suporte, implemente a logica nativamente: contagem por origem/host na janela indicada (C1, C2) e sequencia ordenada por host (C3).
4. Referencia entre regras pelo campo `name` (por exemplo, `php2shell_post_http500_php_route`).

## Ajustes obrigatorios antes de ativar

- **logsource e campos:** mapeie `Image`, `ParentImage`, `User`, `TargetFilename`, `DestinationIp`, `cs-*`, `c-ip` e `Computer` para os campos do seu SIEM. A regra S4 usa um logsource personalizado (`category: application`, `product: php`) para logs de erro do PHP.
- **Campo de agrupamento:** `Computer` (C2, C3) e `c-ip` (C1) precisam existir nos eventos apos o mapeamento.
- **Usuarios e processos:** ajuste a lista de usuarios do servico web (S7) e os nomes de processos (PHP-FPM versionado, LiteSpeed, FrankenPHP).
- **Excecoes:** crie excecoes por linha de comando completa e host, nunca por nome generico de processo.
- **S3 sem baseline gera ruido:** alerte apenas destinos ineditos por servidor.

## Limitacoes

- Nao ha IOCs publicos consolidados especificos do PHP2Shell; a deteccao e comportamental (resultado da exploracao).
- Regras comportamentais podem gerar falsos positivos em aplicacoes que usam utilitarios do sistema.
- As regras tiveram a sintaxe YAML validada, mas nao foram convertidas nem testadas em um SIEM durante a elaboracao.
- Teste em homologacao antes de producao. Nao ha procedimento de exploracao neste pacote.

## Fonte principal

Aviso oficial do PHP: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
