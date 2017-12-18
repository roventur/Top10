# Risk - Application Security Risks

## What Are Application Security Risks?

Gli attaccanti potenzialmente possono usare diversi percorsi della tua applicazione per danneggiare il tuo business o la tua organizzazione. Ognuno di questi percorsi rappresenta un rischio che può o meno essere abbastanza serio da garantire attenzione. 

![App Security Risks](images/0x10-risk-1.png)

A volte questi percorsi sono facili da trovare e sfruttare, mentre altre volte sono estremamente difficili. Similmente, il danno che ne deriva può non avere nessuna conseguenza, o può portarti fuori dal business. Per determinare il rischio che la tua organizzazione corre, puoi valutare la probabilità associtata ad ogni minaccia, vettore di attacco, e debolezza della sicurezza e combinare con una stima dell'impatto tecnico e di business per la tua organizzazione. Insieme, questi fattori determinano il rischio complessivo.

## What's My Risk

La [OWASP Top 10](https://www.owasp.org/index.php/Top10) ha l'obiettivo di identificare i rischi più seri per la sicurezza delle applicazioni web per una vasta gamma di organizzazioni. Per ognuno di questi rischi, forniamo informazioni generiche sulla probabilità e sull'impatto tecnico usando il prossimo semplice schema di rating, che è basato sulla OWASP Risk Rating Methodology.  

| Threat Agents | Exploitability | Weakness Prevalence | Weakness Detectability | Technical Impacts | Business Impacts |
| -- | -- | -- | -- | -- | -- |
| Appli-   | Easy 3 | Widespread 3 | Easy 3 | Severe 3 | Business     |
| cation   | Average 2 | Common 2 | Average 2 | Moderate 2 | Specific |
| Specific | Difficult 1 | Uncommon 1 | Difficult 1 | Minor 1 |       |

In questa edizione, abbiamo aggiornato il sistema di rating del rischio per aiutare nel calcolo della probabilità e dell'impatto di un dato rischio. Per ulteriori dettagli, vedere [Note About Risks](0xc0-note-about-risks.md). 

Ogni organizzazione è unica, e lo stesso vale per gli attori della minaccia per quella organizzazione, i loro obiettivi, e l'impatto di ogni breccia. Se una organizzazione di pubblico interesse usa un sistema di gestione dei contenuti (CMS) per fornire informazioni pubbliche e un sistema sanitario utilizza lo stesso CMS per dati sanitari sensibili, gli attori della minaccia e gli impatti sul business possono essere differenti per lo stesso software. E' di importanza critica comprendere il rischio per la propria organizzazione sulla base degli attori delle minacce e sugli impatti sul business. 

Dove possibile, i nomi dei rischi nella Top 10 sono allineati alla [Common Weakness Enumeration](https://cwe.mitre.org/) (CWE) per promuovere convenzioni di nomi generalmente accettate e per ridurre la confusione.

## References

### OWASP

* [OWASP Risk Rating Methodology](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Article on Threat/Risk Modeling](https://www.owasp.org/index.php/Threat_Risk_Modeling)

### External

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
