# A2:2017 Broken Authentication

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 3 | Prevalence 2 : Detectability 2 | Technical 3 : Business |
| Gli attaccanti hanno a disposizione centinaia di milioni di coppie user/password per attacchi Credential Stuffing, account di amministrazione di default,  strumenti di attacco a forza bruta o strumenti per attacchi basati su dizionari. Gli attacchi alla gestione delle sessioni sono ben noti, in particolare quelli relativi a token di sessione non scaduti. | La diffusione delle autenticazioni deboli è alta a causa del design e della implementazione di molti sistemi di controllo di autenticazione e accesso. La gestione delle sessioni è alla base di dei controlli di accesso e autenticatione ed è presente in tutte le applicazioni stateful. Gli attaccanti possono trovare autenticazioni fallaci attraverso chiamate manuali e sfruttarle con strumenti di attacco automatici basati su liste di password o dizionari. | Agli attaccanti è sufficiente avere accesso a pochi account, o anche solo un account amministrativo, per compromettere l'intero sistema. In base al dominio dell'applicazione questo può portare a riciclaggio di denaro, frodi previdenziali e furti di identità, o alla diffuzione di informazioni sensibili legalmente protette. |

## L'Applicazione è vulnerabile?

La certificazione dell'identità dell'utente, l'autenticazione e la gestione delle sessioni sono aspetti critici nel progeggere contro gli attacchi basati su autenticazione.

Possono esserci debolezze nell'autenticazione se l'applicazione:

* Permette attacchi automatici come il [credential stuffing](https://www.owasp.org/index.php/Credential_stuffing), in cui l'attaccante ha una lista di credenziali valide.
* Permette attacchi a forza bruta o altri attacchi automatici.
* Permette password di deault, deboli o ben note come "Password1" o "admin/admin".
* Utilizza sistemi di recupero di credenziali smarrite deboli o inefficaci, come il "rispondere ad domande" che non possono essere resi sicuri.
* Trasmette o salva password in chiaro o con metodi di hash / encription non efficaci. (vedere **A3:2017-Sensitive Data Exposure**).
* Non implementa una autenticazione multi-factor o ne usa una inefficace.
* Espone gli id di sessione nello URL (ad esempio con lo  URL rewriting).
* Non aggiorna gli ID di sessione dopo i login.
* Non invalida correttamente gli ID di sessione. Le sessioni utente o i token di autenticazione (in particolare i token single sign-on (SSO)) non sono annullati correttamente dopo il logout o un periodo di inattività dell'utente.

## Prevenzione

* Ove possibile implementare l'autenticazione multi-factor per prevenire attacchi automatici credentiali stuffing, a forza bruta o con credenziali rubate.
* Non rilasciare od installare con credenziali di default attivi, in particolar modo per gli utenti amministrativi.
* Aggiungere controlli sulla debolezza delle password, come verificare tutte le password, nuove e aggiornate, con la lista delle  [1000 peggiori password](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
* Allineare le policy su lunghezza, complessità e tempi di rotazione delle passwor con [NIST 800-63 B's guidelines in section 5.1.1 for Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) o altre policy moderne e fattuali.
* Assicurarsi che la registrazione, il processo di recupero delle credenziali e i percorsi delle API siano protetti da attacchi basati su enumerazione di account utilizzando lo stesso messaggio per tutti gli output.
* Limitare o rallentare progressivamente i login falliti. Registrare tutti i fallimenti e avvisare gli amministratori quando vengono individuati attacchi credential stuffing, a forza bruta o di altro tipo.
* Utilizzare un session manager built-in, sicuro, server-side che genera un nuovo ID di sessione casuale ad alta entropia dopo i login. Gli ID di sessione non dovrebbero essere negli URL, dovrebbero essere salvati in maniera sicura e invalidati dopo logout, tempi di inattività o timeout assoluti.

## Scenari esempio di attacco

Scenario #1: [Credential stuffing](https://www.owasp.org/index.php/Credential_stuffing), l'utilizzo di  [liste di password conosciute](https://github.com/danielmiessler/SecLists), è un attacco comune. Se l'applicazione non implementa sistemi di protezione contro questo tipo di attacco può essere usata come un sistema di validazione delle password.

**Scenario #2**: Molti attacchi all'autenticazione sono dovuti all'utilizzo continuato della password come solo fattore di identificazione. Sebbene una volta considerate best practice, policy come rotazione delle password e requisiti di complessità minima finiscono per incoraggiare gli utenti a utilizzare e riutilizzare password deboli. Si raccomanda alle organizzazioni di bloccare queste pratiche come in    

**Scenario #2**: Most authentication attacks occur due to the continued use of passwords as a sole factor. Once considered best practices, password rotation and complexity requirements are viewed as encouraging users to use, and reuse, weak passwords. Organizations are recommended to stop these practices per NIST 800-63 e utilizzare una autenticazione multi-factor.

**Scenario #3**: I timeout delle session non sono configurati correttamente. Un utente utilizza un computer pubblico per accedere ad una applicazione. Invece di effettuare il logout, l'utente chiude il tab del browser e se va. Un attaccante usa lo stesso browser un ora dopo e la sessione utente è ancora attiva.

## Referenze

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
 and [Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
* [OWASP Automated Threats Handbook](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Esterne

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - for thorough, modern, evidence-based advice on authentication. 
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
