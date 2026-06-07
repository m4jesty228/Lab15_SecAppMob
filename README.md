# Lab 15 — Analyse Dynamique Android : Inspection TLS/HTTPS et Gestion du SSL Pinning
**Auteur :** DOSSAH Yao Landry  
**Filière :** Génie CyberDefense et Systèmes de Télécommunications Embarquées (GCDSTE)  
**Établissement :** ENSA Marrakech

---

## Contexte pédagogique

Ce laboratoire porte sur la neutralisation du mécanisme de **SSL Pinning** dans les applications Android, dans un cadre d'audit de sécurité mobile autorisé. L'objectif est de comprendre comment les applications protègent leurs communications TLS, d'utiliser **Frida** pour hooker les couches de vérification de certificats (Java et native), de mettre en place un proxy d'interception, et de valider la capture du trafic HTTPS en clair. L'analyse est strictement défensive, réalisée sur un appareil/émulateur contrôlé avec une application de test.

> ⚠️ **Avertissement éthique :** Ces techniques sont réservées à un cadre légal — tests sur vos propres applications/appareils, formation, ou audit autorisé. Ne pas déployer en production ni sur des données réelles.

---

## Environnement

| Composant | Détail |
|-----------|--------|
| OS hôte | Windows (PowerShell) / macOS / Linux |
| Python | 3.8+ avec pip |
| ADB | Android Platform Tools |
| Frida (PC) | frida + frida-tools (pip) |
| frida-server | Même version que le client Frida, déployé sur l'appareil |
| Proxy TLS | Burp Suite Community/Pro ou mitmproxy |
| Appareil cible | Android 8+ avec débogage USB activé |

---

## Architecture du lab

```
Machine hôte (PC)
      │
      │  frida -U -f com.example.app -l sslpin_bypass_universal.js
      │  Proxy TLS : 127.0.0.1:8080 (Burp / mitmproxy)
      │
      ▼
Appareil Android (USB)
      │
      ├── frida-server  ← daemon embarqué (port 27042)
      │
      └── Application cible
           ├── SSLContext / X509TrustManager  ← hook Java
           ├── Conscrypt TrustManagerImpl     ← hook Java (Android 7+)
           ├── OkHttp CertificatePinner       ← hook Java
           ├── WebViewClient                  ← hook Java
           └── BoringSSL / libssl.so          ← hook natif (cas avancé)
```

---

## Étape 1 — Installer Frida et déployer frida-server

### 1.1 Installer Frida côté PC

```bash
python -m pip install --upgrade frida frida-tools

# Vérification
frida --version
python -c "import frida; print(frida.__version__)"
```

### 1.2 Préparer ADB et l'appareil

Activer **Options développeur → Débogage USB** sur l'appareil, brancher en USB, accepter l'empreinte de débogage.

```bash
adb devices
# Attendu : appareil listé "device" (pas "unauthorized")
```

### 1.3 Déployer frida-server sur l'appareil

```bash
# Identifier l'architecture CPU
adb shell getprop ro.product.cpu.abi

# Télécharger frida-server correspondant à "frida --version" sur :
# https://github.com/frida/frida/releases

# Décompresser, transférer et lancer
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server -l 0.0.0.0"

# Port forwarding si nécessaire
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043

# Vérification
frida-ps -Uai
```

> ⚠️ La version de `frida` (PC) et de `frida-server` (Android) doit être **strictement identique**.

---

## Étape 2 — Mettre en place le proxy et le certificat CA

### 2.1 Lancer le proxy

- **Burp Suite** : Proxy → Options → noter l'adresse et le port (ex : `127.0.0.1:8080`).
- **mitmproxy** : `mitmproxy -p 8080`

### 2.2 Installer la CA proxy sur l'appareil

Accéder à `http://burp` ou `http://mitm.it` depuis le navigateur de l'appareil, télécharger et installer le certificat en tant que **certificat CA utilisateur**.

> Sur Android 7+, les applications peuvent ignorer les CA utilisateur via Network Security Config — d'où la nécessité des hooks TrustManager/Conscrypt.

### 2.3 Rediriger le trafic vers le proxy

```bash
# Méthode recommandée (USB)
adb reverse tcp:8080 tcp:8080
```

Puis configurer le proxy de l'appareil (Wi-Fi) sur `127.0.0.1:8080`, ou utiliser la redirection USB ci-dessus.

---

## Étape 3 — Lancer l'application cible sous Frida

```bash
# Identifier le package
frida-ps -Uai

# Mode spawn (recommandé — injection très tôt au démarrage)
frida -U -f com.example.app -l sslpin_bypass_universal.js --no-pause

# Mode attach (si l'app est déjà ouverte)
frida -U -n "NomDuProcessus" -l sslpin_bypass_universal.js
```

---

## Étape 4 — Script de bypass SSL universel

Fichier : `sslpin_bypass_universal.js`

```javascript
// sslpin_bypass_universal.js
Java.perform(function(){
  const ArrayList = Java.use('java.util.ArrayList');
  function ok(tag){ console.log('[+] SSL bypass:', tag); }

  // 1) SSLContext.init — injecter un TrustManager permissif si absent
  try{
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom')
      .implementation = function(km, tm, sr){
        let useTm = tm;
        try {
          if (!tm || tm.length === 0){
            const X509TM = Java.registerClass({
              name: 'com.frida.FriendlyTM',
              implements: [Java.use('javax.net.ssl.X509TrustManager')],
              methods: {
                checkClientTrusted: function(chain, authType){},
                checkServerTrusted: function(chain, authType){},
                getAcceptedIssuers: function(){ return Java.array('java.security.cert.X509Certificate', []); }
              }
            });
            const TMArr = Java.use('[Ljavax.net.ssl.TrustManager;');
            const arr = TMArr.$new(1); arr[0] = X509TM.$new(); useTm = arr;
            ok('Injected permissive TrustManager');
          }
        } catch(e){}
        return this.init(km, useTm, sr);
      };
    ok('SSLContext.init patched');
  }catch(e){ console.log('[-] SSLContext.init patch failed:', e.message); }

  // 2) Patch large des implémentations X509TrustManager
  try{
    Java.enumerateLoadedClasses({
      onMatch: function(name){
        const low = name.toLowerCase();
        if (low.includes('trust') || low.includes('pin')){
          try{
            const K = Java.use(name);
            ['checkServerTrusted','checkClientTrusted'].forEach(m => {
              if (K[m]) K[m].overloads.forEach(ov => {
                ov.implementation = function(){ ok(name+'.'+m+' -> allow'); return null; };
              });
            });
          }catch(_){}
        }
      }, onComplete: function(){ ok('X509TrustManager patches attempted'); }
    });
  }catch(e){ console.log('[-] enumerateLoadedClasses failed:', e.message); }

  // 3) Conscrypt TrustManagerImpl (Android 7+)
  ['com.android.org.conscrypt.TrustManagerImpl','org.conscrypt.TrustManagerImpl'].forEach(cls => {
    try{
      const TMI = Java.use(cls);
      ['checkTrusted','verifyChain','checkServerTrusted'].forEach(m => {
        if (TMI[m]) TMI[m].overloads.forEach(ov => {
          ov.implementation = function(){
            ok(cls+'.'+m+' -> allow');
            try { return ov.apply(this, arguments); } catch(e){ try { return ArrayList.$new(); } catch(_){ return null; } }
          };
        });
      });
      ok(cls+' patched');
    }catch(e){}
  });

  // 4) OkHttp 3/4 CertificatePinner
  try{
    const CP = Java.use('okhttp3.CertificatePinner');
    if (CP.check) CP.check.overloads.forEach(ov => {
      ov.implementation = function(){ ok('okhttp3.CertificatePinner.check skip'); return; };
    });
  }catch(e){}

  // 5) WebView — ignorer les erreurs SSL
  try{
    const WVC = Java.use('android.webkit.WebViewClient');
    if (WVC.onReceivedSslError) WVC.onReceivedSslError.implementation = function(view, handler, error){
      ok('WebView onReceivedSslError -> proceed'); handler.proceed();
    };
  }catch(e){}

  console.log('[+] Universal SSL pinning bypass installed');
});
```

**Résultat attendu :** les logs Frida affichent les lignes `[+] SSL bypass: ...` lors des connexions, et le proxy commence à intercepter les requêtes HTTPS en clair.

---

## Étape 5 — Variantes et cibles spécifiques

| Scénario | Approche |
|----------|----------|
| App OkHttp/Retrofit uniquement | Le bloc `CertificatePinner.check` suffit |
| Package OkHttp renommé (obfuscation) | Enumérer les classes chargées et filtrer `okhttp`, adapter le nom de classe |
| Android récent (Conscrypt dominant) | Patcher `checkTrusted` / `verifyChain` de `TrustManagerImpl` |
| App WebView embarquée | Le hook `onReceivedSslError` couvre la plupart des cas |

---

## Étape 6 — Cas avancé : pinning natif (BoringSSL / OpenSSL)

Si aucune requête n'apparaît dans le proxy malgré le script Java, le pinning est probablement implémenté dans une librairie native.

### 6.1 Découverte des symboles natifs

```bash
frida-trace -U -i SSL_* -i X509_* com.example.app
```

### 6.2 Hook natif minimal

Fichier : `sslpin_bypass_native.js`

```javascript
// sslpin_bypass_native.js
function hook(name, lib){
  const addr = Module.findExportByName(lib||null, name);
  if (!addr) return console.log('[*] no', name);
  Interceptor.attach(addr, {
    onLeave(rv){
      if (name === 'SSL_get_verify_result'){
        console.log('[+] SSL_get_verify_result -> X509_V_OK');
        rv.replace(ptr(0)); // 0 = X509_V_OK
      }
    }
  });
  console.log('[+] Hooked', name);
}

hook('SSL_get_verify_result', 'libssl.so');
```

### 6.3 Lancement combiné

```bash
frida -U -f com.example.app -l sslpin_bypass_universal.js -l sslpin_bypass_native.js --no-pause
```

---

## Étape 7 — Validation et livrables

**Validation :**
- Le proxy affiche les requêtes HTTPS de l'app avec URL, en-têtes et corps en clair.
- La console Frida affiche les logs `[+] SSL bypass:` au moment des connexions.

**Livrables attendus :**

| Livrable | Description |
|----------|-------------|
| Capture `frida --version` + `frida-ps -Uai` | Preuves d'installation |
| `sslpin_bypass_universal.js` | Script Java universel |
| `sslpin_bypass_native.js` | Script natif (cas avancé) |
| Capture proxy | Requête HTTPS interceptée (URL + en-têtes) |
| Journal Frida | Au moins une ligne `[+] SSL bypass:` |

---

## Dépannage (FAQ)

**`error: unable to connect to remote frida-server`**
- Vérifier `adb devices` → doit afficher `device`.
- Vérifier `adb shell ps | grep frida` → `frida-server` doit tourner.
- Aligner strictement les versions `frida` (PC) et `frida-server` (Android).
- Si nécessaire : `adb forward tcp:27042 tcp:27042`.

**Pas de trafic dans le proxy malgré les hooks**
- La CA n'est pas installée ou l'app n'utilise pas le store utilisateur → les hooks TrustManager/Conscrypt doivent forcer l'acceptation.
- L'app peut utiliser Cronet ou une lib native custom → tracer `SSL_*` et adapter.
- Vérifier la configuration du proxy (port/adresse) et la connectivité réseau.

**L'app crash au démarrage avec `-f`**
- Essayer le mode attach : `frida -U -n "NomDuProcessus" -l script.js`.
- Injecter d'abord un script minimal, puis ajouter le bypass SSL.

**Obfuscation / packages renommés**

```javascript
// Enumérer les classes chargées et filtrer par mots-clés
Java.perform(function(){
  Java.enumerateLoadedClasses({
    onMatch: function(n){
      const s = n.toLowerCase();
      if (s.includes('okhttp') || s.includes('pin') || s.includes('trust')) console.log(n);
    },
    onComplete: function(){ console.log('done'); }
  });
});
```

Adapter ensuite les noms de classes dans le script selon l'espace de noms réel.

**WebView continue à bloquer**
- Certaines WebView personnalisées ne passent pas par `onReceivedSslError` → tracer les classes du client web de l'app et hooker leur gestion des erreurs.

**Pinning Cronet/Chromium**
- Le pinning peut être natif → tracer `SSL_*` et chercher les classes `org.chromium.net`.

---

## Points clés retenus

- Frida permet de hooker à la fois les couches **Java** (TrustManager, Conscrypt, OkHttp, WebView) et **natives** (BoringSSL/libssl.so) pour neutraliser le SSL pinning.
- Le mode **spawn** (`-f`) est préférable pour les apps qui effectuent le pinning très tôt au démarrage ; le mode **attach** est utile quand le spawn provoque un crash.
- Sur Android 7+, les CA utilisateur sont ignorées par défaut par les apps — les hooks Frida contournent cette restriction sans modifier l'APK.
- Un pinning implémenté via `okhttp3.CertificatePinner` est distinct d'un pinning natif — diagnostiquer d'abord la couche concernée avant de choisir le script.
- La combinaison **script Java universel + hook natif** couvre la quasi-totalité des implémentations rencontrées en pratique.

---

*Lab réalisé dans le cadre du cours Sécurité des Applications Mobiles — ENSA Marrakech, Filière GCDSTE*
