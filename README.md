# Duplicate Finder — User Guide (Windows) / Guide d'utilisation (Windows)

A step-by-step guide to download, prepare and run `duplicate_finder.py` to detect and manage duplicate files on a Windows PC, removable drives (USB), or Android devices via ADB.

Guide étape par étape pour télécharger, préparer et exécuter `duplicate_finder.py` afin de détecter et gérer les fichiers en double sur un PC Windows, des lecteurs amovibles (USB) ou des appareils Android via ADB.

---

## Summary (English) / Résumé (Français)

This tool scans a selected folder, removable drive, or an Android device (via ADB) to find duplicate files. It provides a live log and progress bar and can prompt you to remove duplicates after scanning.

Cet outil analyse un dossier choisi, un lecteur amovible ou un appareil Android (via ADB) pour trouver les fichiers en double. Il affiche un journal en temps réel et une barre de progression et peut vous proposer de supprimer les doublons à la fin du scan.

---

## Quick notes / Notes rapides

- System / Système: Windows 10 / 11 (recommended / recommandé)  
- Language / Langue: English + French  
- Script: `duplicate_finder.py`  
- Python: 3.8+ recommended / recommandé  
- ADB/Android scanning is optional — only required to scan a phone. / Le scan via ADB est optionnel — requis seulement pour scanner un téléphone.

---

## Important safety notice — read first / Avis de sécurité important — à lire en premier

- The script may offer to delete duplicate files. Always make a backup or run the script in a "dry" or read-only mode first (if supported) before removing files.
- If you are unsure what the script will delete, do not confirm deletion. Inspect the log and sample output first.
- Prefer running the tool on a copy of the data or on a small test folder before scanning large or important drives.

Le script peut proposer de supprimer des fichiers en double. Faites toujours une sauvegarde ou exécutez le script en mode "simulation" ou lecture-seule si cette option existe avant de supprimer des fichiers.  
Si vous n'êtes pas sûr de ce que le script va supprimer, ne confirmez pas la suppression. Inspectez d'abord le journal et la sortie d'exemple.  
Il est préférable d'exécuter l'outil sur une copie des données ou sur un petit dossier test avant d'analyser des lecteurs volumineux ou sensibles.

---

## Prerequisites / Prérequis

- Windows 10 or 11 (64-bit recommended). / Windows 10 ou 11 (64 bits recommandé).  
- Python 3.8 or newer installed. Download from the official site:
  - https://www.python.org/downloads/windows/
  - During installation, check "Add Python to PATH".
- The file `duplicate_finder.py` (place it in a folder you can open in PowerShell).  
- For Android device scanning: ADB (Platform Tools). See the Android section below.

---

## Quick start (fast path) / Démarrage rapide

1. Download Python 3.8+ and install it (ensure "Add Python to PATH" is checked).  
2. Place `duplicate_finder.py` in a folder (e.g., `C:\tools\duplicate-finder`).  
3. Open PowerShell in that folder (Shift + Right click → "Open PowerShell window here").  
4. Run:
```powershell
python duplicate_finder.py
```
5. A GUI window should open (or the script will prompt). Choose:
   - Local folder...
   - Removable drive...
   - Android via ADB...
6. Monitor the log and progress. When scanning finishes, review duplicates and choose actions (do not confirm deletion until you review).

1. Téléchargez Python 3.8+ et installez-le (vérifiez que "Add Python to PATH" est coché).  
2. Placez `duplicate_finder.py` dans un dossier (par exemple `C:\tools\duplicate-finder`).  
3. Ouvrez PowerShell dans ce dossier (Shift + clic droit → "Open PowerShell window here").  
4. Exécutez :
```powershell
python duplicate_finder.py
```
5. Une fenêtre GUI devrait s'ouvrir (ou le script vous invitera). Choisissez :
   - Local folder...
   - Removable drive...
   - Android via ADB...
6. Surveillez le journal et la progression. À la fin du scan, vérifiez les doublons et choisissez les actions (ne confirmez pas la suppression sans vérification).

---

## Android via ADB — setup and basic steps / Android via ADB — configuration et étapes de base

1. Download Android Platform Tools (ADB):
   - https://developer.android.com/studio/releases/platform-tools
2. Extract and place the `platform-tools` folder in:
   - Recommended: `C:\platform-tools`
3. Connect the Android device via USB.
4. Enable Developer Options and USB Debugging on the phone:
   - Settings → About phone → tap Build number 7 times.
   - Settings → System → Developer options → enable "USB debugging".
   - Authorize the PC when prompted on the phone.
5. If the script supports automatic adb detection and a file browser, choose "Android via ADB..." and wait — enumerating many files may take time.
6. If `adb` is not found, ensure `C:\platform-tools\adb.exe` exists and that `C:\platform-tools` is in your PATH or run the script from a shell where `adb` is accessible.

1. Téléchargez Platform Tools (ADB) :
   - https://developer.android.com/studio/releases/platform-tools
2. Extrayez et placez le dossier `platform-tools` dans :
   - Recommandé : `C:\platform-tools`
3. Connectez l'appareil Android via USB.
4. Activez les options développeur et le débogage USB sur le téléphone :
   - Paramètres → À propos du téléphone → tapez Numéro de build 7 fois.
   - Paramètres → Système → Options pour les développeurs → activez "USB debugging".
   - Autorisez le PC quand le téléphone le demande.
5. Si le script détecte automatiquement `adb` et propose un explorateur de fichiers, choisissez "Android via ADB..." et patientez — l'énumération peut être longue.
6. Si `adb` introuvable, vérifiez que `C:\platform-tools\adb.exe` existe et que `C:\platform-tools` est dans le PATH, ou lancez le script depuis un shell où `adb` est accessible.

Note: Windows Explorer may show the phone via MTP; ADB requires USB debugging and the adb daemon.  
Remarque : l'Explorateur Windows montre souvent le téléphone via MTP ; ADB nécessite le débogage USB et le démon adb.

---

## Behavior & UI notes / Comportement & interface

- The script shows a live log and a progress bar.  
- A "Cancel" button should stop scanning cleanly.  
- At the end of the scan the script usually offers actions: review, delete duplicates, or export a report. Always review the proposed deletions before confirming.

- Le script affiche un journal en temps réel et une barre de progression.  
- Un bouton "Cancel" doit arrêter le scan proprement.  
- À la fin du scan, le script propose généralement des actions : vérifier, supprimer les doublons ou exporter un rapport. Vérifiez toujours les suppressions proposées avant de confirmer.

---

## Troubleshooting / Dépannage

- Script does not run: ensure `python` is available in PATH. In PowerShell:
```powershell
python --version
```
- `adb` not found: verify `C:\platform-tools\adb.exe` exists and that `C:\platform-tools` is in PATH.
- Phone visible in Explorer but not to the script: Explorer uses MTP; the script requires ADB + authorized USB debugging.
- Long scan times: scanning large volumes or many small files can take long. Test on a small folder first.
- Permissions errors: admin rights typically not required. Run as admin only if necessary.

- Le script ne démarre pas : vérifiez que `python` est présent dans le PATH. Dans PowerShell :
```powershell
python --version
```
- `adb` introuvable : vérifiez que `C:\platform-tools\adb.exe` existe et que `C:\platform-tools` est dans le PATH.
- Téléphone visible dans l'Explorateur mais pas dans le script : l'Explorateur utilise MTP ; le script exige ADB + débogage USB autorisé.
- Temps de scan longs : de grands volumes ou beaucoup de petits fichiers prennent du temps. Testez d'abord sur un petit dossier.
- Erreurs de permission : les droits admin ne sont généralement pas nécessaires. N'exécutez en admin que si c'est requis.

---

## FAQs / Questions fréquentes

Q: I don't have ADB — can I still scan the phone?  
A: Not reliably. To scan via ADB you need Platform Tools + USB debugging enabled.

Q: Will the script overwrite or permanently delete files?  
A: Deletion is permanent unless you use recovery tools. The script should warn before deleting. Backup first.

Q: Does this require external Python packages?  
A: The original README indicates only the standard library. If additional packages are required, the script's help or a requirements file should list them.

Q : Je n'ai pas ADB — puis-je quand même scanner le téléphone ?  
R : Pas de manière fiable. Pour scanner via ADB, il faut Platform Tools + débogage USB activé.

Q : Le script écrasera-t-il ou supprimera-t-il définitivement des fichiers ?  
R : La suppression est permanente, sauf recours à des outils de récupération. Le script doit avertir avant suppression. Sauvegardez d'abord.

Q : Est-ce que des paquets Python externes sont nécessaires ?  
R : Le README original indique l'utilisation uniquement de la bibliothèque standard. Si des paquets supplémentaires sont requis, l'aide du script ou un fichier requirements devra les lister.

---

## Example workflows / Exemples d'utilisation

- Quick GUI run (double-click) / Exécution GUI rapide (double-clic)  
  1. Double-click `duplicate_finder.py`.  
  2. Choose target (Local folder / Removable drive / Android via ADB).  
  3. Wait for scan and review results.

- CLI run (PowerShell) / Exécution CLI (PowerShell)
```powershell
cd C:\path\to\duplicate-finder
python duplicate_finder.py
```
---

## Contributing, Support, and Contact / Contribution, support et contact

- Author / Maintainer: red923 — https://github.com/red923  
- For issues, bug reports, or feature requests: open an issue in this repository on GitHub. Provide Windows version, Python version, reproduction steps, and a minimal example when possible.

- Auteur / Mainteneur : red923 — https://github.com/red923  
- Pour signaler des bugs, demander des fonctionnalités : ouvrez une issue sur GitHub. Fournissez la version de Windows, la version de Python, les étapes pour reproduire et un exemple minimal si possible.

Optional contact from original README / Contact optionnel de l'original :  
- Facebook: https://web.facebook.com/regis.gakiza.9

---