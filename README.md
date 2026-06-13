# pwndbg ImGui Wrapper

Interface graphique pyimgui (via [imgui_bundle](https://github.com/pthom/imgui_bundle)) pour
afficher les sections de contexte pwndbg dans des fenêtres dockables, comme dans Ghidra :
drag & drop d'une fenêtre sur une autre = onglets ; détachable en fenêtre flottante (viewports).

## Installation

```bash
pip install imgui-bundle
```

Pwndbg doit être installé et chargé dans gdb (cf https://pwndbg.re/stable/setup/).

## Lancement

Terminal 1 — lance gdb + pwndbg avec la config `contextoutput` automatique :

```bash
python3 pwndbg_launcher.py ./mon_binaire
```

Cela crée un PTY par section (`regs`, `disasm`, `code`, `stack`, `backtrace`,
`args`, `threads`, `heap_tracker`, `expressions`, `last_signal`) et appelle
`contextoutput <section> <tty> True` pour chacune via un fichier gdbinit
temporaire (cf [doc officielle](https://pwndbg.re/stable/tutorials/splitting-the-context/)).

Terminal 2 — lance l'interface :

```bash
python3 gui.py
```

⚠️ `pwndbg_launcher.py` et `gui.py` doivent partager les mêmes PTYs : actuellement
chacun crée son propre `PtyManager`. Pour une vraie utilisation, il faut soit :

- lancer les deux dans **le même process** (le plus simple — voir `run_combined.py`
  ci-dessous), soit
- faire communiquer les chemins de PTY entre les deux process (ex: fichier JSON
  partagé, socket Unix).

## Usage de l'UI

- **Menu "Window"** (top bar) : coche/décoche chaque section pour
  l'afficher/masquer, ainsi que **"GDB Console"**.
- **GDB Console** : fenêtre dockable affichant stdout/stderr de gdb (PTY
  dédié) avec un champ de saisie en bas pour envoyer des commandes
  directement à gdb (Entrée pour valider, flèches haut/bas pour
  l'historique). C'est une vraie console gdb : tu peux y taper
  `b main`, `run`, `c`, `next`, etc.
- **Drag & drop** d'un onglet de fenêtre sur une autre fenêtre : fusionne en
  onglets dans le même panneau (comportement natif du docking ImGui).
- Drag & drop hors de toute zone de dock : détache la fenêtre en fenêtre OS
  flottante séparée (si `enable_viewports = True`, déjà activé).
- **Menu "View"** : active/désactive l'auto-scroll par section (et pour la
  console).
- **"Reset layout"** : recrée le layout de dock par défaut
  (disasm/code en haut-gauche, regs à droite, stack/backtrace/console en bas).

## Couleurs ANSI

Les sorties pwndbg sont colorées via des séquences ANSI SGR (`\x1b[31m...`).
`ansi.py` parse ces séquences (couleurs 0-15, 256 couleurs, RGB direct, bold,
underline, reverse) et `render_ansi_text()` dans `gui.py` affiche chaque
ligne comme une suite de `imgui.text_colored` + `same_line()`, ce qui
préserve les couleurs originales de regs/disasm/etc. directement dans
l'UI (au lieu de `input_text_multiline`, qui ne supporte pas le texte
coloré).

## Lancement combiné (recommandé)

Pour éviter le problème de PTYs séparés, lance tout depuis un seul script :

```python
# run_combined.py
import threading
from pty_manager import PtyManager
from pwndbg_launcher import PwndbgLauncher
from gui import main_with_manager  # variante de main() acceptant un PtyManager existant

pm = PtyManager()
launcher = PwndbgLauncher(pty_manager=pm, binary="./mon_binaire")
launcher.start()  # lance gdb dans un sous-process, hérite du terminal courant

main_with_manager(pm)  # lance la fenêtre ImGui (bloquant)

launcher.stop()
pm.close_all()
```
