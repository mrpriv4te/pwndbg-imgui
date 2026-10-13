# pwndbg-imgui

Interface Dear ImGui (via [imgui_bundle](https://github.com/pthom/imgui_bundle)) pour
[pwndbg](https://pwndbg.re), façon Ghidra/IDA : toutes les sections du contexte dans des
fenêtres dockables, plus des outils qui exploitent pwndbg directement.

**Un seul fichier** : `pwndbg_imgui.py`.

## Installation

```bash
pip install imgui-bundle
ln -s "$PWD/pwndbg_imgui.py" ~/.local/bin/pwndbg-imgui   # optionnel
```

pwndbg doit être installé. Il est chargé, dans l'ordre :
1. par ton `gdbinit` s'il le fait déjà,
2. sinon via une commande utilisateur `init-pwndbg` si elle existe,
3. sinon depuis `$PWNDBG_PATH`, `~/.local/share/pwndbg`, `~/pwndbg`, `/usr/share/pwndbg`…

(ou explicitement : `--pwndbg ~/chemin/pwndbg`, `--init-cmd init-pwndbg`).

## Utilisation

Comme `pwndbg` / `gdb` : tout ce qui n'est pas une option de l'interface est passé à gdb.

```bash
pwndbg-imgui ./chall
pwndbg-imgui --args ./chall arg1 arg2
pwndbg-imgui -p 1234
pwndbg-imgui ./chall core
pwndbg-imgui -ex 'target remote :1234' ./chall
```

Options de l'interface : `--gdb PATH`, `--pwndbg PATH`, `--init-cmd CMD`, `--no-pwndbg`,
`--theme NAME`, `--font PATH`, `--font-size N`, `--no-io`, `--no-viewports`, `--maximize`,
`--reset-layout`, `--list-themes` (voir `--help`).

## Fonctionnalités

- **Contexte pwndbg** : Registers, Disassembly, Source, Stack, Backtrace, Arguments, Watch,
  Threads, Heap Tracker, Last Signal. Chaque section s'adapte à la taille de sa fenêtre
  (disasm/stack/source/backtrace affichent exactement le nombre de lignes visibles) et
  seules les sections affichées sont calculées.
- **Adresses cliquables partout** : survol = région mémoire + chaîne de déréférencement
  pwndbg ; Ctrl+clic = ouvrir dans la vue mémoire ; clic droit = telescope, désassembler,
  xinfo, chercher les pointeurs, breakpoint, watchpoint…
- **Breakpoints** : clic dans la marge de Disassembly/Source, fenêtre dédiée (activer,
  conditions, compteurs de hits, watchpoints), mémorisés par binaire.
- **Console gdb** : couleurs, historique persistant, complétion Tab (via gdb), Entrée vide
  = répéter la dernière commande, Ctrl+C = interrompre.
- **Program I/O** : le programme débogué a son propre terminal (stdin/stdout séparés de
  gdb), en mode brut (binary-safe). Envoi en texte, hex ou expression Python façon
  pwntools (`b"A"*40 + p64(0x401136)`, `flat(...)`, `cyclic(100)`), octets non
  imprimables affichés en `\xNN`, vue hexdump de la sortie.
- **Mémoire** : hexdump/qwords colorés par région (légende pwndbg), octets modifiés depuis
  le dernier arrêt surlignés, édition en place (tape des chiffres hexa), suivi automatique
  d'une expression (`$sp`, `$rdi`…), inspecteur de valeurs.
- **VMMap**, **navigateur de commandes pwndbg** (aide intégrée), **éditeur de la config
  pwndbg**, **vues de commandes** live (n'importe quelle commande, rafraîchie à chaque
  arrêt : `heap`, `bins`, `vis_heap_chunks`, `got`, `telescope`…), **pattern cyclic**
  (générer, envoyer au programme, retrouver un offset depuis `$pc`/`$sp`).
- **Palette de commandes** (Ctrl+P), barre d'outils (Run/Start/Continue/Pause/Step…),
  barre d'état (pid, arch, checksec, légende), notifications (breakpoint, signal, exit).
- **Barre de titre intégrée** au thème (glisser pour déplacer, double-clic pour maximiser ;
  désactivable dans Preferences pour retrouver celle du système).
- **13 thèmes** (sombres et clairs, contraste corrigé automatiquement), zoom du code
  (Ctrl+molette), polices système, layout et réglages persistants
  (`~/.config/pwndbg-imgui/`).

Raccourcis : F5 continue/run · F6 pause · F7/F8 si/ni · Shift+F7/F8 step/next ·
Ctrl+F7 finish · Shift+F5 kill · Ctrl+P palette · Ctrl+G aller à une adresse ·
Ctrl+F rechercher (menu Help → Keyboard shortcuts pour la liste complète).

## Fonctionnement

Le script joue deux rôles. Lancé normalement, il crée un PTY pour la console gdb et un
pour le programme, puis démarre gdb en se sourçant lui-même dedans (`runpy`) comme
« agent » (bibliothèque standard uniquement). L'agent redirige chaque section du contexte
vers l'interface (`contextoutput` avec un callable) et répond à des requêtes JSON
(mémoire, vmmap, breakpoints, complétion…) sur un `socketpair` hérité.
