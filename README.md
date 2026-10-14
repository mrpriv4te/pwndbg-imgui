# pwndbg-imgui

Interface Dear ImGui (via [imgui_bundle](https://github.com/pthom/imgui_bundle)) pour
[pwndbg](https://pwndbg.re), façon Ghidra/IDA : toutes les sections du contexte dans des
fenêtres dockables, plus des outils qui exploitent pwndbg directement.

## Installation

Avec [pipx](https://pipx.pypa.io), dans son propre environnement (imgui-bundle inclus) :

```bash
pipx install .                 # depuis ce dossier
pipx install -e .              # pour développer : les modifications du code sont prises en compte
pipx upgrade pwndbg-imgui      # après un `git pull` (sans -e : `pipx install --force .`)
```

La commande `pwndbg-imgui` est alors disponible (`python -m pwndbg_imgui` fonctionne aussi).

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

### S'attacher à une session gdb existante (`init-pwndbg-ui`)

Pour ouvrir l'interface depuis un gdb déjà lancé (utile avec `gdb.debug`/`gdb.attach` de
pwntools), ajoute une fois la commande `init-pwndbg-ui` à ton gdbinit :

```bash
pwndbg-imgui --gdbinit >> ~/.config/gdb/gdbinit
```

Ensuite, dans n'importe quelle session gdb :

```
(gdb) init-pwndbg-ui        # charge pwndbg si besoin puis ouvre l'interface, attachée à ce gdb
```

gdb reste dans son terminal (c'est là que vivent le programme et sa saisie) ; l'interface
affiche le contexte et pilote gdb. Fermer l'interface rend le contexte au terminal.
`$PWNDBG_IMGUI_ARGS` passe des options (ex. `export PWNDBG_IMGUI_ARGS=--maximize`).

Dans un script pwntools, il suffit d'ajouter `init-pwndbg-ui` au `gdbscript` (ou
d'utiliser `context.gdb_binary = "pwndbg-imgui"`). Un template prêt à l'emploi avec
l'option `-d ui` est généré par :

```bash
pwndbg-imgui --exploit            # crée ./exploit.py
pwndbg-imgui --exploit > e.py     # ou vers un autre fichier
```

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

Deux modes, mais le même agent côté gdb :

- **Lancé par l'interface** (`pwndbg-imgui ./chall`) : l'interface crée un PTY pour la
  console gdb et un pour le programme, puis démarre gdb en lui faisant charger `agent.py`.
- **Attaché** (`init-pwndbg-ui` dans un gdb existant) : gdb garde son terminal ; `agent.attach()`
  lance l'interface et lui passe un `socketpair`. Fermer l'interface rend le contexte au
  terminal (l'agent se désenregistre proprement).

Dans les deux cas gdb charge `agent.py` **par son chemin** : gdb utilise son propre Python
(celui de pwndbg), qui ne doit pas voir l'environnement pipx. L'agent (bibliothèque standard
uniquement) redirige chaque section du contexte vers l'interface (`contextoutput` avec un
callable) et répond à des requêtes JSON (mémoire, vmmap, breakpoints, complétion,
décompilation, console…) sur le `socketpair`.

```
src/pwndbg_imgui/
├── cli.py            point d'entrée, options (n'importe l'interface qu'au lancement)
├── agent.py          côté gdb (stdlib uniquement)
├── transport.py      client RPC + PTYs
├── term.py           mini émulateur de terminal (ANSI)
├── theme.py          couleurs et thèmes
├── settings.py       réglages persistants
├── fonts.py          recherche des polices (fontconfig)
├── payload.py        cyclic, expressions de payload, hexdump
└── ui/
    ├── app.py        état, process gdb, événements, runner hello_imgui
    ├── chrome.py     menus, barre d'outils/titre/état, palette, dialogues
    ├── panels.py     fenêtres outils (console, I/O, vmmap, breakpoints…)
    ├── sections.py   comportement des sections du contexte
    ├── views.py      vues mémoire, décompilateur, commandes
    ├── widgets.py    TextView et helpers
    ├── appearance.py polices et application du thème
    ├── native.py     contrôle de la fenêtre GLFW (barre de titre)
    └── catalog.py    sections et presets d'outils
```
