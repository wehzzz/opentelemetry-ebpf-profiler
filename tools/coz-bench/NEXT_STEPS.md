# NEXT_STEPS — sched_ext backend + full Coz benchmark suite

Roadmap pour la prochaine itération. Conçu pour qu'une **nouvelle conversation
Claude** (ou un nouvel ingénieur) puisse reprendre le projet sans rouvrir
toute l'historique.

---

## TL;DR

- Le pipeline Coz expérimental (`internal/experimental/coz/`) fonctionne mais
  son backend de perturbation **ptrace** coûte ~50–100 µs/event et ce coût
  domine le bruit des slopes mesurés (cf. [RESULTS.md](RESULTS.md) §4).
- Plan : **remplacer ptrace par un BPF sched_ext** (kernel ≥6.12), qui fait le
  throttling natif kernel sans round-trip userspace.
- Bénéfice attendu : overhead par event divisé par ~50, IC des slopes
  rétrécis d'un facteur √50 ≈ 7×, plusieurs benchs passent de FAIL à PASS
  stable.
- Coût : **~2 semaines** de dev focus, kernel 6.12+ requis.

---

## Pourquoi sched_ext et pas autre chose

| Mécanisme | Coût | Per-thread ? | Throttle gradué | Sémantique Coz |
|-----------|------|-------------|-----------------|----------------|
| ptrace (actuel) | ~50–100 µs/event | ✓ | ✓ | ✓ exacte |
| SIGSTOP/SIGCONT | ~10–20 µs/event | ❌ thread-group-wide | — | — |
| cgroup v2 cpu.max | ~0 pendant fenêtre | ✓ (via threaded mode) | ✓ | ~ continue (drift) |
| SCHED_IDLE | ~5–10 µs setup | ✓ | ❌ binaire | partiel |
| **sched_ext** | **~0 (callback BPF)** | **✓** | **✓** | **✓ exacte** |

Le détail complet de cette analyse est dans l'historique de la conversation
précédente. Résumé : sched_ext est la **seule option** qui combine cheap +
sémantique conditionnelle exacte + gradué + per-thread + pas de modification
de binaire.

---

## Pré-requis hardware/kernel

| Composant | Requirement | Note |
|-----------|-------------|------|
| Kernel | ≥6.12 avec `CONFIG_SCHED_CLASS_EXT=y` | **VM dev** : Ubuntu 6.17.0-14-generic confirmé OK. **EC2 actuelle** (Ubuntu 6.8) **NE SUPPORTE PAS** — pas de dev/test possible dessus |
| Clang | ≥17 | Pour BPF CO-RE et target=bpf |
| libbpf | ≥1.4 | API sched_ext stabilisée |
| linux-tools-generic | matching kernel | Pour `bpftool` |
| Priv | CAP_BPF + CAP_SYS_ADMIN ou sudo | Loading struct_ops |

**EKS** : noeud par défaut en 6.1 → trop vieux. Soit nouvelle AMI Bottlerocket
récente, soit attendre AWS bump. Hors scope dev court terme.

---

## Plan d'implémentation (suit la séquence des tasks #12 à #18)

### Étape 1 — Bootstrap dev env (Task #12)

```bash
# Sur la VM 6.17 :
sudo apt update
sudo apt install -y clang-17 llvm-17 libbpf-dev linux-tools-generic linux-headers-$(uname -r)

# Vérifier que sched_ext est compilé
cat /sys/kernel/sched_ext/state
# attendu : "disabled" (= dispo mais pas activé)

# Cloner scx comme référence
git clone https://github.com/sched-ext/scx /tmp/scx
cd /tmp/scx
meson setup build --buildtype=release
meson compile -C build
# Tester scx_simple comme hello-world
sudo build/scheds/c/scx_simple
# Si ça tourne sans crasher la machine -> toolchain OK
```

### Étape 2 — BPF scheduler (Task #13)

Créer `support/ebpf/coz_sched.bpf.c`. Structure minimale :

```c
struct sched_ext_ops coz_sched_ops = {
    .select_cpu  = (void *)coz_select_cpu,
    .enqueue     = (void *)coz_enqueue,
    .dispatch    = (void *)coz_dispatch,
    .runnable    = (void *)coz_runnable,
    .stopping    = (void *)coz_stopping,
    .init        = (void *)coz_init,
    .exit        = (void *)coz_exit,
    .name        = "coz_sched",
};

// Map: TID -> throttle_level (0=normal, 100=fully paused)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 4096);
} coz_throttle_set SEC(".maps");

// Global flag: 1 if some target TID is currently in target function
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} coz_target_active SEC(".maps");
```

Logique throttle :
- Dans `enqueue` : si tid est dans `coz_throttle_set` ET `target_active` est 1,
  diriger la task vers une low-priority DSQ (dispatch queue) qui sera
  consommée uniquement quand la high-prio DSQ est vide. Cela approxime un
  throttle gradué via le ratio de temps target_active vs inactive.
- Pour throttle gradué fin (5%, 10%, 20%) : maintenir un compteur de duty
  cycle. Quand target_active passe à 1, ne défer que `throttle_level%` des
  enqueues vers low-prio (skip le reste via random sampling déterministe).

Référence API : `kernel/sched/ext.c` dans les sources kernel + scx_simple/
scx_qmap comme exemples minimaux.

### Étape 3 — Wire les uprobes existants (Task #14)

Modifier `support/ebpf/coz.ebpf.c` :

```c
// Dans coz_target_enter (après les check existants) :
u32 key = 0;
u32 *active = bpf_map_lookup_elem(&coz_target_active, &key);
if (active) {
    __sync_fetch_and_add(active, 1);
}

// Dans coz_target_exit (après les check existants) :
u32 key = 0;
u32 *active = bpf_map_lookup_elem(&coz_target_active, &key);
if (active && *active > 0) {
    __sync_fetch_and_sub(active, 1);
}
```

Le compteur (au lieu d'un booléen) gère le cas où plusieurs threads de la
target sont simultanément dans la target function.

**Important** : `coz_target_active` doit être partagé entre `coz.ebpf.c` et
`coz_sched.bpf.c`. Soit via map pinning dans BPF FS (`/sys/fs/bpf/coz/target_active`),
soit via lien à la compilation (un seul objet BPF avec les deux programs).
Le pinning est plus propre pour le découplage.

### Étape 4 — Backend userspace (Task #15)

Nouveau fichier `internal/experimental/coz/schedext_linux.go` :

```go
type SchedExtBackend struct {
    throttleMap   *ebpf.Map  // TID -> throttle level
    targetActive  *ebpf.Map  // global flag
    schedLink     link.Link  // struct_ops attachment
    attachedTIDs  []int      // non-target TIDs we control
}

func NewSchedExtBackend(bpfObjectPath string) (*SchedExtBackend, error) {
    // Load BPF object, find sched_ext struct_ops, link.AttachStructOps()
}

func (b *SchedExtBackend) Attach(tids []int) error {
    // Store tids; nothing to do at attach time (apply will populate map)
}

func (b *SchedExtBackend) Apply(ctx, target, speedup, duration) (PerturbationStats, error) {
    // Get current target ActiveTIDs
    state, _ := target(ctx)
    // Populate throttle_set: every attached TID NOT in active gets throttle=speedup
    // Wait the duration (target_active flag is maintained by uprobes during this time)
    // Clear throttle_set
}

func (b *SchedExtBackend) Detach() error {
    // Unload struct_ops, close maps
}
```

Ajouter au runner :
```go
flag.StringVar(&backend, "backend", "ptrace", "Perturbation backend: ptrace | schedext")
```

Et un constructeur factory dans `coz.NewController`.

### Étape 5 — Validation sur les 5 benchs (Task #16)

```bash
# Sur la VM 6.17, depuis ce repo :
sudo /tmp/coz-verify -bench lockheavy -backend schedext -budget 120s ...
# Comparer avec :
sudo /tmp/coz-verify -bench lockheavy -backend ptrace -budget 120s ...
```

Critère de succès : sur 3 runs consécutifs avec le backend sched_ext :
- `lockheavy` : PASS sur 3/3
- `coz_lock` : PASS sur 3/3
- Au moins 1 des 3 autres benchs passe en PASS

Si oui → backend validé, passer à l'étape 6. Si non → debug
(probablement throttle gradué incorrect, ou wire-up uprobe→sched cassé).

### Étape 6 — Porter pbzip2 + Phoenix (Task #17)

**pbzip2** :
```bash
sudo apt install -y libbz2-dev
curl -O https://github.com/plasma-umass/coz/archive/master.tar.gz
tar xzf master.tar.gz coz-master/benchmarks/pbzip2
# Adapter pbzip2.cpp : remplacer #include <coz.h> et COZ_PROGRESS par appels à
# bench_progress() local + ajouter bench_compress_step() comme target candidate
make -C tools/coz-bench bench_pbzip2
```

Bench spec dans `verify/main.go` :
```go
"pbzip2": {
    binary: "bench_pbzip2",
    progressSymbol: "bench_progress",
    autoTargets: 5,
    cpuPin: "0,1,2,3",  // pbzip2 scale = besoin de plusieurs cores
    expectations: func(ranks []targetRanking) []string {
        // Coz paper §6.2: consumer thread shows +9% slope
        // Notre attente: bench_consumer_step (or équivalent) #1
        return assertHigher(ranks, "bench_consumer_step", "bench_producer_step")
    },
},
```

**Phoenix benchs** (histogram, kmeans, linear_regression, matrix_multiply,
pca, string_match, word_count) :

Chacun a un fichier unique `*-pthread.c` + `stddefines.h` upstream. Process :

```bash
for bench in histogram kmeans linear_regression matrix_multiply pca string_match word_count; do
  curl -O https://raw.githubusercontent.com/plasma-umass/coz/master/benchmarks/$bench/$bench-pthread.c
  # Renommer en bench_coz_<bench>.c
  # Remplacer COZ_PROGRESS par bench_progress()
  # Identifier 1-2 fonctions sur le chemin critique pour les exposer comme symboles
  # Générer un dataset d'entrée si nécessaire (chaque bench a un format spécifique)
done
```

Tableau des datasets attendus (à confirmer dans chaque .c) :
- histogram : image bitmap (taille ~10MB)
- kmeans : points 2D générés au démarrage si pas d'argument
- linear_regression : key-value txt (~50MB)
- matrix_multiply : matrices générées
- pca : matrice générée
- string_match : keys file + corpus
- word_count : texte (~10MB)

### Étape 7 — Rapport final (Task #18)

Mettre à jour `tools/coz-bench/RESULTS.md` avec :
- Tableau 12 benchs × 2 backends (slope, CI, status, verdict)
- Pour chaque PASS : pointer le pattern performance-patterns concerné si
  applicable
- Pour chaque FAIL persistant après sched_ext : diagnostic (variance interne
  du workload, sémantique cgroup-drift, effet causal trop petit, etc.)
- Comparaison avec les slopes du Coz paper où documenté

---

## Comment lancer les benchs (state actuel + futur)

### État actuel (backend ptrace, kernel 6.8 OK)

```bash
cd /home/bits/go/src/github.com/DataDog/opentelemetry-ebpf-profiler

# Build
make -C support/ebpf coz
make -C tools/coz-bench
go build -o /tmp/coz-runner ./tools/coz-runner
go build -o /tmp/coz-verify ./tools/coz-bench/verify

# Lancer un bench
sudo /tmp/coz-verify \
  -bench lockheavy \
  -bench-dir ./tools/coz-bench \
  -runner /tmp/coz-runner \
  -bpf-object ./support/ebpf/coz.ebpf.amd64 \
  -budget 120s \
  -report /tmp/coz-verify-lockheavy.json

# Tous les benchs en série
sudo ./tools/coz-bench/run-all-benches.sh
```

### Après l'étape 4 (backend sched_ext, kernel ≥6.12 requis)

```bash
# Sur la VM 6.17 :
sudo /tmp/coz-verify \
  -bench lockheavy \
  -backend schedext \
  -sched-bpf-object ./support/ebpf/coz_sched.bpf.amd64 \
  ...autres flags inchangés...
```

---

## Architecture rapide (état actuel)

```
coz-runner (CLI)
  └─ internal/experimental/coz/
      ├─ controller.go    — orchestration, rotation block-randomisée
      ├─ schedule.go      — génération cell pool + shuffle par round
      ├─ types.go         — Config, validation, defaults
      ├─ bpf.go           — interface BPFProgramSet + DeltaCounter
      ├─ program.go       — ProgramSet (cilium/ebpf wrapper)
      ├─ ptrace_linux.go  — BACKEND ACTUEL (à compléter pas remplacer)
      ├─ sampler_linux.go — perf_event_open ring buffer pour auto-pick
      ├─ autopick.go      — symbolisation + top-K noise filter
      ├─ analysis.go      — régression slope HC1 + status enum
      ├─ report.go        — JSON output shape
      └─ proc.go          — enumeration TIDs

support/ebpf/
  ├─ coz.ebpf.c       — uprobes coz_progress / coz_target_enter/exit
  └─ (futur) coz_sched.bpf.c — sched_ext scheduler

tools/coz-bench/
  ├─ bench_*.c        — benchmarks (5 existants + 8 à porter)
  ├─ verify/main.go   — driver de validation (PASS/FAIL)
  ├─ run-all-benches.sh — wrapper
  ├─ RESULTS.md       — résultats documentés
  └─ NEXT_STEPS.md    — ce fichier
```

---

## Survival tips pour une fresh conversation

Points non-évidents découverts en cours de route :

1. **`runtime.LockOSThread()` dans Controller.Start** ([controller.go:73](../../internal/experimental/coz/controller.go:73))
   est CRITIQUE pour ptrace. Sans ce pin, `PtraceSeize` et `PtraceInterrupt`
   s'exécutent sur des OS threads différents → `ESRCH` silencieux. C'est un
   piège classique de la combinaison Go scheduler + ptrace. **Pour sched_ext
   ce n'est pas nécessaire** — l'API ne dépend pas du caller TID.

2. **`s=100` (full pause)** : notre `applyFullPause` actuel attrape parfois
   le thread porteur du target quand il est entre 2 itérations (dans sem_post
   ou exit-uprobe gap) et le bloque pour toute la fenêtre → throughput collapse.
   **Pour le verify on a supprimé s=100 des speedups**. Avec sched_ext on
   pourra rétablir s=100 cleanly puisque le scheduler n'arrête pas un thread
   qui est en chemin vers la target function.

3. **L'auto-pick doit filtrer le progress symbol** ([main.go](../coz-runner/main.go))
   — sinon `bench_progress` finit dans les targets et pollue le ranking.
   C'est déjà patché mais à ne PAS régresser.

4. **Pinning CPU** : sans `taskset` qui force la contention, pauser les
   non-target ne libère rien → pas de signal Coz. Tous les bench specs ont
   un `cpuPin` adapté dans verify/main.go.

5. **L'unique map BPF coz_target_state** garde le `target_id` ET le `depth`
   par thread. La logique BPF rejette les exits dont le `target_id` ne match
   pas la dernière entrée → **pas de nested targets supportés**. Pour
   sched_ext on aura besoin de modifier ça si on veut supporter des
   appels nested.

6. **Budget vs Rounds** : `-rounds 0 -budget 60s` veut dire "unlimited rounds,
   bornée par budget". `-rounds 5` = exactement 5 rounds. Bug fixé dans
   [types.go:Normalize](../../internal/experimental/coz/types.go) — la
   valeur par défaut Rounds=5 ne s'applique QUE si Budget est aussi à 0.

7. **Les windows écrivent un rapport partiel à la fin de chaque round** —
   donc une interruption Ctrl+C garde les résultats.

8. **Les benchs avec progress > 1000/s** (coz_pc, par exemple) bouffent du
   CPU sur la résolution BPF map → variance plus grande. Pour ces benchs,
   préférer un workload plus lourd par item de progress.

---

## Hypothèses à valider quand le backend sched_ext est en place

- [ ] Overhead par cell window passe de ~100ms à <10ms
- [ ] IC half-width des slopes réduit d'au moins 5×
- [ ] `lockheavy` passe PASS sur 3/3 runs consécutifs
- [ ] `coz_lock` passe PASS sur 3/3 runs consécutifs
- [ ] La sémantique conditionnelle (slope identique à Coz pour des targets qui
      dominent le workload) tient
- [ ] On peut rétablir `s=100` sans collapse de throughput

Si tout coche → on est à niveau papier pour les workloads CPU-bound. La
prochaine extension serait du support JIT (Java/Python) — cf. discussion
précédente sur l'intégration avec le profiler de prod.

---

## Pour démarrer une nouvelle conversation

Donne au futur Claude :
- Ce fichier (`tools/coz-bench/NEXT_STEPS.md`)
- [tools/coz-bench/RESULTS.md](RESULTS.md) (état des résultats actuels)
- [internal/experimental/coz/](../../internal/experimental/coz/) (le package à étendre)
- Accès SSH à la VM 6.17
- Le TaskList existant (#12–#18 ouverts)

Commande de prompt suggérée :
> "Reprends le projet Coz expérimental documenté dans tools/coz-bench/NEXT_STEPS.md.
> Tu as accès SSH à une VM Ubuntu 6.17. Commence par la Task #12 (bootstrap
> sched_ext dev env) en vérifiant que la toolchain marche, puis enchaîne sur
> #13. Pas d'option A intermediate — on va direct sur sched_ext (D)."
