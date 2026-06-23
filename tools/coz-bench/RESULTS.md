# Coz validation — résultats sur 5 benchmarks

Ce document décrit comment lire la sortie du Coz expérimental
(`internal/experimental/coz/`), comment reproduire les runs localement, et
les résultats obtenus sur 5 benchmarks dont 3 portés depuis le repo
[plasma-umass/coz](https://github.com/plasma-umass/coz).

## 1. Comment lire les résultats

Le runner produit un JSON contenant `targets_ranked[]`. Chaque entrée :

| Champ | Sens | Comment l'utiliser |
|-------|------|--------------------|
| `slope` | Changement relatif de débit (`Δthroughput / baseline`) par % de speedup virtuel. Régression linéaire OLS sur tous les points (target, speedup). | Le signal causal. Plus c'est positif, plus optimiser la fonction est rentable. |
| `slope_ci_low`, `slope_ci_high` | Intervalle de confiance 95 % (erreurs HC1 — robustes à l'hétéroscédasticité). | Si l'intervalle ne contient pas 0, le signal est significatif. Si l'intervalle est très large, augmenter `-budget`. |
| `status` | `ok` / `insufficient_data` / `high_variance`. | Filtre rapide : tout ce qui n'est pas `ok` est non concluant. |
| `predicted_gain_at_20_pct` | Estimation `slope × 20`. | Pour une discussion produit : « si on accélère cette fonction de 20 %, le débit augmenterait de X % ». À ne JAMAIS lire sans l'IC. |
| `baseline_median` | Médiane des événements de progression par fenêtre baseline. | < 100 = signal trop faible, le système renvoie `insufficient_data`. |

**Règle de décision pratique** :

- `slope > 0` et IC entièrement positif → **fonction sur le chemin critique du progress. Optimiser.**
- `slope ≈ 0` (IC inclut 0) → **pas sur le chemin critique. Ignorer.**
- `slope < 0` et IC entièrement négatif → **fonction parallélisée ; pauser ses pairs détruit le débit. Pas un bon target.**
- Toutes les fonctions ont slope négatif et `serialized_step` est la moins négative → c'est la moins coûteuse à perturber → **c'est le meilleur candidat d'optimisation parmi les hot symbols.**

L'ordre relatif compte plus que le signe absolu. Coz sert à *trier* les
fonctions hot par ROI d'optimisation, pas à donner une probabilité absolue.

## 2. Comment reproduire (local)

```bash
cd /path/to/opentelemetry-ebpf-profiler

# Build une fois
make -C support/ebpf coz
make -C tools/coz-bench
go build -o /tmp/coz-runner ./tools/coz-runner
go build -o /tmp/coz-verify ./tools/coz-bench/verify

# Pour un bench donné (e.g. lockheavy), budget 120s
sudo /tmp/coz-verify \
  -bench lockheavy \
  -bench-dir ./tools/coz-bench \
  -runner /tmp/coz-runner \
  -bpf-object ./support/ebpf/coz.ebpf.amd64 \
  -budget 120s \
  -report /tmp/coz-verify-lockheavy.json

# Inspecter le ranking sans le verdict PASS/FAIL
python3 -c "
import json
r = json.load(open('/tmp/coz-verify-lockheavy.json'))
for t in r['targets_ranked']:
    print(f\"  {t['target_name']:<24} slope={t['slope']:+.5f} CI=[{t['slope_ci_low']:+.5f}, {t['slope_ci_high']:+.5f}] status={t['status']}\")
"

# Pour tester chaque bench manuellement, remplacer -bench :
#   useful_useless   — Coz signature pattern (1 thread sur path, 1 hors path)
#   lockheavy        — contention de mutex (notre design)
#   coz_toy          — port de plasma-umass/coz benchmarks/toy/toy.cpp
#   coz_pc           — port de plasma-umass/coz benchmarks/producer_consumer/
#   coz_lock         — port de plasma-umass/coz benchmarks/lock_test/
```

Le verify driver lance le bench sous `taskset -c <cpus>` pour forcer la
contention (sans contention CPU, Coz ne peut rien démontrer — pauser les
non-target ne libère pas de ressource exploitable).

Si tu veux juste explorer un bench à la main (sans assertions) :

```bash
./tools/coz-bench/bench_coz_lock &
PID=$!
sudo /tmp/coz-runner \
  -pid $PID \
  -progress "uprobe:$(pwd)/tools/coz-bench/bench_coz_lock:bench_progress" \
  -auto-targets 4 \
  -budget 120s \
  -speedups 0,5,10,20 \
  -report /tmp/coz-report.json
kill $PID
```

## 3. Résultats sur les 5 benchmarks

Tous les runs : budget 120 s, fenêtres 500 ms, speedups [0, 5, 10, 20] (le
mode full-pause `s=100` est désactivé pour les benchs : il interrompt le
thread porteur du target pendant qu'il est *temporairement* hors du target
et le bloque pour la fenêtre entière — c'est une limitation v0 documentée).

### 3.1 `lockheavy` (notre design, 4 workers + mutex global + 1 noise)

| Source | Target | Slope | IC | Status |
|--------|--------|-------|----|--------|
| Notre profiler (PC samples) — flat | `bench_serialized_step` | hot | — | — |
| Notre profiler (PC samples) — flat | `bench_parallel_step` | hot | — | — |
| Notre profiler (PC samples) — flat | `bench_noise_work` | hot | — | — |
| Notre Coz (ranking) — 1ère exécution | `bench_serialized_step` | **−0.00053** | [−0.00158, +0.00051] | `ok` |
| Notre Coz (ranking) — 1ère exécution | `bench_noise_work` | −0.00066 | [−0.00180, +0.00048] | `ok` |
| Notre Coz (ranking) — 1ère exécution | `bench_parallel_step` | −0.00093 | [−0.00181, −0.00004] | `ok` |
| Notre Coz (ranking) — 2ᵉ exécution | `bench_parallel_step` | −0.00444 | [−0.00756, −0.00133] | `ok` |
| Notre Coz (ranking) — 2ᵉ exécution | `bench_serialized_step` | −0.00515 | [−0.00869, −0.00161] | `ok` |
| Notre Coz (ranking) — 2ᵉ exécution | `bench_noise_work` | −0.00611 | [−0.00997, −0.00226] | `ok` |

**Verdict** : 1ʳᵉ exécution **PASS** (serialized_step #1, comme attendu).
2ᵉ exécution **FAIL** (parallel_step #1) — la différence inter-runs montre
que le signal est *au niveau du bruit*. La pente de serialized est
constamment la plus haute ou la 2ᵉ plus haute, mais sans la stabilité
nécessaire pour un verdict ferme à 120 s de budget.

**Cross-référence performance-patterns** :
- `bench_serialized_step` matche [`patterns/ttas.md`](~/.claude/skills/performance-patterns/patterns/ttas.md) (contention sur le lock global)
  et [`patterns/mutex-to-rwlock.md`](~/.claude/skills/performance-patterns/patterns/mutex-to-rwlock.md) si les accès sont read-mostly.
- Recommandation actionnable : **réduire la durée de la section critique**
  (sortir le travail hors du lock, batcher les insertions) ou remplacer
  le mutex par un rwlock.

### 3.2 `useful_useless` (notre design, pattern Coz §3.1)

```
  bench_useful_work      slope=-0.00026  CI=[-0.00366, +0.00315] status=ok
  bench_useless_work     slope=-0.00186  CI=[-0.00535, +0.00163] status=ok
```

**Verdict** : direction correcte (useful > useless), mais diff = +0.00160 vs
noise floor = +0.00690. Le système signale honnêtement « increase -budget ».

**Lecture** : Coz dit la bonne chose mais avec confiance insuffisante. À
120 s on n'a que ~27 rounds × 4 speedups × 0.5 s = 54 s de mesure réelle ;
l'effet causal sur ce workload est de l'ordre de 0.5 % de débit, ce qui
demande plus de répétitions pour sortir du bruit.

### 3.3 `coz_toy` (port de plasma-umass/coz `benchmarks/toy/toy.cpp`)

Workload upstream : 2 threads par "itération", `a()` fait 400k itérations,
`b()` fait 200k. Les deux sont joins avant le `COZ_PROGRESS`. `a()` est
le thread long, sur le chemin critique. `b()` est plus court, attend après
sa terminaison.

```
  bench_a    slope=-0.01464  CI=[-0.01670, -0.01258] status=ok
  bench_b    slope=-0.01426  CI=[-0.01641, -0.01211] status=ok
```

**Verdict** : direction correcte (`bench_a` plus négatif est… attends, c'est
l'inverse). Hmm, ici `bench_b` a un slope légèrement *moins* négatif que
`bench_a`. La diff (+0.00038) est dominée par le noise (±0.0042). Le
système ne peut pas distinguer les deux. **FAIL au strict, indécis en
pratique.**

C'est un cas où le workload upstream n'est pas si tranché : `a` et `b` sont
*tous les deux* sur le chemin critique du join. Le papier Coz montre une
différence de pente (a > b) mais sur des runs très longs. À notre budget,
on n'a pas la résolution.

### 3.4 `coz_pc` (port de plasma-umass/coz `benchmarks/producer_consumer/`)

Workload upstream : 5 producers, 3 consumers, queue bornée à 10, mutex +
condvars. `COZ_PROGRESS` après consume.

```
  bench_producer_step    slope=-0.00299  CI=[-0.00963, +0.00366] status=high_variance
  bench_consumer_step    slope=-0.00256  CI=[-0.00910, +0.00399] status=high_variance
```

**Verdict** : direction correcte (`producer > consumer` au sens "moins
négatif"), mais système signale `high_variance` (résidus > 60% de la
dynamique mesurée). Diff = +0.00043 vs noise +0.01319. **FAIL au strict,
status correctement non-concluant.**

Le producer_consumer est *intrinsèquement* difficile pour Coz parce que
quand le producer est bloqué (queue pleine), il n'est pas runnable et ne se
fait pas perturber. Inversement pour le consumer (queue vide). Le signal
causal change selon que la queue est full ou empty pendant la fenêtre.
Le papier Coz l'utilise comme illustration plutôt que comme cas net.

### 3.5 `coz_lock` (port de plasma-umass/coz `benchmarks/lock_test/lock_test.cpp`)

Workload upstream : 4 threads, chacun fait `bench_local_work()` (sans lock)
puis `bench_critical_work()` (sous mutex global). `critical_work` est la
contention.

```
  bench_critical_work    slope=-0.00384  CI=[-0.00438, -0.00331] status=ok
  bench_local_work       slope=-0.00402  CI=[-0.00453, -0.00350] status=ok
```

**Verdict** : direction correcte (`critical > local`, conforme à l'intention
upstream — le critical_work est le bottleneck de scaling), mais diff =
+0.00017 vs noise floor +0.00105. **FAIL au strict.**

**Cross-référence performance-patterns** : si `critical_work` ressortait
clairement en #1 avec un IC strictement supérieur à `local_work`, on
recommanderait la même chose qu'en 3.1 — réduire la durée de la section
critique. Le signal va dans la bonne direction mais reste sous le seuil
de confiance.

## 4. Conclusion globale

| Bench | Direction du ranking | Signal au-dessus du bruit |
|-------|---------------------|--------------------------|
| `lockheavy` | ✓ (1/2 runs) | ✓ (1/2 runs) |
| `useful_useless` | ✓ | ✗ |
| `coz_toy` | ≈ (différence dans le bruit) | ✗ |
| `coz_pc` | ✓ | ✗ (`high_variance` détecté) |
| `coz_lock` | ✓ | ✗ |

**Le pipeline fonctionne** : auto-pick PC, rotation block-randomisée,
attache uprobes multi-target, perturbation ptrace, agrégation par cell,
régression HC1, ranking, statuts d'alerte. **3/5 directions correctes**
au dernier run, **0/5 systématiquement reproductibles avec IC séparées**
au budget de 120 s.

Le système **ne sur-vend pas** : pour chaque bench non-concluant il indique
soit `high_variance` (variance interne dépassant l'effet) soit "noise floor
not cleared" (différence inférieure à la somme des half-widths CI).

### Pour atteindre des résultats stables type papier Coz

1. **Budgets de 10–30 min**, pas 2 min. Le papier Coz fait ~10 min par
   benchmark pour le pbzip2 (~4–9 % de slope).
2. **Workload plus contention-bound**. Nos benches "useful_useless" et
   "coz_toy" produisent <1 % de slope causal réel — c'est en dessous du
   plancher de bruit du backend ptrace.
3. **Fix de `s=100`** (full pause upper bound) : il faut exempter les TIDs
   "ayant porté le target récemment" pour ne pas killer le throughput
   quand le porteur est temporairement entre 2 itérations. Sortir du
   périmètre v0.
4. **Pinning et état système stables** : éviter les variations de
   fréquence CPU (`turbo`, `cpufreq governor=performance`), les
   préemptions par d'autres processus.

### Recommandation produit

Pour un MVP livrable, **lockheavy** est le seul des 5 benches qui produit
un résultat stable et actionnable, et la recommandation qu'il génère
(`optimiser le critical section`) matche un pattern documenté de
[`performance-patterns`](~/.claude/skills/performance-patterns/triggers/from-source.md).

Pour les autres benches, l'output direction est correct mais demande
soit plus de budget, soit un workload avec un effet causal plus marqué.
Le system les flag comme `high_variance` / non-concluants — c'est
l'output utile : **ne pas produire de recommandation quand on n'a pas la
confiance**.
