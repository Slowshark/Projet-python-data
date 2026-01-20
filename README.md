# 🔒 Projet ANSSI - Extraction et Analyse de Vulnérabilités

Analyse complète des vulnérabilités de sécurité ANSSI avec extraction RSS, enrichissement via APIs, consolidation Pandas, visualisations et modèles de Machine Learning.

## 📋 Objectifs du Projet

- ✅ Extraire les données des flux RSS des avis et alertes ANSSI
- ✅ Identifier les CVE mentionnées dans les bulletins
- ✅ Enrichir les CVE avec informations complémentaires (CVSS, EPSS, CWE)
- ✅ Consolider les données dans un DataFrame Pandas
- ✅ Analyser et visualiser les vulnérabilités
- ✅ Implémenter modèles de Machine Learning (supervisé + non-supervisé)
- ✅ Générer des alertes personnalisées par email

## 🏗️ Structure du Projet

```
Projet/
├── src/                              # Code source (modules réutilisables)
│   ├── rss_extractor.py             # Classe: RSSExtractor
│   ├── cve_extractor.py             # Classe: CVEExtractor
│   ├── cve_enricher.py              # Classe: CVEEnricher (MITRE + EPSS)
│   ├── data_consolidator.py         # Classe: DataConsolidator
│   ├── alert_generator.py           # Classe: AlertGenerator
│   └── email_notifier.py            # Classe: EmailNotifier
├── data/
│   ├── raw/                         # Données brutes (APIs, RSS)
│   │   ├── bulletins_anssi.json
│   │   ├── cves_extracted.json
│   │   ├── cves_enriched.json
│   │   ├── mitre/                   # Données MITRE locales (optionnel)
│   │   ├── first/                   # Données EPSS locales (optionnel)
│   │   ├── avis/                    # Bulletins avis (optionnel)
│   │   └── alertes/                 # Bulletins alertes (optionnel)
│   └── processed/
│       └── cves_consolidated.csv    # DataFrame final
├── notebooks/
│   └── analysis.ipynb               # Jupyter Notebook complet
│       - Exploration des données
│       - 12+ visualisations
│       - Clustering K-Means
│       - Classification supervisée
│       - Régression EPSS
│       - Génération alertes
├── output/
│   └── alerts/                      # Alertes générées (JSON)
├── main.py                          # Script d'orchestration (7 étapes)
├── config.py                        # Configuration (à personnaliser)
├── requirements.txt                 # Dépendances Python
├── .env.example                     # Variables d'environnement
├── setup.sh                         # Script d'installation
├── .gitignore
├── README.md                        # Cette documentation
├── QUICKSTART.md                    # Guide de démarrage rapide
└── contributions.txt                # Contributions équipe

```

## 🚀 Installation Rapide

### Prérequis
- Python 3.8+
- pip
- (Optionnel) Connexion Internet pour APIs externes

### Étapes
```bash
# 1. Créer environnement virtuel
python -m venv .venv

# 2. Activer l'environnement
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux/Mac:
source .venv/bin/activate

# 3. Installer dépendances
pip install -r requirements.txt
```

## ▶️ Utilisation - Exécution Complète

```bash
python main.py
```

Ce script exécute automatiquement les 7 étapes:

1. **Extraction RSS** ✓ → `data/raw/bulletins_anssi.json`
2. **Extraction CVE** ✓ → `data/raw/cves_extracted.json`
3. **Enrichissement** ✓ → `data/raw/cves_enriched.json`
4. **Consolidation** ✓ → `data/processed/cves_consolidated.csv`
5. **Alertes** ✓ → `output/alerts/alerts_*.json`
6. **Visualisations** → Jupyter Notebook
7. **ML** → Jupyter Notebook

## 📊 Analyses et Visualisations

Ouvrir le Jupyter Notebook après exécution de `main.py`:

```bash
jupyter notebook notebooks/analysis.ipynb
```

### Contenu du Notebook
- **EDA**: Exploration complète du DataFrame
- **Visualisations**: 
  - Histogrammes CVSS/EPSS
  - Pie charts CWE
  - Scatter CVSS vs EPSS
  - Box plots par vendor
  - Heatmaps correlations
  - Tendances temporelles
- **ML Unsupervised**: K-Means clustering (silhouette validation)
- **ML Supervised**: Classification criticité (Random Forest) + Régression EPSS
- **Alertes**: Distribution et top alertes

## 🧠 Modèles Machine Learning

### Modèle Non-Supervisé: K-Means Clustering
- **Entrées**: CVSS, EPSS, vendor, severity
- **Validation**: Silhouette score + Elbow method
- **Visualisation**: PCA 2D
- **Output**: Clusters pour groupement thématique

### Modèle Supervisé 1: Classification Criticité
- **Modèle**: Random Forest (100 trees)
- **Entrées**: CVSS, EPSS, vendor, product, severity
- **Sortie**: 4 classes (Critique, Élevée, Moyenne, Faible)
- **Métriques**: Accuracy, F1-Score, Confusion Matrix
- **Validation**: Train/Test split (80/20)

### Modèle Supervisé 2: Régression EPSS
- **Modèle**: Gradient Boosting Regressor
- **Entrées**: CVSS, vendor, product, severity
- **Sortie**: Score EPSS prédit (0-1)
- **Métriques**: RMSE, R²
- **Validation**: Cross-validation

## 📧 Notifications Email (Optionnel)

Pour activer les alertes par email:

1. Créer un email Gmail dédié
2. Générer "App Password": https://support.google.com/accounts/answer/185833
3. Copier `.env.example` → `.env` et remplir:
   ```
   ALERT_EMAIL=votre_email@gmail.com
   ALERT_PASSWORD=app_password
   ```
4. Décommenter section email dans `src/email_notifier.py`

## ⚙️ Configuration

Fichiers de configuration:
- `config.py`: Paramètres projet (MAX_CVES, RATE_LIMIT, etc.)
- `.env.example`: Variables d'environnement
- `requirements.txt`: Dépendances Python

## 📚 Modules Détaillés

### rss_extractor.py
```python
extractor = RSSExtractor(rate_limit_delay=2.0)
feeds = extractor.extract_all_feeds()
extractor.save_to_json()
```

### cve_extractor.py
```python
extractor = CVEExtractor()
results = extractor.extract_cves_from_bulletins(bulletins)
extractor.save_to_json(results)
```

### cve_enricher.py
```python
enricher = CVEEnricher(use_local_files=True)
enriched = enricher.enrich_multiple_cves(cve_list, max_cves=10)
enricher.save_to_json(enriched)
```

### data_consolidator.py
```python
consolidator = DataConsolidator()
df = consolidator.consolidate()
csv_path = consolidator.save_to_csv()
```

### alert_generator.py
```python
generator = AlertGenerator(alert_rules=rules)
generator.load_dataframe(csv_path)
alerts = generator.generate_alerts()
generator.save_alerts_to_json()
```

### email_notifier.py
```python
notifier = EmailNotifier(sender_email, sender_password)
notifier.send_alerts(alerts, recipient_email, alert_level="CRITIQUE")
```

## 🔒 Bonnes Pratiques - Utilisation Responsable

1. **Rate Limiting**: Délais de 2 secondes automatiques entre requêtes
2. **Fichiers Locaux**: Utiliser prioritairement les fichiers pré-téléchargés
3. **Limitation Tests**: Utiliser `max_cves` pour les premiers tests
4. **Cache**: Les données sont sauvegardées localement après chaque étape

## 📊 Exemple de Sortie

### DataFrame Consolidé (CSV)
```
id_anssi,titre_anssi,type_bulletin,date_publication,cve_id,cvss_score,base_severity,...
CERTFR-2024-ALE-001,Vulnérabilités Ivanti,alerte,2024-01-11,CVE-2024-22024,8.3,High,...
```

### Alertes (JSON)
```json
{
  "total_alerts": 45,
  "alerts_by_level": {"CRITIQUE": 12, "ÉLEVÉE": 20, "MOYENNE": 13},
  "alerts": [
    {
      "alert_level": "CRITIQUE",
      "cve_id": "CVE-2024-22024",
      "cvss_score": 8.3,
      "epss_score": 0.85,
      "vendor": "Ivanti",
      "produit": "ICS",
      ...
    }
  ]
}
```

## ✅ Checklist Livrable

- [x] Code Python fonctionnel (`main.py`, modules `src/`)
- [x] README.md clair et complet
- [x] `data/processed/cves_consolidated.csv`
- [x] `notebooks/analysis.ipynb`
- [x] Export HTML du notebook (depuis Jupyter)
- [ ] `contributions.txt` complété
- [ ] **ZIP du projet** (avant deadline)

## ⚠️ Gestion des Erreurs

Le code gère automatiquement:
- ✓ CVE sans données CVSS/EPSS
- ✓ Bulletins sans CVE
- ✓ APIs indisponibles (fallback fichiers locaux)
- ✓ Requêtes réseau échouées
- ✓ Erreurs JSON/parsing

## 📞 Support & Documentation

- **Fichiers d'aide**:
  - `QUICKSTART.md`: Guide rapide
  - Docstrings détaillées dans le code
  - Commentaires explicatifs

- **Problèmes courants**: Voir QUICKSTART.md

---

**Développé pour le cours Python Data & IA - ESILV A3** 🎓

Respect des délais de rate limit | Utilisation responsable des APIs | Gestion complète des exceptions

