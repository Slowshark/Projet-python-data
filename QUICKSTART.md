# DÉMARRAGE RAPIDE - Projet ANSSI

## 🚀 Installation Initiale

### 1. Vérifier les Prérequis
- Python 3.8+
- pip
- Connexion Internet (pour les APIs ANSSI, MITRE, EPSS)

### 2. Créer l'Environnement Virtuel

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux/Mac:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Installer les Dépendances
```bash
pip install -r requirements.txt
```

## ▶️ Exécution du Pipeline

### Option 1: Exécution Complète
```bash
python main.py
```

Cela exécutera les 7 étapes:
1. ✓ Extraction RSS ANSSI
2. ✓ Extraction CVE
3. ✓ Enrichissement (MITRE + EPSS)
4. ✓ Consolidation DataFrame
5. ✓ Génération des Alertes
6-7. Visualisations et ML dans Jupyter

### Option 2: Étapes Individuelles

**Extraction RSS:**
```bash
python src/rss_extractor.py
```

**Extraction CVE:**
```bash
python src/cve_extractor.py
```

**Enrichissement CVE:**
```bash
python src/cve_enricher.py
```

**Consolidation:**
```bash
python src/data_consolidator.py
```

**Génération Alertes:**
```bash
python src/alert_generator.py
```

## 📊 Analyse et Visualisations

Ouvrir le Jupyter Notebook:
```bash
jupyter notebook notebooks/analysis.ipynb
```

Le notebook contient:
- Exploration des données
- 12+ visualisations
- Clustering K-Means
- Classification supervisée
- Régression EPSS
- Génération d'alertes

## 📁 Structure des Fichiers

```
Projet/
├── src/                          # Code source
│   ├── rss_extractor.py
│   ├── cve_extractor.py
│   ├── cve_enricher.py
│   ├── data_consolidator.py
│   ├── alert_generator.py
│   └── email_notifier.py
├── data/
│   ├── raw/                      # Données brutes
│   │   ├── bulletins_anssi.json
│   │   ├── cves_extracted.json
│   │   ├── cves_enriched.json
│   │   ├── mitre/               # Données MITRE locales
│   │   └── first/               # Données EPSS locales
│   └── processed/
│       └── cves_consolidated.csv
├── notebooks/
│   └── analysis.ipynb            # Jupyter Notebook complet
├── output/
│   └── alerts/                   # Alertes générées
├── main.py                       # Script principal
├── requirements.txt
└── README.md
```

## ⚠️ Utilisation Responsable des APIs

### Rate Limiting
Le code inclut des délais de 2 secondes entre les requêtes pour ne pas surcharger les serveurs.

### Utilisation des Fichiers Locaux
Pour les tests, utiliser les fichiers pré-téléchargés dans:
- `data/raw/mitre/`
- `data/raw/first/`
- `data/raw/avis/`
- `data/raw/alertes/`

## 📧 Configuration des Notifications Email

Pour activer les notifications email:

1. Créer un email Gmail dédié (ne pas utiliser votre compte personnel)

2. Générer un "App Password":
   - Aller sur: https://support.google.com/accounts/answer/185833
   - Activer l'authentification à deux facteurs
   - Générer le mot de passe d'application

3. Configurer les variables d'environnement:
```bash
export ALERT_EMAIL="votre_email@gmail.com"
export ALERT_PASSWORD="votre_app_password"
```

4. Décommenter la section email dans `src/email_notifier.py`

## 🔍 Dépannage

### Problème: "Fichier non trouvé"
→ Vérifier que main.py a été exécuté en premier

### Problème: "Rate limit exceeded"
→ Les délais de 2 secondes sont déjà inclus. Réduire max_cves dans cve_enricher.py

### Problème: "Connection refused"
→ Vérifier la connexion Internet et les pare-feu

## 📝 Fichiers de Sortie

Après exécution:

1. **CSV consolidé:** `data/processed/cves_consolidated.csv`
   - Toutes les données enrichies en un seul fichier

2. **Alertes JSON:** `output/alerts/alerts_YYYYMMDD_HHMMSS.json`
   - Alertes structurées par niveau

3. **Notebook HTML:** Exporter depuis Jupyter
   - File → Export As → HTML

## ✅ Checklist Livrable

- [ ] Code Python fonctionnel (main.py et modules)
- [ ] README.md clair et détaillé
- [ ] data/processed/cves_consolidated.csv
- [ ] notebooks/analysis.ipynb
- [ ] Export HTML du notebook
- [ ] contributions.txt rempli
- [ ] Zip du projet (NOT .7z or .rar)

## 📞 Support

Consulter:
- README.md pour la documentation complète
- Code source avec commentaires détaillés
- Jupyter Notebook pour les exemples

---

**Bonne chance avec le projet! 🚀**
