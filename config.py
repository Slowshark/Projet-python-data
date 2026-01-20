"""
Configuration de test - à utiliser pour les premiers tests du projet
"""

# Paramètres de test
MAX_BULLETINS = 5        # Nombre de bulletins à traiter (None = tous)
MAX_CVES = 10           # Nombre de CVE à enrichir (None = tous)
RATE_LIMIT_DELAY = 1.0  # Délai entre les requêtes (en secondes)

# Utiliser les fichiers locaux en priorité
USE_LOCAL_FILES = True

# Seuils d'alerte pour les tests
ALERT_RULES = {
    "critical_cvss": 8.0,      # Plus bas pour voir plus d'alertes
    "high_cvss": 6.0,
    "high_epss": 0.5,
    "monitored_vendors": ["Microsoft", "Apache", "Ivanti"],
    "monitored_products": []
}

# Paramètres ML pour les tests
ML_CONFIG = {
    "test_size": 0.2,
    "random_state": 42,
    "clustering_k_range": range(2, 6),  # K-means range
    "clustering_k_default": 3,
    "rf_n_estimators": 50,
    "gb_n_estimators": 50
}

# Dossiers
DATA_RAW = "data/raw"
DATA_PROCESSED = "data/processed"
OUTPUT_ALERTS = "output/alerts"
NOTEBOOKS = "notebooks"
