"""
Script principal - Orchestration du pipeline complet
"""

import sys
import time
import os
import json
import pandas as pd
from pathlib import Path

# Ajout du répertoire src au chemin
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rss_extractor import RSSExtractor
from cve_extractor import CVEExtractor
from cve_enricher import CVEEnricher
from data_consolidator import DataConsolidator
from alert_generator import AlertGenerator
from email_notifier import EmailNotifier

def print_section(title):
    """Affiche une section de titre"""
    print(f"\n{'='*60}")
    print(f"{title:^60}")
    print(f"{'='*60}\n")

def main():
    """Fonction principale - Orchestration du pipeline"""
    
    print_section("PIPELINE D'ANALYSE DES VULNÉRABILITÉS ANSSI")
    print("Ce script exécute l'ensemble du pipeline d'extraction et")
    print("d'analyse des vulnérabilités ANSSI en 7 étapes.\n")
    
    try:
        # ÉTAPE 1 : Extraction RSS
        print_section("ÉTAPE 1 : EXTRACTION DES FLUX RSS")
        print("Extraction des avis et alertes ANSSI...")
        
        # Vérifier si des données existent déjà (pour tests)
        import json
        import os
        bulletins_file = "data/raw/bulletins_anssi.json"
        
        if os.path.exists(bulletins_file):
            with open(bulletins_file, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
                if existing_data.get("avis") or existing_data.get("alertes"):
                    print("[INFO] Utilisation des données existantes...")
                    rss_data = existing_data
                    bulletins_data = rss_data
                else:
                    rss_extractor = RSSExtractor(rate_limit_delay=2.0)
                    rss_data = rss_extractor.extract_all_feeds()
                    rss_extractor.save_to_json()
                    bulletins_data = rss_data
        else:
            rss_extractor = RSSExtractor(rate_limit_delay=2.0)
            rss_data = rss_extractor.extract_all_feeds()
            rss_extractor.save_to_json()
            bulletins_data = rss_data
        
        # ÉTAPE 2 : Extraction CVE
        print_section("ÉTAPE 2 : EXTRACTION DES CVE")
        print("Identification des CVE dans les bulletins...")
        
        cve_extractor = CVEExtractor(rate_limit_delay=2.0)
        # Chargement des bulletins depuis l'étape 1
        with open("data/raw/bulletins_anssi.json", 'r', encoding='utf-8') as f:
            bulletins_data = json.load(f)
        all_bulletins = bulletins_data.get("avis", []) + bulletins_data.get("alertes", [])
        
        # Limitation pour les tests (à modifier)
        # all_bulletins = all_bulletins[:5]
        
        # Vérifier si les données CVE existent déjà
        cves_file = "data/raw/cves_extracted.json"
        if os.path.exists(cves_file):
            with open(cves_file, 'r', encoding='utf-8') as f:
                existing_cves = json.load(f)
                if existing_cves.get("total_unique_cves"):
                    print("[INFO] Utilisation des CVE existants...")
                    cve_results = existing_cves
                else:
                    cve_results = cve_extractor.extract_cves_from_bulletins(all_bulletins)
                    cve_extractor.save_to_json(cve_results)
        else:
            cve_results = cve_extractor.extract_cves_from_bulletins(all_bulletins)
            cve_extractor.save_to_json(cve_results)
        
        # ÉTAPE 3 : Enrichissement CVE
        print_section("ÉTAPE 3 : ENRICHISSEMENT DES CVE")
        print("Récupération des informations MITRE et EPSS...")
        print("(Attention: utiliser les fichiers locaux en priorité)\n")
        
        cve_enricher = CVEEnricher(rate_limit_delay=2.0, use_local_files=True)
        cve_list = cve_results.get("total_unique_cves", [])
        
        # Pour les tests: limiter à quelques CVE
        max_test_cves = 10
        if len(cve_list) > max_test_cves:
            print(f"[INFO] Limitation à {max_test_cves} CVE pour les tests")
            cve_list = cve_list[:max_test_cves]
        
        enriched_cves = cve_enricher.enrich_multiple_cves(cve_list)
        cve_enricher.save_to_json(enriched_cves)
        
        # ÉTAPE 4 : Consolidation
        print_section("ÉTAPE 4 : CONSOLIDATION DES DONNÉES")
        print("Création du DataFrame Pandas...")
        
        # Vérifier si le CSV existe déjà
        csv_file = "data/processed/cves_consolidated.csv"
        csv_path = csv_file
        
        if os.path.exists(csv_file):
            print("[INFO] Chargement du DataFrame depuis le CSV existant...")
            df = pd.read_csv(csv_file)
            print(f"[SUCCÈS] DataFrame chargé avec {len(df)} lignes")
            consolidator = DataConsolidator()
            consolidator.df = df
        else:
            consolidator = DataConsolidator()
            df = consolidator.consolidate()
            
            if df is not None:
                csv_path = consolidator.save_to_csv()
                consolidator.display_summary()
            else:
                print("[ERREUR] Consolidation échouée")
                return False
        
        # ÉTAPE 5 : Visualisations (à faire dans Jupyter)
        print_section("ÉTAPE 5 : VISUALISATIONS ET ANALYSES")
        print("Les visualisations seront créées dans le Jupyter Notebook")
        print("Consultez: notebooks/analysis.ipynb\n")
        
        # ÉTAPE 6 : Machine Learning (à faire dans Jupyter)
        print_section("ÉTAPE 6 : MODÈLES MACHINE LEARNING")
        print("Les modèles ML seront implémentés dans le Jupyter Notebook")
        print("Consultez: notebooks/analysis.ipynb\n")
        
        # ÉTAPE 7 : Alertes
        print_section("ÉTAPE 7 : GÉNÉRATION DES ALERTES")
        print("Génération des alertes personnalisées...")
        
        alert_rules = {
            "critical_cvss": 9.0,
            "high_cvss": 7.0,
            "high_epss": 0.75,
            "monitored_vendors": ["Microsoft", "Apache", "Ivanti"],
            "monitored_products": []
        }
        
        alert_generator = AlertGenerator(alert_rules=alert_rules)
        if alert_generator.load_dataframe(csv_path):
            alerts = alert_generator.generate_alerts()
            alert_generator.save_alerts_to_json()
            alert_generator.display_summary()
        else:
            print("[ERREUR] Impossible de charger le DataFrame")
            return False
        
        # Notifications email (optionnel)
        print_section("NOTIFICATIONS EMAIL (OPTIONNEL)")
        print("Pour activer les notifications email:")
        print("1. Configurez les variables d'environnement ALERT_EMAIL et ALERT_PASSWORD")
        print("2. Décommentez la section de notification dans email_notifier.py\n")
        
        print_section("PIPELINE TERMINÉ")
        print("✓ Flux RSS extraits")
        print("✓ CVE identifiés")
        print("✓ Données enrichies")
        print("✓ DataFrame consolidé (CSV)")
        print("✓ Alertes générées")
        print("\nProchain: Ouvrir le Jupyter Notebook pour les visualisations et ML")
        print(f"Fichier: notebooks/analysis.ipynb\n")
        
        return True
        
    except Exception as e:
        print(f"\n[ERREUR FATALE] {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
