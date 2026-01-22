"""
Module d'enrichissement des CVE avec les APIs MITRE et EPSS
"""

import requests
import json
import time
from typing import Dict, Optional, List
import os

class CVEEnricher:
    """Enrichisseur de CVE avec données MITRE et EPSS"""
    
    MITRE_API_URL = "https://cveawg.mitre.org/api/cve"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    
    def __init__(self, rate_limit_delay: float = 2.0, use_local_files: bool = True):
        """
        Initialise l'enrichisseur
        
        Args:
            rate_limit_delay: Délai en secondes entre les requêtes
            use_local_files: Si True, essaie d'utiliser les fichiers locaux d'abord
        """
        self.rate_limit_delay = rate_limit_delay
        self.use_local_files = use_local_files
    
    def get_mitre_data(self, cve_id: str) -> Optional[Dict]:
        """
        Récupère les données MITRE pour un CVE
        
        Args:
            cve_id: Identifiant CVE (ex: CVE-2023-46805)
            
        Returns:
            Dictionnaire avec les données ou None en cas d'erreur
        """
        # Essai avec les fichiers locaux si activé
        if self.use_local_files:
            local_path = os.path.join("data4project/mitre", cve_id)
            if os.path.exists(local_path):
                try:
                    with open(local_path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception as e:
                    print(f"[AVERTISSEMENT] Erreur lecture fichier local {cve_id}: {e}")
        
        # Sinon, requête API
        try:
            url = f"{self.MITRE_API_URL}/{cve_id}"
            print(f"[INFO] Récupération MITRE: {cve_id}")
            
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"[ERREUR] Impossible de récupérer {cve_id} depuis MITRE: {e}")
            return None
    
    def get_epss_data(self, cve_id: str) -> Optional[Dict]:
        """
        Récupère le score EPSS pour un CVE
        
        Args:
            cve_id: Identifiant CVE
            
        Returns:
            Dictionnaire avec le score EPSS ou None
        """
        # Essai avec les fichiers locaux si activé
        if self.use_local_files:
            local_path = os.path.join("data4project/first", cve_id)
            if os.path.exists(local_path):
                try:
                    with open(local_path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception as e:
                    print(f"[AVERTISSEMENT] Erreur lecture fichier EPSS local {cve_id}: {e}")
        
        # Sinon, requête API
        try:
            url = f"{self.EPSS_API_URL}?cve={cve_id}"
            print(f"[INFO] Récupération EPSS: {cve_id}")
            
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"[ERREUR] Impossible de récupérer EPSS pour {cve_id}: {e}")
            return None
    
    def extract_cvss_info(self, mitre_data: Dict) -> Dict:
        """
        Extrait les informations CVSS des données MITRE
        
        Args:
            mitre_data: Données du CVE depuis MITRE
            
        Returns:
            Dictionnaire avec cvss_score et base_severity
        """
        result = {
            "cvss_score": None,
            "base_severity": None,
            "cvss_version": ""
        }
        
        try:
            if not mitre_data or "containers" not in mitre_data:
                return result
            
            cna = mitre_data["containers"].get("cna", {})
            metrics = cna.get("metrics", [])
            
            if not metrics:
                return result
            
            # Essayer différentes versions de CVSS
            metric = metrics[0]
            cvss_keys = ["cvssV3_1", "cvssV3_0", "cvssV2_0"]
            
            for key in cvss_keys:
                if key in metric:
                    result["cvss_score"] = metric[key].get("baseScore", 0.0)
                    result["base_severity"] = metric[key].get("baseSeverity", "N/A")
                    result["cvss_version"] = key
                    break
            
        except Exception as e:
            print(f"[ERREUR] Erreur extraction CVSS: {e}")
        
        return result
    
    def extract_cwe_info(self, mitre_data: Dict) -> Dict:
        """
        Extrait les informations CWE des données MITRE
        
        Args:
            mitre_data: Données du CVE depuis MITRE
            
        Returns:
            Dictionnaire avec cwe_id et cwe_description
        """
        result = {
            "cwe_id": "Non disponible",
            "cwe_description": "Non disponible"
        }
        
        try:
            if not mitre_data or "containers" not in mitre_data:
                return result
            
            cna = mitre_data["containers"].get("cna", {})
            problem_types = cna.get("problemTypes", [])
            
            if problem_types and "descriptions" in problem_types[0]:
                descriptions = problem_types[0]["descriptions"]
                if descriptions:
                    result["cwe_id"] = descriptions[0].get("cweId", "Non disponible")
                    result["cwe_description"] = descriptions[0].get("description", "Non disponible")
            
        except Exception as e:
            print(f"[ERREUR] Erreur extraction CWE: {e}")
        
        return result
    
    def extract_affected_products(self, mitre_data: Dict) -> List[Dict]:
        """
        Extrait les produits affectés
        
        Args:
            mitre_data: Données du CVE depuis MITRE
            
        Returns:
            Liste des produits affectés
        """
        products = []
        
        try:
            if not mitre_data or "containers" not in mitre_data:
                return products
            
            cna = mitre_data["containers"].get("cna", {})
            affected = cna.get("affected", [])
            
            for product in affected:
                vendor = product.get("vendor", "N/A")
                product_name = product.get("product", "N/A")
                versions = [v["version"] for v in product.get("versions", []) 
                           if v.get("status") == "affected"]
                
                products.append({
                    "vendor": vendor,
                    "product": product_name,
                    "affected_versions": versions
                })
            
        except Exception as e:
            print(f"[ERREUR] Erreur extraction produits: {e}")
        
        return products
    
    def extract_epss_score(self, epss_data: Dict) -> Optional[float]:
        """
        Extrait le score EPSS
        
        Args:
            epss_data: Données EPSS
            
        Returns:
            Score EPSS ou None
        """
        try:
            data_list = epss_data.get("data", [])
            if data_list:
                return float(data_list[0].get("epss", None))
        except Exception as e:
            print(f"[ERREUR] Erreur extraction EPSS: {e}")
        
        return None
    
    def enrich_cve(self, cve_id: str) -> Dict:
        """
        Enrichit un CVE avec toutes les données disponibles
        
        Args:
            cve_id: Identifiant CVE
            
        Returns:
            Dictionnaire enrichi du CVE
        """
        print(f"\n[ENRICHISSEMENT] {cve_id}")
        
        enriched = {
            "cve_id": cve_id,
            "cvss_score": None,
            "base_severity": None,
            "cvss_version": None,
            "cwe_id": "Non disponible",
            "cwe_description": "Non disponible",
            "epss_score": None,
            "affected_products": [],
            "description": "Non disponible",
            "errors": []
        }
        
        try:
            # Récupération données MITRE
            mitre_data = self.get_mitre_data(cve_id)
            if mitre_data:
                # Extraction CVSS
                cvss_info = self.extract_cvss_info(mitre_data)
                enriched.update(cvss_info)
                
                # Extraction CWE
                cwe_info = self.extract_cwe_info(mitre_data)
                enriched.update(cwe_info)
                
                # Extraction produits affectés
                enriched["affected_products"] = self.extract_affected_products(mitre_data)
                
                # Extraction description
                try:
                    desc = mitre_data["containers"]["cna"]["descriptions"][0]["value"]
                    enriched["description"] = desc[:500]  # Limite à 500 caractères
                except (KeyError, IndexError, TypeError):
                    pass
            else:
                enriched["errors"].append("Impossible de récupérer données MITRE")
            
            time.sleep(self.rate_limit_delay / 2)
            
            # Récupération données EPSS
            epss_data = self.get_epss_data(cve_id)
            if epss_data:
                epss_score = self.extract_epss_score(epss_data)
                enriched["epss_score"] = epss_score
            else:
                enriched["errors"].append("Impossible de récupérer données EPSS")
            
            time.sleep(self.rate_limit_delay / 2)
            
        except Exception as e:
            print(f"[ERREUR] Erreur enrichissement {cve_id}: {e}")
            enriched["errors"].append(str(e))
        
        return enriched
    
    def enrich_multiple_cves(self, cve_list: List[str], max_cves: Optional[int] = None) -> List[Dict]:
        """
        Enrichit plusieurs CVE
        
        Args:
            cve_list: Liste des CVE à enrichir
            max_cves: Limite du nombre de CVE à traiter (pour les tests)
            
        Returns:
            Liste des CVE enrichis
        """
        print(f"\n=== Enrichissement des CVE ===\n")
        print(f"Total CVE à traiter: {len(cve_list)}")
        
        if max_cves:
            cve_list = cve_list[:max_cves]
            print(f"Limité à: {max_cves} CVE (mode test)")
        
        enriched_cves = []
        
        for i, cve_id in enumerate(cve_list):
            print(f"\n[{i+1}/{len(cve_list)}] Traitement...")
            enriched = self.enrich_cve(cve_id)
            enriched_cves.append(enriched)
        
        print(f"\n[SUCCÈS] Enrichissement de {len(enriched_cves)} CVE terminé")
        
        return enriched_cves
    
    def save_to_json(self, enriched_cves: List[Dict], output_dir: str = "data/raw") -> None:
        """
        Sauvegarde les CVE enrichis en JSON
        
        Args:
            enriched_cves: Liste des CVE enrichis
            output_dir: Répertoire de sortie
        """
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "cves_enriched.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(enriched_cves, f, ensure_ascii=False, indent=2)
        
        print(f"\n[INFO] CVE enrichis sauvegardés dans: {output_file}")


def main():
    """Fonction principale"""
    
    # Chargement des CVE extraits
    try:
        with open("data/raw/cves_extracted.json", 'r', encoding='utf-8') as f:
            cve_results = json.load(f)
        
        cve_list = cve_results.get("total_unique_cves", [])
        
        if not cve_list:
            print("[ERREUR] Aucun CVE trouvé. Veuillez d'abord exécuter cve_extractor.py")
            return
        
    except FileNotFoundError:
        print("[ERREUR] Fichier cves_extracted.json non trouvé.")
        return
    
    # Enrichissement des CVE
    enricher = CVEEnricher(rate_limit_delay=2.0, use_local_files=True)
    
    # ATTENTION: Pour les tests, limiter à quelques CVE (ex: 5)
    enriched_cves = enricher.enrich_multiple_cves(cve_list, max_cves=5)
    
    # Sauvegarde
    enricher.save_to_json(enriched_cves)


if __name__ == "__main__":
    main()
