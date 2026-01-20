"""
Module d'extraction des CVE depuis les bulletins ANSSI (fichiers JSON)
"""

import requests
import re
import json
import time
from typing import List, Dict, Set
import os

class CVEExtractor:
    """Extracteur de CVE depuis les bulletins ANSSI"""
    
    def __init__(self, rate_limit_delay: float = 2.0):
        """
        Initialise l'extracteur
        
        Args:
            rate_limit_delay: Délai en secondes entre les requêtes
        """
        self.rate_limit_delay = rate_limit_delay
        self.cve_pattern = r"CVE-\d{4}-\d{4,7}"
    
    def get_bulletin_json_url(self, bulletin_url: str) -> str:
        """
        Convertit l'URL d'un bulletin en URL du fichier JSON
        
        Args:
            bulletin_url: URL du bulletin ANSSI
            
        Returns:
            URL du fichier JSON correspondant
        """
        # Ajoute "/json/" à la fin de l'URL si ce n'est pas déjà le cas
        if not bulletin_url.endswith('/'):
            bulletin_url += '/'
        return bulletin_url + 'json'
    
    def extract_cves_from_bulletin(self, bulletin_url: str) -> Dict:
        """
        Extrait les CVE d'un bulletin ANSSI via son fichier JSON
        
        Args:
            bulletin_url: URL du bulletin
            
        Returns:
            Dictionnaire contenant les CVE et autres infos
        """
        try:
            json_url = self.get_bulletin_json_url(bulletin_url)
            
            print(f"[INFO] Récupération des CVE depuis: {json_url}")
            response = requests.get(json_url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Extraction des CVE depuis la clé "cves" si elle existe
            cves_from_key = []
            if "cves" in data:
                cves_from_key = [cve["name"] for cve in data["cves"] if "name" in cve]
            
            # Extraction des CVE via regex dans l'ensemble des données
            cves_from_regex = list(set(re.findall(self.cve_pattern, json.dumps(data))))
            
            # Fusion et suppression des doublons
            all_cves = list(set(cves_from_key + cves_from_regex))
            all_cves.sort()
            
            result = {
                "bulletin_url": bulletin_url,
                "json_url": json_url,
                "cves": all_cves,
                "count": len(all_cves),
                "raw_data": data  # Stockage des données brutes pour enrichissement ultérieur
            }
            
            print(f"[INFO] {len(all_cves)} CVE(s) trouvé(s)")
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[ERREUR] Erreur lors de la récupération du bulletin: {e}")
            return {
                "bulletin_url": bulletin_url,
                "cves": [],
                "error": str(e)
            }
        except json.JSONDecodeError as e:
            print(f"[ERREUR] Erreur lors du décodage JSON: {e}")
            return {
                "bulletin_url": bulletin_url,
                "cves": [],
                "error": str(e)
            }
    
    def extract_cves_from_bulletins(self, bulletins: List[Dict]) -> Dict:
        """
        Extrait les CVE de plusieurs bulletins
        
        Args:
            bulletins: Liste des bulletins ANSSI (contenant 'lien')
            
        Returns:
            Dictionnaire avec CVE et leurs associations
        """
        print("\n=== Extraction des CVE depuis les Bulletins ===\n")
        
        results = {
            "bulletins_processed": 0,
            "total_unique_cves": set(),
            "bulletin_cve_mapping": [],
            "errors": []
        }
        
        for i, bulletin in enumerate(bulletins):
            print(f"\n[{i+1}/{len(bulletins)}] Traitement du bulletin...")
            
            try:
                cve_data = self.extract_cves_from_bulletin(bulletin["lien"])
                
                if cve_data.get("cves"):
                    results["bulletin_cve_mapping"].append({
                        "bulletin_id": bulletin.get("id", "N/A"),
                        "bulletin_titre": bulletin.get("titre", "N/A"),
                        "bulletin_type": bulletin.get("type_bulletin", "N/A"),
                        "cves": cve_data["cves"],
                        "cve_count": len(cve_data["cves"])
                    })
                    results["total_unique_cves"].update(cve_data["cves"])
                    results["bulletins_processed"] += 1
                
                # Respect du rate limit
                time.sleep(self.rate_limit_delay)
                
            except Exception as e:
                print(f"[ERREUR] Erreur lors du traitement: {e}")
                results["errors"].append({
                    "bulletin": bulletin.get("id", "N/A"),
                    "error": str(e)
                })
        
        # Conversion du set en liste pour sérialisation
        results["total_unique_cves"] = sorted(list(results["total_unique_cves"]))
        results["total_unique_cve_count"] = len(results["total_unique_cves"])
        
        print(f"\n[SUCCÈS] Extraction terminée:")
        print(f"  - Bulletins traités: {results['bulletins_processed']}")
        print(f"  - CVE uniques trouvés: {results['total_unique_cve_count']}")
        print(f"  - Erreurs: {len(results['errors'])}")
        
        return results
    
    def save_to_json(self, cve_results: Dict, output_dir: str = "data/raw") -> None:
        """
        Sauvegarde les résultats en JSON
        
        Args:
            cve_results: Résultats de l'extraction
            output_dir: Répertoire de sortie
        """
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "cves_extracted.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cve_results, f, ensure_ascii=False, indent=2)
        
        print(f"\n[INFO] Résultats sauvegardés dans: {output_file}")


def main():
    """Fonction principale"""
    
    # Chargement des bulletins depuis le fichier RSS précédemment extrait
    try:
        with open("data/raw/bulletins_anssi.json", 'r', encoding='utf-8') as f:
            bulletins_data = json.load(f)
        
        all_bulletins = bulletins_data.get("avis", []) + bulletins_data.get("alertes", [])
        
        if not all_bulletins:
            print("[ERREUR] Aucun bulletin trouvé. Veuillez d'abord exécuter rss_extractor.py")
            return
        
    except FileNotFoundError:
        print("[ERREUR] Fichier bulletins_anssi.json non trouvé.")
        print("[INFO] Veuillez d'abord exécuter: python src/rss_extractor.py")
        return
    
    # Extraction des CVE
    extractor = CVEExtractor(rate_limit_delay=2.0)
    cve_results = extractor.extract_cves_from_bulletins(all_bulletins)
    
    # Sauvegarde
    extractor.save_to_json(cve_results)
    
    # Affichage d'exemple
    if cve_results.get("total_unique_cves"):
        print(f"\n=== Exemple de CVE trouvés ===")
        print(cve_results["total_unique_cves"][:5])


if __name__ == "__main__":
    main()
