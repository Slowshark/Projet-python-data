"""
Module d'extraction des flux RSS des bulletins ANSSI (avis et alertes)
"""

import feedparser
import requests
import time
import json
from datetime import datetime
from typing import List, Dict
import os

class RSSExtractor:
    """Extracteur de flux RSS ANSSI"""
    
    # URLs des flux RSS ANSSI
    ANSSI_AVIS_URL = "https://www.cert.ssi.gouv.fr/avis/feed"
    ANSSI_ALERTES_URL = "https://www.cert.ssi.gouv.fr/alerte/feed"
    
    def __init__(self, rate_limit_delay: float = 2.0):
        """
        Initialise l'extracteur
        
        Args:
            rate_limit_delay: Délai en secondes entre les requêtes (pour respecter les rate limits)
        """
        self.rate_limit_delay = rate_limit_delay
        self.avis_data = []
        self.alertes_data = []
    
    def extract_feed(self, url: str, feed_type: str = "avis") -> List[Dict]:
        """
        Extrait les données d'un flux RSS
        
        Args:
            url: URL du flux RSS
            feed_type: Type de bulletin ("avis" ou "alerte")
            
        Returns:
            Liste des entrées du flux
        """
        try:
            print(f"[INFO] Extraction du flux RSS {feed_type}...")
            
            # Utiliser requests pour gérer les redirections
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            if response.status_code != 200:
                print(f"[ERREUR] Impossible d'accéder au flux {feed_type}. Status: {response.status_code}")
                return []
            
            # Parser le contenu avec feedparser
            feed = feedparser.parse(response.text)
            
            entries = []
            for entry in feed.entries:
                entry_id = entry.get("id", "")
                if isinstance(entry_id, str) and "/" in entry_id:
                    extracted_id = entry_id.split("/")[-2]
                else:
                    extracted_id = entry_id if isinstance(entry_id, str) else "N/A"
                
                description = entry.get("description", "N/A")
                description = description[:500] if description else "N/A"  # Truncate description
                
                data = {
                    "id": extracted_id,
                    "titre": entry.get("title", "N/A"),
                    "description": description,
                    "lien": entry.get("link", "N/A"),
                    "date_publication": entry.get("published", "N/A"),
                    "type_bulletin": feed_type,
                }
                entries.append(data)
            
            print(f"[INFO] {len(entries)} entrées extraites du flux {feed_type}")
            return entries
            
        except Exception as e:
            print(f"[ERREUR] Erreur lors de l'extraction du flux {feed_type}: {e}")
            return []
    
    def extract_all_feeds(self) -> Dict:
        """
        Extrait tous les flux RSS (avis et alertes)
        
        Returns:
            Dictionnaire contenant avis et alertes
        """
        print("\n=== Extraction des Flux RSS ANSSI ===\n")
        
        # Extraction des avis
        self.avis_data = self.extract_feed(self.ANSSI_AVIS_URL, "avis")
        time.sleep(self.rate_limit_delay)  # Respect du rate limit
        
        # Extraction des alertes
        self.alertes_data = self.extract_feed(self.ANSSI_ALERTES_URL, "alerte")
        time.sleep(self.rate_limit_delay)
        
        result = {
            "avis": self.avis_data,
            "alertes": self.alertes_data,
            "total": len(self.avis_data) + len(self.alertes_data),
            "timestamp": datetime.now().isoformat()
        }
        
        print(f"\n[SUCCÈS] Extraction terminée:")
        print(f"  - Avis: {len(self.avis_data)}")
        print(f"  - Alertes: {len(self.alertes_data)}")
        print(f"  - Total: {result['total']}")
        
        return result
    
    def save_to_json(self, output_dir: str = "data/raw") -> None:
        """
        Sauvegarde les données extraites en JSON
        
        Args:
            output_dir: Répertoire de sortie
        """
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "bulletins_anssi.json")
        data = {
            "avis": self.avis_data,
            "alertes": self.alertes_data,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"\n[INFO] Données sauvegardées dans: {output_file}")


def main():
    """Fonction principale"""
    extractor = RSSExtractor(rate_limit_delay=2.0)
    
    # Extraction des flux
    result = extractor.extract_all_feeds()
    
    # Sauvegarde en JSON
    extractor.save_to_json()
    
    # Affichage d'exemple
    if extractor.avis_data:
        print("\n=== Exemple d'Avis ===")
        avis = extractor.avis_data[0]
        print(f"Titre: {avis['titre']}")
        print(f"Lien: {avis['lien']}")
        print(f"Date: {avis['date_publication']}")


if __name__ == "__main__":
    main()
