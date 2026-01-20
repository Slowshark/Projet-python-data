"""
Module de consolidation des données dans un DataFrame Pandas
"""

import pandas as pd
import json
import os
from typing import List, Dict, Optional
from datetime import datetime

class DataConsolidator:
    """Consolidateur de données dans un DataFrame Pandas"""
    
    def __init__(self):
        """Initialise le consolidateur"""
        self.df = None
        self.bulletins_data = {}
        self.cve_data = {}
        self.enriched_cves = []
    
    def load_bulletins(self, file_path: str = "data/raw/bulletins_anssi.json") -> bool:
        """
        Charge les données des bulletins
        
        Args:
            file_path: Chemin du fichier JSON des bulletins
            
        Returns:
            True si succès, False sinon
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.bulletins_data = json.load(f)
            
            total = len(self.bulletins_data.get("avis", [])) + len(self.bulletins_data.get("alertes", []))
            print(f"[INFO] {total} bulletins chargés")
            return True
            
        except FileNotFoundError:
            print(f"[ERREUR] Fichier {file_path} non trouvé")
            return False
    
    def load_cves(self, file_path: str = "data/raw/cves_extracted.json") -> bool:
        """
        Charge les données des CVE extraits
        
        Args:
            file_path: Chemin du fichier JSON des CVE extraits
            
        Returns:
            True si succès, False sinon
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.cve_data = json.load(f)
            
            print(f"[INFO] Données CVE chargées: {self.cve_data.get('total_unique_cve_count', 0)} CVE uniques")
            return True
            
        except FileNotFoundError:
            print(f"[ERREUR] Fichier {file_path} non trouvé")
            return False
    
    def load_enriched_cves(self, file_path: str = "data/raw/cves_enriched.json") -> bool:
        """
        Charge les données des CVE enrichis
        
        Args:
            file_path: Chemin du fichier JSON des CVE enrichis
            
        Returns:
            True si succès, False sinon
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.enriched_cves = json.load(f)
            
            print(f"[INFO] {len(self.enriched_cves)} CVE enrichis chargés")
            return True
            
        except FileNotFoundError:
            print(f"[ERREUR] Fichier {file_path} non trouvé")
            return False
    
    def create_enriched_cve_map(self) -> Dict:
        """
        Crée un dictionnaire de recherche rapide pour les CVE enrichis
        
        Returns:
            Dictionnaire {cve_id: enriched_data}
        """
        return {cve["cve_id"]: cve for cve in self.enriched_cves}
    
    def consolidate(self) -> Optional[pd.DataFrame]:
        """
        Consolide toutes les données dans un DataFrame Pandas
        
        Returns:
            DataFrame consolidé ou None en cas d'erreur
        """
        print("\n=== Consolidation des Données ===\n")
        
        # Chargement des données
        if not self.load_bulletins():
            return None
        if not self.load_cves():
            return None
        if not self.load_enriched_cves():
            print("[AVERTISSEMENT] Fichier CVE enrichis non trouvé, continuation sans enrichissement")
        
        # Création de la carte des CVE enrichis
        enriched_map = self.create_enriched_cve_map()
        
        # Construction du DataFrame
        rows = []
        
        # Parcours des bulletins (avis et alertes)
        all_bulletins = (
            self.bulletins_data.get("avis", []) +
            self.bulletins_data.get("alertes", [])
        )
        
        bulletin_cve_map = {}
        for mapping in self.cve_data.get("bulletin_cve_mapping", []):
            bulletin_cve_map[mapping["bulletin_id"]] = mapping
        
        print(f"Traitement de {len(all_bulletins)} bulletins...\n")
        
        for bulletin in all_bulletins:
            bulletin_id = bulletin.get("id", "N/A")
            
            # Récupération des CVE pour ce bulletin
            cve_mapping = bulletin_cve_map.get(bulletin_id, {})
            cves = cve_mapping.get("cves", [])
            
            if not cves:
                print(f"[AVERTISSEMENT] Aucun CVE trouvé pour {bulletin_id}")
                cves = ["N/A"]
            
            # Création une ligne par CVE du bulletin
            for cve_id in cves:
                enriched_cve = enriched_map.get(cve_id, {})
                
                # Extraction des produits affectés
                products = enriched_cve.get("affected_products", [])
                
                if not products:
                    # Créer une ligne sans produits spécifiques
                    row = {
                        "id_anssi": bulletin_id,
                        "titre_anssi": bulletin.get("titre", "N/A"),
                        "type_bulletin": bulletin.get("type_bulletin", "N/A"),
                        "date_publication": bulletin.get("date_publication", "N/A"),
                        "cve_id": cve_id,
                        "cvss_score": enriched_cve.get("cvss_score"),
                        "base_severity": enriched_cve.get("base_severity", "Non disponible"),
                        "cwe_id": enriched_cve.get("cwe_id", "Non disponible"),
                        "cwe_description": enriched_cve.get("cwe_description", "Non disponible"),
                        "epss_score": enriched_cve.get("epss_score"),
                        "lien_bulletin": bulletin.get("lien", "N/A"),
                        "description_cve": enriched_cve.get("description", "Non disponible"),
                        "vendor": "N/A",
                        "produit": "N/A",
                        "versions_affectees": "N/A"
                    }
                    rows.append(row)
                else:
                    # Créer une ligne par produit affecté
                    for product in products:
                        row = {
                            "id_anssi": bulletin_id,
                            "titre_anssi": bulletin.get("titre", "N/A"),
                            "type_bulletin": bulletin.get("type_bulletin", "N/A"),
                            "date_publication": bulletin.get("date_publication", "N/A"),
                            "cve_id": cve_id,
                            "cvss_score": enriched_cve.get("cvss_score"),
                            "base_severity": enriched_cve.get("base_severity", "Non disponible"),
                            "cwe_id": enriched_cve.get("cwe_id", "Non disponible"),
                            "cwe_description": enriched_cve.get("cwe_description", "Non disponible"),
                            "epss_score": enriched_cve.get("epss_score"),
                            "lien_bulletin": bulletin.get("lien", "N/A"),
                            "description_cve": enriched_cve.get("description", "Non disponible"),
                            "vendor": product.get("vendor", "N/A"),
                            "produit": product.get("product", "N/A"),
                            "versions_affectees": ", ".join(product.get("affected_versions", []))
                        }
                        rows.append(row)
        
        # Création du DataFrame
        if rows:
            self.df = pd.DataFrame(rows)
            
            # Conversion des colonnes numériques
            if "cvss_score" in self.df.columns:
                self.df["cvss_score"] = pd.to_numeric(self.df["cvss_score"], errors="coerce")
            if "epss_score" in self.df.columns:
                self.df["epss_score"] = pd.to_numeric(self.df["epss_score"], errors="coerce")
        else:
            # Créer un DataFrame vide avec les bonnes colonnes
            self.df = pd.DataFrame(columns=[
                "id_anssi", "titre_anssi", "type_bulletin", "date_publication",
                "cve_id", "cvss_score", "base_severity", "cwe_id", "cwe_description",
                "epss_score", "lien_bulletin", "description_cve", "vendor", "produit", "versions_affectees"
            ])
        
        print(f"\n[SUCCÈS] DataFrame créé avec {len(self.df)} lignes")
        
        return self.df
    
    def save_to_csv(self, output_dir: str = "data/processed") -> str:
        """
        Sauvegarde le DataFrame en CSV
        
        Args:
            output_dir: Répertoire de sortie
            
        Returns:
            Chemin du fichier CSV
        """
        if self.df is None:
            print("[ERREUR] Aucun DataFrame à sauvegarder")
            return ""
        
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "cves_consolidated.csv")
        self.df.to_csv(output_file, index=False, encoding='utf-8')
        
        print(f"\n[INFO] DataFrame sauvegardé dans: {output_file}")
        
        return output_file
    
    def display_summary(self) -> None:
        """Affiche un résumé du DataFrame"""
        
        if self.df is None or len(self.df) == 0:
            print("[INFO] Aucune donnée à afficher (DataFrame vide)")
            return
        
        print("\n=== Résumé du DataFrame ===\n")
        print(f"Dimensions: {self.df.shape[0]} lignes, {self.df.shape[1]} colonnes")
        print(f"\nColonnes: {', '.join(self.df.columns.tolist())}")
        
        print(f"\n--- Statistiques ---")
        if 'cve_id' in self.df.columns:
            print(f"CVE uniques: {self.df['cve_id'].nunique()}")
        if 'id_anssi' in self.df.columns:
            print(f"Bulletins uniques: {self.df['id_anssi'].nunique()}")
        if 'vendor' in self.df.columns:
            print(f"Vendors uniques: {self.df['vendor'].nunique()}")
        
        if 'cvss_score' in self.df.columns and len(self.df['cvss_score'].dropna()) > 0:
            print(f"\n--- Scores CVSS ---")
            print(self.df['cvss_score'].describe())
        
        print(f"\n--- Gravité par Score CVSS ---")
        print(self.df['base_severity'].value_counts())
        
        print(f"\n--- Premiers lignes ---")
        print(self.df.head())


def main():
    """Fonction principale"""
    
    consolidator = DataConsolidator()
    
    # Consolidation
    df = consolidator.consolidate()
    
    if df is not None:
        # Sauvegarde
        consolidator.save_to_csv()
        
        # Affichage du résumé
        consolidator.display_summary()
    else:
        print("[ERREUR] Consolidation échouée")


if __name__ == "__main__":
    main()
