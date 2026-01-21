"""
Module de chargement des données CVE depuis les fichiers locaux (data4project)
Charge les données MITRE, FIRST (EPSS), et les bulletins ANSSI (alertes/avis)
"""

import os
import json
import pandas as pd
from typing import Dict, List, Optional, Any
from datetime import datetime


class LocalDataLoader:
    """Chargeur de données CVE depuis les fichiers locaux"""
    
    def __init__(self, data_path: str = "data4project"):
        """
        Initialise le chargeur
        
        Args:
            data_path: Chemin vers le dossier data4project
        """
        self.data_path = data_path
        self.mitre_path = os.path.join(data_path, "mitre")
        self.first_path = os.path.join(data_path, "first")
        self.alertes_path = os.path.join(data_path, "alertes")
        self.avis_path = os.path.join(data_path, "Avis")
        
        self.mitre_data: Dict[str, Dict] = {}
        self.epss_data: Dict[str, Dict] = {}
        self.alertes_data: List[Dict] = []
        self.avis_data: List[Dict] = []
    
    def load_mitre_cves(self, limit: Optional[int] = None) -> int:
        """
        Charge les données CVE depuis le dossier MITRE
        
        Args:
            limit: Nombre max de CVE à charger (None = tous)
            
        Returns:
            Nombre de CVE chargés
        """
        if not os.path.exists(self.mitre_path):
            print(f"[ERREUR] Dossier MITRE non trouvé: {self.mitre_path}")
            return 0
        
        count = 0
        for cve_folder in os.listdir(self.mitre_path):
            if limit and count >= limit:
                break
            
            cve_file = os.path.join(self.mitre_path, cve_folder)
            if os.path.isfile(cve_file):
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        cve_id = data.get("cveMetadata", {}).get("cveId", cve_folder)
                        self.mitre_data[cve_id] = data
                        count += 1
                except (json.JSONDecodeError, IOError) as e:
                    continue
        
        print(f"[INFO] {count} CVE chargés depuis MITRE")
        return count
    
    def load_epss_data(self, limit: Optional[int] = None) -> int:
        """
        Charge les données EPSS depuis le dossier FIRST
        
        Args:
            limit: Nombre max de CVE à charger (None = tous)
            
        Returns:
            Nombre de scores EPSS chargés
        """
        if not os.path.exists(self.first_path):
            print(f"[ERREUR] Dossier FIRST non trouvé: {self.first_path}")
            return 0
        
        count = 0
        for cve_folder in os.listdir(self.first_path):
            if limit and count >= limit:
                break
            
            cve_file = os.path.join(self.first_path, cve_folder)
            if os.path.isfile(cve_file):
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if data.get("status") == "OK" and data.get("data"):
                            cve_info = data["data"][0]
                            cve_id = cve_info.get("cve")
                            if cve_id:
                                self.epss_data[cve_id] = {
                                    "epss": float(cve_info.get("epss", 0)),
                                    "percentile": float(cve_info.get("percentile", 0)),
                                    "date": cve_info.get("date")
                                }
                                count += 1
                except (json.JSONDecodeError, IOError, ValueError) as e:
                    continue
        
        print(f"[INFO] {count} scores EPSS chargés depuis FIRST")
        return count
    
    def load_alertes(self) -> int:
        """
        Charge les alertes CERT-FR
        
        Returns:
            Nombre d'alertes chargées
        """
        if not os.path.exists(self.alertes_path):
            print(f"[ERREUR] Dossier alertes non trouvé: {self.alertes_path}")
            return 0
        
        count = 0
        for alerte_file in os.listdir(self.alertes_path):
            file_path = os.path.join(self.alertes_path, alerte_file)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        data["type_bulletin"] = "alerte"
                        self.alertes_data.append(data)
                        count += 1
                except (json.JSONDecodeError, IOError):
                    continue
        
        print(f"[INFO] {count} alertes CERT-FR chargées")
        return count
    
    def load_avis(self, limit: Optional[int] = None) -> int:
        """
        Charge les avis CERT-FR
        
        Args:
            limit: Nombre max d'avis à charger (None = tous)
            
        Returns:
            Nombre d'avis chargés
        """
        if not os.path.exists(self.avis_path):
            print(f"[ERREUR] Dossier Avis non trouvé: {self.avis_path}")
            return 0
        
        count = 0
        for avis_file in os.listdir(self.avis_path):
            if limit and count >= limit:
                break
            
            file_path = os.path.join(self.avis_path, avis_file)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        data["type_bulletin"] = "avis"
                        self.avis_data.append(data)
                        count += 1
                except (json.JSONDecodeError, IOError):
                    continue
        
        print(f"[INFO] {count} avis CERT-FR chargés")
        return count
    
    def extract_cvss_from_mitre(self, cve_id: str) -> Dict[str, Any]:
        """
        Extrait les informations CVSS depuis les données MITRE
        
        Args:
            cve_id: Identifiant CVE
            
        Returns:
            Dictionnaire avec les scores CVSS
        """
        result = {
            "cvss_score": None,
            "cvss_version": "",
            "base_severity": "",
            "vector_string": "",
            "cwe_id": "",
            "description": "",
            "vendor": "",
            "product": "",
            "date_published": None
        }
        
        if cve_id not in self.mitre_data:
            return result
        
        data = self.mitre_data[cve_id]
        
        # Metadata
        metadata = data.get("cveMetadata", {})
        result["date_published"] = metadata.get("datePublished")
        result["vendor"] = metadata.get("assignerShortName", "")
        
        # Containers CNA
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        
        # Description
        descriptions = cna.get("descriptions", [])
        if descriptions:
            result["description"] = descriptions[0].get("value", "")
        
        # CVSS Metrics
        metrics = cna.get("metrics", [])
        for metric in metrics:
            cvss_v31 = metric.get("cvssV3_1")
            cvss_v30 = metric.get("cvssV3_0")
            cvss_v2 = metric.get("cvssV2_0")
            
            if cvss_v31:
                result["cvss_score"] = cvss_v31.get("baseScore")
                result["cvss_version"] = "3.1"
                result["base_severity"] = cvss_v31.get("baseSeverity", "")
                result["vector_string"] = cvss_v31.get("vectorString", "")
                break
            elif cvss_v30:
                result["cvss_score"] = cvss_v30.get("baseScore")
                result["cvss_version"] = "3.0"
                result["base_severity"] = cvss_v30.get("baseSeverity", "")
                result["vector_string"] = cvss_v30.get("vectorString", "")
                break
            elif cvss_v2:
                result["cvss_score"] = cvss_v2.get("baseScore")
                result["cvss_version"] = "2.0"
                result["base_severity"] = cvss_v2.get("baseSeverity", "")
                result["vector_string"] = cvss_v2.get("vectorString", "")
                break
        
        # CWE
        problem_types = cna.get("problemTypes", [])
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe = desc.get("cweId", "")
                if cwe:
                    result["cwe_id"] = cwe
                    break
        
        # Affected Products
        affected = cna.get("affected", [])
        if affected:
            first_affected = affected[0]
            result["vendor"] = first_affected.get("vendor", result["vendor"])
            result["product"] = first_affected.get("product", "")
        
        return result
    
    def consolidate_to_dataframe(self) -> pd.DataFrame:
        """
        Consolide toutes les données dans un DataFrame
        
        Returns:
            DataFrame avec toutes les données CVE consolidées
        """
        rows = []
        
        # Traitement des alertes
        for alerte in self.alertes_data:
            cves = alerte.get("cves", [])
            for cve_info in cves:
                cve_id = cve_info.get("name", "")
                if not cve_id:
                    continue
                
                # Données MITRE
                cvss_info = self.extract_cvss_from_mitre(cve_id)
                
                # Données EPSS
                epss_info = self.epss_data.get(cve_id, {})
                
                # Systèmes affectés
                affected_systems = alerte.get("affected_systems", [])
                for system in affected_systems or [{"product": {"name": "", "vendor": {"name": ""}}}]:
                    product_info = system.get("product", {})
                    vendor_info = product_info.get("vendor", {})
                    
                    row = {
                        "cve_id": cve_id,
                        "id_anssi": alerte.get("reference", ""),
                        "titre_anssi": alerte.get("title", ""),
                        "type_bulletin": "alerte",
                        "summary": alerte.get("summary", ""),
                        "date_bulletin": alerte.get("revisions", [{}])[0].get("revision_date") if alerte.get("revisions") else None,
                        "vendor": vendor_info.get("name", "") or cvss_info["vendor"],
                        "produit": product_info.get("name", "") or cvss_info["product"],
                        "description": cvss_info["description"],
                        "cvss_score": cvss_info["cvss_score"],
                        "cvss_version": cvss_info["cvss_version"],
                        "base_severity": cvss_info["base_severity"],
                        "vector_string": cvss_info["vector_string"],
                        "cwe_id": cvss_info["cwe_id"],
                        "epss_score": epss_info.get("epss"),
                        "epss_percentile": epss_info.get("percentile"),
                        "date_published": cvss_info["date_published"]
                    }
                    rows.append(row)
        
        # Traitement des avis
        for avis in self.avis_data:
            cves = avis.get("cves", [])
            for cve_info in cves:
                cve_id = cve_info.get("name", "")
                if not cve_id:
                    continue
                
                # Données MITRE
                cvss_info = self.extract_cvss_from_mitre(cve_id)
                
                # Données EPSS
                epss_info = self.epss_data.get(cve_id, {})
                
                # Systèmes affectés
                affected_systems = avis.get("affected_systems", [])
                for system in affected_systems or [{"product": {"name": "", "vendor": {"name": ""}}}]:
                    product_info = system.get("product", {})
                    vendor_info = product_info.get("vendor", {})
                    
                    row = {
                        "cve_id": cve_id,
                        "id_anssi": avis.get("reference", ""),
                        "titre_anssi": avis.get("title", ""),
                        "type_bulletin": "avis",
                        "summary": avis.get("summary", ""),
                        "date_bulletin": avis.get("revisions", [{}])[0].get("revision_date") if avis.get("revisions") else None,
                        "vendor": vendor_info.get("name", "") or cvss_info["vendor"],
                        "produit": product_info.get("name", "") or cvss_info["product"],
                        "description": cvss_info["description"],
                        "cvss_score": cvss_info["cvss_score"],
                        "cvss_version": cvss_info["cvss_version"],
                        "base_severity": cvss_info["base_severity"],
                        "vector_string": cvss_info["vector_string"],
                        "cwe_id": cvss_info["cwe_id"],
                        "epss_score": epss_info.get("epss"),
                        "epss_percentile": epss_info.get("percentile"),
                        "date_published": cvss_info["date_published"]
                    }
                    rows.append(row)
        
        # Si pas de bulletins, créer des lignes à partir des CVE MITRE uniquement
        if not rows:
            for cve_id in self.mitre_data.keys():
                cvss_info = self.extract_cvss_from_mitre(cve_id)
                epss_info = self.epss_data.get(cve_id, {})
                
                row = {
                    "cve_id": cve_id,
                    "id_anssi": "",
                    "titre_anssi": "",
                    "type_bulletin": "mitre",
                    "summary": "",
                    "date_bulletin": None,
                    "vendor": cvss_info["vendor"],
                    "produit": cvss_info["product"],
                    "description": cvss_info["description"],
                    "cvss_score": cvss_info["cvss_score"],
                    "cvss_version": cvss_info["cvss_version"],
                    "base_severity": cvss_info["base_severity"],
                    "vector_string": cvss_info["vector_string"],
                    "cwe_id": cvss_info["cwe_id"],
                    "epss_score": epss_info.get("epss"),
                    "epss_percentile": epss_info.get("percentile"),
                    "date_published": cvss_info["date_published"]
                }
                rows.append(row)
        
        df = pd.DataFrame(rows)
        
        # Conversion des dates
        if not df.empty:
            df['date_bulletin'] = pd.to_datetime(df['date_bulletin'], errors='coerce')
            df['date_published'] = pd.to_datetime(df['date_published'], errors='coerce')
        
        print(f"[INFO] DataFrame créé: {len(df)} lignes, {len(df.columns)} colonnes")
        return df
    
    def load_all(self, mitre_limit: Optional[int] = None, avis_limit: Optional[int] = None) -> pd.DataFrame:
        """
        Charge toutes les données et retourne un DataFrame consolidé
        
        Args:
            mitre_limit: Limite de CVE MITRE à charger
            avis_limit: Limite d'avis à charger
            
        Returns:
            DataFrame consolidé
        """
        print("=== Chargement des données locales ===")
        self.load_mitre_cves(limit=mitre_limit)
        self.load_epss_data(limit=mitre_limit)
        self.load_alertes()
        self.load_avis(limit=avis_limit)
        
        return self.consolidate_to_dataframe()
    
    def save_consolidated_csv(self, df: pd.DataFrame, output_path: str = "data/processed/cves_consolidated_local.csv") -> bool:
        """
        Sauvegarde le DataFrame consolidé en CSV
        
        Args:
            df: DataFrame à sauvegarder
            output_path: Chemin de sortie
            
        Returns:
            True si succès
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            df.to_csv(output_path, index=False, encoding='utf-8')
            print(f"[INFO] Données sauvegardées: {output_path}")
            return True
        except IOError as e:
            print(f"[ERREUR] Impossible de sauvegarder: {e}")
            return False


# Test standalone
if __name__ == "__main__":
    loader = LocalDataLoader("data4project")
    df = loader.load_all(mitre_limit=500, avis_limit=200)
    
    if not df.empty:
        print(f"\n=== Aperçu du DataFrame ===")
        print(df.head())
        print(f"\n=== Statistiques ===")
        print(f"CVE uniques: {df['cve_id'].nunique()}")
        print(f"Alertes: {len(df[df['type_bulletin'] == 'alerte'])}")
        print(f"Avis: {len(df[df['type_bulletin'] == 'avis'])}")
        print(f"CVE avec CVSS: {df['cvss_score'].notna().sum()}")
        print(f"CVE avec EPSS: {df['epss_score'].notna().sum()}")
        
        loader.save_consolidated_csv(df)
