#!/bin/bash
# Script d'installation et de démarrage du projet

echo "=================================="
echo "Installation du Projet ANSSI"
echo "=================================="

# Vérification de Python
if ! command -v python &> /dev/null; then
    echo "❌ Python n'est pas installé"
    exit 1
fi

echo "✓ Python trouvé"

# Création de l'environnement virtuel
if [ ! -d ".venv" ]; then
    echo ""
    echo "Création de l'environnement virtuel..."
    python -m venv .venv
fi

# Activation de l'environnement
echo "Activation de l'environnement virtuel..."
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "❌ Erreur lors de l'activation de l'environnement"
    exit 1
fi

# Installation des dépendances
echo ""
echo "Installation des dépendances..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "✓ Installation terminée"
echo ""
echo "===================================="
echo "Pour lancer le pipeline:"
echo "python main.py"
echo ""
echo "Pour ouvrir le Jupyter Notebook:"
echo "jupyter notebook notebooks/analysis.ipynb"
echo "===================================="
