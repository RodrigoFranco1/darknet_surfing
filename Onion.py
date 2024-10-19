#!/usr/bin/env python3

# Usage: python3 onion.py -l keywords.txt -u urls.txt


import argparse
from requests_tor import RequestsTor
import requests
import sys

# Función para cargar las palabras clave desde un archivo
def load_keywords(file):
    with open(file, "r") as f:
        return f.read().splitlines()

# Configuración del analizador de argumentos
parser = argparse.ArgumentParser(description="Herramienta de Threat Intelligence en la Darknet")
parser.add_argument("-l", "--list", help="Archivo con la lista de términos a buscar (uno por línea)")
parser.add_argument("-u", "--urls", help="Archivo con la lista de URLs .onion (uno por línea)")
args = parser.parse_args()

# Verificar si al menos uno de los argumentos fue proporcionado
if not args.list and not args.urls:
    print("Error: Debes proporcionar al menos un archivo de términos (-l) o un archivo de URLs (-u).")
    sys.exit(1)

# Cargar las palabras clave desde un archivo si se proporciona
keywords = []
if args.list:
    keywords = load_keywords(args.list)
    print(f"Palabras clave cargadas desde {args.list}")

# Cargar las URLs desde un archivo si se proporciona
urls = []
if args.urls:
    with open(args.urls, "r") as f:
        urls = f.read().splitlines()
    print(f"URLs cargadas desde {args.urls}")

# Si no hay URLs ni palabras clave, finalizar el script
if not keywords and not urls:
    print("No se proporcionaron ni palabras clave ni URLs para procesar.")
    sys.exit(1)

# Configurar RequestsTor para utilizar TOR
requests = RequestsTor(tor_ports=(9050,), tor_cport=9051)

# Archivo de salida para almacenar los resultados
output_file = "darknet_results.txt"

# Recorrer cada URL y realizar la búsqueda
with open(output_file, "w") as output:
    if urls:  # Solo proceder si se proporcionaron URLs
        for url in urls:
            try:
                # Hacer la solicitud HTTP a la URL en la darknet
                r = requests.get(url, timeout=30)
                r.raise_for_status()

                # Dividir el contenido en líneas para buscar las palabras clave en cada línea
                lines = r.text.splitlines()
                found_keywords = []

                if keywords:  # Solo buscar términos si se proporcionaron
                    for i, line in enumerate(lines):
                        for keyword in keywords:
                            if keyword in line:
                                # Añadir el término y la línea donde fue encontrado a la lista
                                found_keywords.append((keyword, i + 1, line.strip()))

                    if found_keywords:
                        # Escribir la URL y los términos encontrados en el archivo de salida
                        output.write(f"\nURL: {url}\n")
                        for keyword, line_number, line_text in found_keywords:
                            output.write(f"Término encontrado: {keyword} (Línea {line_number}): {line_text}\n")
                        output.write("-" * 80 + "\n")
                        print(f"Términos encontrados en {url}: {', '.join([kw[0] for kw in found_keywords])}")
                    else:
                        print(f"Ningún término encontrado en {url}")
                else:
                    print(f"Contenido de {url} descargado, pero no se especificaron palabras clave para buscar.")
                    output.write(f"\nContenido de {url} descargado sin búsqueda de palabras clave.\n")

            except requests.exceptions.RequestException as e:
                print(f"Error al conectar con {url}: {e}")
                output.write(f"Error al conectar con {url}: {e}\n")
    else:
        print("No se proporcionaron URLs para procesar.")
