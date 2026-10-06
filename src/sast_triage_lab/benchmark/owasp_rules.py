"""Correspondance entre les règles CodeQL et les catégories OWASP Benchmark.

Chaque entrée associe l'identifiant d'une règle CodeQL à la catégorie et au
CWE attendus par OWASP Benchmark (Java 1.2 / Python 0.1). Une correspondance
n'est retenue que si le ou les CWE déclarés par CodeQL dans les métadonnées
de la règle (balises ``external/cwe/cwe-*``) contiennent le CWE attendu par
le benchmark pour cette catégorie — jamais seulement sur la ressemblance des
noms. Par exemple, ``py/cookie-injection`` ressemble à ``securecookie`` mais
est tagué CWE-020, pas CWE-614 : il est volontairement absent.

Les règles dont aucun CWE ne recoupe une catégorie du benchmark (par exemple
``java/stack-trace-exposure`` ou ``java/tainted-format-string``) sont aussi
absentes : ce n'est pas un oubli, elles n'ont simplement pas de vérité de
référence dans ce jeu de labels.

Deux catégories restent sans règle correspondante dans le pack de requêtes
CodeQL utilisé : ``trustbound`` (CWE-501, Java et Python) et, pour Python,
``hash``/``weakrand`` (CWE-328/330 : les règles disponibles les tagguent
toujours en mélange avec CWE-327, ce qui empêcherait de distinguer
``crypto`` de ces catégories sans ambiguïté).
"""

from __future__ import annotations

RULE_CATEGORY_MAP: dict[str, dict[str, tuple[str, str]]] = {
    "java": {
        "java/command-line-injection": ("cmdi", "78"),
        "java/path-injection": ("pathtraver", "22"),
        "java/sql-injection": ("sqli", "89"),
        "java/ldap-injection": ("ldapi", "90"),
        "java/xss": ("xss", "79"),
        "java/weak-cryptographic-algorithm": ("crypto", "327"),
        "java/insecure-cookie": ("securecookie", "614"),
        "java/insecure-randomness": ("weakrand", "330"),
        "java/xml/xpath-injection": ("xpathi", "643"),
    },
    "python": {
        "py/command-line-injection": ("cmdi", "78"),
        "py/path-injection": ("pathtraver", "22"),
        "py/sql-injection": ("sqli", "89"),
        "py/ldap-injection": ("ldapi", "90"),
        "py/reflective-xss": ("xss", "79"),
        "py/code-injection": ("codeinj", "94"),
        "py/unsafe-deserialization": ("deserialization", "502"),
        "py/url-redirection": ("redirect", "601"),
        "py/xxe": ("xxe", "611"),
        "py/xpath-injection": ("xpathi", "643"),
        "py/weak-cryptographic-algorithm": ("crypto", "327"),
        "py/insecure-cookie": ("securecookie", "614"),
    },
}
