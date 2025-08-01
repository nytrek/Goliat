#!/usr/bin/env python3
"""
Sistema Avanzado de Gestión de Contraseñas con IA v1.0.0
Desarrollado por: github.com/nytrek
Licencia: MIT
"""

import re
import secrets
import string
import math
import time
import hashlib
import json
import os
import sys
import requests
import sqlite3
import base64
import csv
from typing import List, Dict, Tuple, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path

# Importaciones de Rich para interfaz avanzada
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich.layout import Layout
    from rich.tree import Tree
    from rich import box
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.live import Live
    from rich.spinner import Spinner
except ImportError:
    print("Error: Rich library not found. Install with: pip install rich")
    sys.exit(1)

# Configuracion del sistema
console = Console()
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

TITLE = """
   ____  ___  _     ___    _  _____ 
  / ___|/ _ \| |   |_ _|  / \|_   _|
 | |  _| | | | |    | |  / _ \ | |  
 | |_| | |_| | |___ | | / ___ \| |  
  \____|\___/|_____|___/_/   \_\_| 
"""

# Constantes de seguridad
SECURITY_LEVELS = {
    'CRITICAL': {'score': 95, 'color': 'bright_green', 'emoji': '🛡️'},
    'EXCELLENT': {'score': 85, 'color': 'green', 'emoji': '✅'},
    'STRONG': {'score': 70, 'color': 'blue', 'emoji': '💪'},
    'MODERATE': {'score': 50, 'color': 'yellow', 'emoji': '⚠️'},
    'WEAK': {'score': 30, 'color': 'orange1', 'emoji': '⚡'},
    'VERY_WEAK': {'score': 0, 'color': 'red', 'emoji': '❌'},
    'COMPROMISED': {'score': 0, 'color': 'bright_red', 'emoji': '🚨'}
}

# Wordlists mejorados para frases de contraseña
WORDLISTS = {
    'common': [
        'abandon', 'ability', 'absent', 'absorb', 'abstract', 'absurd', 'abuse', 'access',
        'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across',
        'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address',
        'adjust', 'admit', 'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford',
        'afraid', 'again', 'agent', 'agree', 'ahead', 'aim', 'air', 'airport',
        'aisle', 'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley',
        'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always',
        'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient',
        'anger', 'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another',
        'answer', 'antenna', 'antique', 'anxiety', 'any', 'apart', 'apology', 'appear',
        'apple', 'approve', 'april', 'arcade', 'arch', 'arctic', 'area', 'arena',
        'argue', 'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest',
        'arrive', 'arrow', 'art', 'artist', 'artwork', 'ask', 'aspect', 'assault',
        'asset', 'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend',
        'attitude', 'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto',
        'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome',
        'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge', 'bag',
        'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely',
        'bargain', 'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean',
        'beauty', 'because', 'become', 'beef', 'before', 'begin', 'behave', 'behind',
        'believe', 'below', 'belt', 'bench', 'benefit', 'best', 'betray', 'better',
        'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird',
        'birth', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak',
        'bless', 'blind', 'blood', 'blossom', 'blow', 'blue', 'blur', 'blush',
        'board', 'boat', 'body', 'boil', 'bomb', 'bone', 'bonus', 'book',
        'boost', 'border', 'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box',
        'boy', 'bracket', 'brain', 'brand', 'brass', 'brave', 'bread', 'breeze',
        'brick', 'bridge', 'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken',
        'bronze', 'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget',
        'buffalo', 'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker', 'burden',
        'burger', 'burst', 'bus', 'business', 'busy', 'butter', 'buyer', 'buzz'
    ],
    'tech': [
        'algorithm', 'android', 'api', 'application', 'artificial', 'bandwidth', 'bitcoin',
        'blockchain', 'browser', 'cache', 'cloud', 'code', 'compiler', 'computer',
        'crypto', 'data', 'database', 'debug', 'digital', 'download', 'encryption',
        'ethernet', 'firewall', 'framework', 'hacker', 'hardware', 'internet', 'java',
        'kernel', 'linux', 'machine', 'memory', 'network', 'operating', 'password',
        'pixel', 'processor', 'program', 'protocol', 'python', 'quantum', 'router',
        'security', 'server', 'software', 'storage', 'system', 'technology', 'terminal',
        'upload', 'virtual', 'virus', 'web', 'wifi', 'wireless'
    ],
    'nature': [
        'avalanche', 'bamboo', 'canyon', 'coral', 'desert', 'eclipse', 'forest',
        'glacier', 'hurricane', 'island', 'jungle', 'lagoon', 'mountain', 'ocean',
        'prairie', 'rainbow', 'river', 'storm', 'thunder', 'volcano', 'waterfall',
        'arctic', 'blizzard', 'breeze', 'cascade', 'cliff', 'comet', 'crystal',
        'dune', 'earth', 'flame', 'frost', 'galaxy', 'horizon', 'lightning',
        'meteor', 'nebula', 'oasis', 'planet', 'quasar', 'summit', 'tsunami',
        'universe', 'wind', 'zenith'
    ],
    'animals': [
        'albatross', 'bear', 'cheetah', 'dolphin', 'elephant', 'falcon', 'giraffe',
        'hawk', 'iguana', 'jaguar', 'kangaroo', 'leopard', 'mongoose', 'narwhal',
        'octopus', 'panther', 'quetzal', 'rhinoceros', 'shark', 'tiger', 'unicorn',
        'vulture', 'whale', 'xerus', 'yak', 'zebra', 'badger', 'cobra', 'dragon',
        'eagle', 'fox', 'gorilla', 'hamster', 'lynx', 'owl', 'penguin', 'rabbit',
        'snake', 'turtle', 'wolf'
    ]
}

@dataclass
class PasswordMetrics:
    """Métricas detalladas de una contraseña"""
    strength_score: float
    entropy_bits: float
    crack_time_seconds: float
    vulnerabilities: List[str]
    recommendations: List[str]
    complexity_level: str
    character_analysis: Dict[str, int]
    pattern_analysis: Dict[str, bool]
    breach_status: bool = False
    creation_time: str = ""

@dataclass
class GenerationConfig:
    """Configuración para generación de contraseñas"""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = True
    custom_symbols: str = ""
    exclude_chars: str = ""
    require_all_types: bool = True

class DatabaseManager:
    """Gestor de base de datos para historial y estadísticas"""
    
    def __init__(self):
        self.db_path = DATA_DIR / "password_manager.db"
        self.init_database()
    
    def init_database(self):
        """Inicializa la base de datos"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT NOT NULL,
                    strength_score REAL,
                    entropy_bits REAL,
                    length INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    password_type TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS breach_cache (
                    hash_prefix TEXT PRIMARY KEY,
                    hash_suffixes TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    def save_password_analysis(self, password: str, metrics: PasswordMetrics, pwd_type: str):
        """Guarda análisis de contraseña en historial"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO password_history 
                (password_hash, strength_score, entropy_bits, length, password_type)
                VALUES (?, ?, ?, ?, ?)
            """, (password_hash, metrics.strength_score, metrics.entropy_bits, 
                  len(password), pwd_type))
    
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas del uso"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Estadísticas generales
            cursor.execute("SELECT COUNT(*) FROM password_history")
            total_analyzed = cursor.fetchone()[0]
            
            cursor.execute("SELECT AVG(strength_score) FROM password_history")
            avg_strength = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT AVG(entropy_bits) FROM password_history")
            avg_entropy = cursor.fetchone()[0] or 0
            
            # Distribución por fortaleza
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN strength_score >= 85 THEN 'EXCELLENT'
                        WHEN strength_score >= 70 THEN 'STRONG'
                        WHEN strength_score >= 50 THEN 'MODERATE'
                        WHEN strength_score >= 30 THEN 'WEAK'
                        ELSE 'VERY_WEAK'
                    END as level,
                    COUNT(*) as count
                FROM password_history
                GROUP BY level
            """)
            distribution = dict(cursor.fetchall())
            
            return {
                'total_analyzed': total_analyzed,
                'average_strength': avg_strength,
                'average_entropy': avg_entropy,
                'strength_distribution': distribution
            }

class AdvancedPasswordSecurityAI:
    """IA avanzada para análisis de seguridad de contraseñas"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.common_patterns = self._load_patterns()
        self.common_passwords = self._load_common_passwords()
        self.breach_cache = {}
        self.lock = threading.Lock()
        
        # Patrones de teclado mejorados
        self.keyboard_patterns = [
            r'(qwerty|asdfgh|zxcvbn)',
            r'(123456|654321|098765)',
            r'(qwer|asdf|zxcv)',
            r'(uiop|hjkl|bnm)',
            r'(147|258|369|741|852|963)'
        ]
        
        # Patrones de fecha
        self.date_patterns = [
            r'(19|20)\d{2}',  # Años
            r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])',  # MMDD
            r'(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])',  # DDMM
        ]
    
    def _load_patterns(self) -> List[str]:
        """Carga patrones comunes mejorados"""
        return [
            r'(.)\1{2,}',  # Repetición de caracteres
            r'(012|123|234|345|456|567|678|789|890)',  # Secuencias numéricas
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Secuencias alfabéticas
            r'(password|admin|user|login|pass|secret|key)',  # Palabras comunes
            r'(qwerty|asdfgh|zxcvbn|qwertyui|asdfghjk)',  # Patrones de teclado
            r'(\d{4,})',  # Secuencias largas de números
            r'([a-zA-Z]+\d+|[a-zA-Z]+\d+[a-zA-Z]+)',  # Patrones palabra+número
        ]
    
    def _load_common_passwords(self) -> set:
        """Carga lista extendida de contraseñas comunes"""
        common_file = DATA_DIR / "common_passwords.txt"
        if common_file.exists():
            try:
                with open(common_file, 'r', encoding='utf-8') as f:
                    return {line.strip().lower() for line in f if line.strip()}
            except Exception:
                pass
        
        # Lista base extendida
        return {
            'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'password1',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '12345678', 'iloveyou',
            'princess', 'rockyou', 'shadow', 'superman', 'michael', 'ninja',
            'mustang', 'mercedes', 'jessica', 'dragon', 'batman', 'master',
            'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow', 'football',
            'jesus', 'hunter', 'killer', 'trustno1', 'jordan', 'jennifer',
            'zxcvbnm', 'asdfgh', 'hunter2', 'changeme', 'secret', 'password!',
            'password@', 'password#', 'password$', '12345', '1234', '123',
            'admin123', 'root', 'toor', 'test', 'guest', 'user', 'demo'
        }
    
    def check_password_breach(self, password: str, timeout: int = 5) -> Tuple[bool, int]:
        """Verifica si la contraseña está en brechas conocidas con timeout"""
        if not password:
            return False, 0
        
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        # Verificar cache local
        if prefix in self.breach_cache:
            suffixes = self.breach_cache[prefix]
            if suffix in suffixes:
                return True, suffixes[suffix]
            return False, 0
        
        try:
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=timeout,
                headers={'User-Agent': 'PasswordManager/4.0'}
            )
            
            if response.status_code == 200:
                suffixes = {}
                for line in response.text.splitlines():
                    parts = line.split(':')
                    if len(parts) == 2:
                        suffixes[parts[0]] = int(parts[1])
                
                with self.lock:
                    self.breach_cache[prefix] = suffixes
                
                if suffix in suffixes:
                    return True, suffixes[suffix]
                return False, 0
                
        except requests.RequestException:
            # Si falla la conexión, continuamos sin la verificación
            pass
        
        return False, 0
    
    def calculate_advanced_entropy(self, password: str) -> float:
        """Cálculo avanzado de entropía considerando patrones"""
        if not password:
            return 0.0
        
        # Determinar espacio de caracteres
        charset_size = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`' for c in password)
        has_extended = any(ord(c) > 127 for c in password)
        
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        if has_extended: charset_size += 100
        
        if charset_size == 0:
            return 0.0
        
        # Entropía base
        base_entropy = len(password) * math.log2(charset_size)
        
        # Penalizaciones por patrones
        pattern_penalty = 1.0
        
        # Penalización por repetición de caracteres
        unique_chars = len(set(password))
        repetition_ratio = unique_chars / len(password)
        pattern_penalty *= repetition_ratio
        
        # Penalización por secuencias
        for pattern in self.common_patterns:
            if re.search(pattern, password.lower()):
                pattern_penalty *= 0.8
                break
        
        # Penalización por patrones de teclado
        for pattern in self.keyboard_patterns:
            if re.search(pattern, password.lower()):
                pattern_penalty *= 0.7
                break
        
        # Penalización por fechas
        for pattern in self.date_patterns:
            if re.search(pattern, password):
                pattern_penalty *= 0.9
                break
        
        # Penalización por contraseñas comunes
        if password.lower() in self.common_passwords:
            pattern_penalty *= 0.1
        
        return base_entropy * pattern_penalty
    
    def analyze_character_composition(self, password: str) -> Dict[str, int]:
        """Analiza la composición de caracteres"""
        analysis = {
            'lowercase': sum(1 for c in password if c.islower()),
            'uppercase': sum(1 for c in password if c.isupper()),
            'digits': sum(1 for c in password if c.isdigit()),
            'special': sum(1 for c in password if c in '!@#$%^&*()_+-=[]{}|;:,.<>?~`'),
            'spaces': sum(1 for c in password if c.isspace()),
            'extended': sum(1 for c in password if ord(c) > 127),
            'unique_chars': len(set(password)),
            'repeated_chars': len(password) - len(set(password))
        }
        return analysis
    
    def detect_advanced_patterns(self, password: str) -> Dict[str, bool]:
        """Detección avanzada de patrones"""
        patterns = {
            'repeated_chars': bool(re.search(r'(.)\1{2,}', password)),
            'sequential_nums': bool(re.search(r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)', password)),
            'sequential_letters': bool(re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower())),
            'keyboard_pattern': any(re.search(pattern, password.lower()) for pattern in self.keyboard_patterns),
            'date_pattern': any(re.search(pattern, password) for pattern in self.date_patterns),
            'common_words': any(word in password.lower() for word in ['password', 'admin', 'user', 'login', 'secret']),
            'only_numbers': password.isdigit(),
            'only_letters': password.isalpha(),
            'starts_with_capital': password[0].isupper() if password else False,
            'ends_with_number': password[-1].isdigit() if password else False,
            'alternating_case': self._check_alternating_case(password),
            'leet_speak': self._check_leet_speak(password)
        }
        return patterns
    
    def _check_alternating_case(self, password: str) -> bool:
        """Verifica si hay alternancia de mayúsculas/minúsculas"""
        if len(password) < 4:
            return False
        
        alternating = 0
        for i in range(1, len(password)):
            if password[i-1].isalpha() and password[i].isalpha():
                if password[i-1].islower() != password[i].islower():
                    alternating += 1
        
        return alternating > len(password) * 0.3
    
    def _check_leet_speak(self, password: str) -> bool:
        """Detecta uso de leet speak"""
        leet_chars = {'3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '@': 'a', '4': 'a'}
        leet_count = sum(1 for c in password if c in leet_chars)
        return leet_count > 0
    
    def estimate_crack_time_advanced(self, password: str, entropy: float) -> Dict[str, float]:
        """Estimación avanzada de tiempo de crackeo por diferentes métodos"""
        if entropy <= 0:
            return {scenario: 0 for scenario in ['online_throttled', 'online_unthrottled', 'offline_slow', 'offline_fast', 'offline_massive']}
        
        # Diferentes escenarios de ataque
        attack_scenarios = {
            'online_throttled': 10,  # 10 intentos/segundo (con throttling)
            'online_unthrottled': 1000,  # 1K intentos/segundo
            'offline_slow': 100_000,  # 100K intentos/segundo (CPU)
            'offline_fast': 100_000_000,  # 100M intentos/segundo (GPU)
            'offline_massive': 100_000_000_000  # 100B intentos/segundo (botnet/ASIC)
        }
        
        # Intentos necesarios (promedio)
        attempts_needed = (2 ** entropy) / 2
        
        # Factores de reducción por patrones conocidos
        reduction_factor = 1.0
        if password.lower() in self.common_passwords:
            reduction_factor = 0.001  # Se encuentra muy rápido en diccionarios
        elif any(re.search(pattern, password.lower()) for pattern in self.common_patterns):
            reduction_factor = 0.1  # Patrones reducen significativamente el tiempo
        
        crack_times = {}
        for scenario, speed in attack_scenarios.items():
            crack_time = (attempts_needed * reduction_factor) / speed
            crack_times[scenario] = max(crack_time, 0.001)  # Mínimo 1ms
        
        return crack_times
    
    def generate_detailed_recommendations(self, password: str, metrics: PasswordMetrics) -> List[str]:
        """Genera recomendaciones detalladas y personalizadas"""
        recommendations = []
        char_analysis = metrics.character_analysis
        patterns = metrics.pattern_analysis
        
        # Recomendaciones de longitud
        if len(password) < 8:
            recommendations.append("🔴 CRÍTICO: Aumentar longitud a mínimo 8 caracteres")
        elif len(password) < 12:
            recommendations.append("🟡 RECOMENDADO: Aumentar longitud a 12+ caracteres para mayor seguridad")
        elif len(password) < 16:
            recommendations.append("🟢 BUENO: Considerar 16+ caracteres para seguridad óptima")
        
        # Recomendaciones de composición
        if char_analysis['lowercase'] == 0:
            recommendations.append("📝 Añadir letras minúsculas (a-z)")
        if char_analysis['uppercase'] == 0:
            recommendations.append("📝 Añadir letras mayúsculas (A-Z)")
        if char_analysis['digits'] == 0:
            recommendations.append("🔢 Añadir números (0-9)")
        if char_analysis['special'] == 0:
            recommendations.append("⚡ Añadir símbolos especiales (!@#$%^&*)")
        
        # Recomendaciones por patrones detectados
        if patterns.get('repeated_chars'):
            recommendations.append("🔄 Evitar repetición excesiva de caracteres")
        if patterns.get('sequential_nums') or patterns.get('sequential_letters'):
            recommendations.append("📈 Evitar secuencias predecibles (123, abc)")
        if patterns.get('keyboard_pattern'):
            recommendations.append("⌨️ Evitar patrones de teclado (qwerty, asdf)")
        if patterns.get('date_pattern'):
            recommendations.append("📅 Evitar fechas y años en la contraseña")
        if patterns.get('common_words'):
            recommendations.append("📖 Evitar palabras comunes del diccionario")
        if patterns.get('only_numbers') or patterns.get('only_letters'):
            recommendations.append("🔀 Combinar diferentes tipos de caracteres")
        
        # Recomendaciones de entropía
        if metrics.entropy_bits < 30:
            recommendations.append("🧮 CRÍTICO: Aumentar complejidad significativamente (entropía muy baja)")
        elif metrics.entropy_bits < 50:
            recommendations.append("🧮 Mejorar diversidad de caracteres (entropía baja)")
        elif metrics.entropy_bits < 70:
            recommendations.append("🧮 Buena entropía, considerar pequeñas mejoras")
        
        # Recomendaciones por breach
        if metrics.breach_status:
            recommendations.append("🚨 URGENTE: Esta contraseña fue comprometida en brechas de datos - CAMBIAR INMEDIATAMENTE")
        
        # Recomendaciones adicionales
        if char_analysis['unique_chars'] / len(password) < 0.6:
            recommendations.append("🔤 Usar mayor variedad de caracteres únicos")
        
        return recommendations
    
    def classify_security_level(self, metrics: PasswordMetrics) -> str:
        """Clasificación avanzada del nivel de seguridad"""
        score = metrics.strength_score
        
        # Override por breach
        if metrics.breach_status:
            return 'COMPROMISED'
        
        # Clasificación por puntuación
        if score >= 95:
            return 'CRITICAL'
        elif score >= 85:
            return 'EXCELLENT'
        elif score >= 70:
            return 'STRONG'
        elif score >= 50:
            return 'MODERATE'
        elif score >= 30:
            return 'WEAK'
        else:
            return 'VERY_WEAK'
    
    def analyze_password_comprehensive(self, password: str) -> PasswordMetrics:
        """Análisis comprehensivo de contraseña con IA avanzada"""
        if not password:
            return PasswordMetrics(
                strength_score=0, entropy_bits=0, crack_time_seconds=0,
                vulnerabilities=["Contraseña vacía"], recommendations=["Ingresar una contraseña válida"],
                complexity_level="VERY_WEAK", character_analysis={}, pattern_analysis={},
                creation_time=datetime.now().isoformat()
            )
        
        # Análisis de composición
        char_analysis = self.analyze_character_composition(password)
        
        # Análisis de patrones
        pattern_analysis = self.detect_advanced_patterns(password)
        
        # Cálculo de entropía avanzada
        entropy = self.calculate_advanced_entropy(password)
        
        # Verificación de brechas
        is_breached, breach_count = self.check_password_breach(password)
        
        # Estimación de tiempo de crackeo
        crack_times = self.estimate_crack_time_advanced(password, entropy)
        
        # Cálculo de puntuación de fortaleza
        strength_score = self._calculate_strength_score(password, char_analysis, pattern_analysis, entropy, is_breached)
        
        # Detección de vulnerabilidades
        vulnerabilities = self._detect_vulnerabilities(password, char_analysis, pattern_analysis, is_breached, breach_count)
        
        # Crear métricas
        metrics = PasswordMetrics(
            strength_score=strength_score,
            entropy_bits=entropy,
            crack_time_seconds=crack_times['offline_slow'],  # Usar escenario promedio
            vulnerabilities=vulnerabilities,
            recommendations=[],
            complexity_level="",
            character_analysis=char_analysis,
            pattern_analysis=pattern_analysis,
            breach_status=is_breached,
            creation_time=datetime.now().isoformat()
        )
        
        # Generar recomendaciones
        metrics.recommendations = self.generate_detailed_recommendations(password, metrics)
        
        # Clasificar nivel de seguridad
        metrics.complexity_level = self.classify_security_level(metrics)
        
        return metrics
    
    def _calculate_strength_score(self, password: str, char_analysis: Dict, 
                                 pattern_analysis: Dict, entropy: float, is_breached: bool) -> float:
        """Cálculo avanzado de puntuación de fortaleza"""
        score = 0.0
        
        # Puntuación por longitud (30 puntos máximo)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 20
        elif length >= 6:
            score += 10
        else:
            score += length * 1.5
        
        # Puntuación por diversidad de caracteres (25 puntos máximo)
        char_types = sum([
            char_analysis['lowercase'] > 0,
            char_analysis['uppercase'] > 0,
            char_analysis['digits'] > 0,
            char_analysis['special'] > 0
        ])
        score += char_types * 6.25
        
        # Bonificación por caracteres extendidos
        if char_analysis['extended'] > 0:
            score += 5
        
        # Puntuación por entropía (25 puntos máximo)
        entropy_score = min(entropy / 80 * 25, 25)
        score += entropy_score
        
        # Puntuación por uniqueness de caracteres (10 puntos máximo)
        if length > 0:
            uniqueness_ratio = char_analysis['unique_chars'] / length
            score += uniqueness_ratio * 10
        
        # Penalizaciones por patrones (hasta -50 puntos)
        pattern_penalties = 0
        if pattern_analysis.get('repeated_chars'): pattern_penalties += 10
        if pattern_analysis.get('sequential_nums'): pattern_penalties += 15
        if pattern_analysis.get('sequential_letters'): pattern_penalties += 15
        if pattern_analysis.get('keyboard_pattern'): pattern_penalties += 20
        if pattern_analysis.get('common_words'): pattern_penalties += 25
        if pattern_analysis.get('only_numbers') or pattern_analysis.get('only_letters'): pattern_penalties += 20
        if pattern_analysis.get('date_pattern'): pattern_penalties += 10
        
        score -= min(pattern_penalties, 50)
        
        # Penalización crítica por breach
        if is_breached:
            score = min(score * 0.1, 15)  # Máximo 15 puntos si está comprometida
        
        # Bonificaciones adicionales
        if length >= 20: score += 5  # Longitud excepcional
        if char_analysis['unique_chars'] == length: score += 5  # Todos caracteres únicos
        if not any(pattern_analysis.values()): score += 10  # Sin patrones detectados
        
        return max(0, min(100, score))
    
    def _detect_vulnerabilities(self, password: str, char_analysis: Dict, 
                              pattern_analysis: Dict, is_breached: bool, breach_count: int) -> List[str]:
        """Detección comprehensiva de vulnerabilidades"""
        vulnerabilities = []
        
        # Vulnerabilidades críticas
        if is_breached:
            if breach_count > 1000000:
                vulnerabilities.append(f"🚨 CRÍTICO: Contraseña comprometida en {breach_count:,} brechas de datos")
            elif breach_count > 10000:
                vulnerabilities.append(f"🚨 ALTO RIESGO: Contraseña vista {breach_count:,} veces en brechas")
            else:
                vulnerabilities.append(f"⚠️ Contraseña comprometida ({breach_count:,} veces en brechas)")
        
        # Vulnerabilidades de longitud
        if len(password) < 6:
            vulnerabilities.append("🔴 CRÍTICO: Longitud extremadamente insuficiente")
        elif len(password) < 8:
            vulnerabilities.append("🟠 ALTO: Longitud insuficiente para seguridad básica")
        elif len(password) < 12:
            vulnerabilities.append("🟡 MEDIO: Longitud por debajo del estándar recomendado")
        
        # Vulnerabilidades de composición
        missing_types = []
        if char_analysis['lowercase'] == 0: missing_types.append("minúsculas")
        if char_analysis['uppercase'] == 0: missing_types.append("mayúsculas")
        if char_analysis['digits'] == 0: missing_types.append("números")
        if char_analysis['special'] == 0: missing_types.append("símbolos")
        
        if len(missing_types) >= 3:
            vulnerabilities.append(f"🔴 CRÍTICO: Falta diversidad - sin {', '.join(missing_types)}")
        elif len(missing_types) >= 2:
            vulnerabilities.append(f"🟠 ALTO: Composición limitada - sin {', '.join(missing_types)}")
        elif len(missing_types) == 1:
            vulnerabilities.append(f"🟡 MEDIO: Falta {missing_types[0]} para completar diversidad")
        
        # Vulnerabilidades por patrones
        if pattern_analysis.get('only_numbers'):
            vulnerabilities.append("🔴 CRÍTICO: Solo contiene números")
        elif pattern_analysis.get('only_letters'):
            vulnerabilities.append("🔴 CRÍTICO: Solo contiene letras")
        
        if pattern_analysis.get('repeated_chars'):
            vulnerabilities.append("🟠 Repetición excesiva de caracteres")
        
        if pattern_analysis.get('sequential_nums'):
            vulnerabilities.append("🟠 Contiene secuencias numéricas predecibles")
        
        if pattern_analysis.get('sequential_letters'):
            vulnerabilities.append("🟠 Contiene secuencias alfabéticas predecibles")
        
        if pattern_analysis.get('keyboard_pattern'):
            vulnerabilities.append("🟠 Contiene patrones de teclado fáciles de adivinar")
        
        if pattern_analysis.get('common_words'):
            vulnerabilities.append("🔴 ALTO: Contiene palabras comunes del diccionario")
        
        if pattern_analysis.get('date_pattern'):
            vulnerabilities.append("🟡 Contiene fechas o años")
        
        # Vulnerabilidades por baja diversidad
        if len(password) > 0:
            uniqueness_ratio = char_analysis['unique_chars'] / len(password)
            if uniqueness_ratio < 0.5:
                vulnerabilities.append("🟠 Baja diversidad de caracteres únicos")
        
        # Verificar si está en lista de contraseñas comunes
        if password.lower() in self.common_passwords:
            vulnerabilities.append("🚨 CRÍTICO: Contraseña extremadamente común")
        
        return vulnerabilities

class UltraSecurePasswordGenerator:
    """Generador ultra-seguro de contraseñas con múltiples algoritmos"""
    
    def __init__(self):
        self.charset_lower = string.ascii_lowercase
        self.charset_upper = string.ascii_uppercase
        self.charset_digits = string.digits
        self.charset_symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?~`'
        self.ambiguous_chars = 'il1Lo0O'
        self.generation_history = []
        self.db_manager = DatabaseManager()
    
    def generate_cryptographically_secure(self, config: GenerationConfig) -> str:
        """Genera contraseña criptográficamente segura"""
        charset = self._build_charset(config)
        
        if not charset:
            raise ValueError("No hay caracteres disponibles para generar contraseña")
        
        # Asegurar que se incluya al menos un carácter de cada tipo requerido
        password_chars = []
        
        if config.require_all_types:
            if config.use_lowercase and self.charset_lower:
                password_chars.append(secrets.choice([c for c in self.charset_lower if c not in config.exclude_chars]))
            if config.use_uppercase and self.charset_upper:
                password_chars.append(secrets.choice([c for c in self.charset_upper if c not in config.exclude_chars]))
            if config.use_digits and self.charset_digits:
                password_chars.append(secrets.choice([c for c in self.charset_digits if c not in config.exclude_chars]))
            if config.use_symbols and (self.charset_symbols or config.custom_symbols):
                symbol_set = config.custom_symbols if config.custom_symbols else self.charset_symbols
                password_chars.append(secrets.choice([c for c in symbol_set if c not in config.exclude_chars]))
        
        # Completar hasta la longitud deseada
        remaining_length = config.length - len(password_chars)
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(charset))
        
        # Mezclar aleatoriamente usando SystemRandom
        secrets.SystemRandom().shuffle(password_chars)
        
        generated_password = ''.join(password_chars)
        
        # Guardar en historial
        self.generation_history.append({
            'password': generated_password,
            'timestamp': datetime.now().isoformat(),
            'config': asdict(config),
            'type': 'cryptographic'
        })
        
        return generated_password
    
    def generate_advanced_passphrase(self, words: int = 6, wordlist_type: str = 'common',
                                   separator: str = '-', capitalize_ratio: float = 0.3,
                                   number_ratio: float = 0.4, symbol_ratio: float = 0.2) -> str:
        """Genera frase de contraseña avanzada con múltiples opciones"""
        if wordlist_type not in WORDLISTS:
            wordlist_type = 'common'
        
        word_list = WORDLISTS[wordlist_type].copy()
        selected_words = []
        
        for _ in range(words):
            word = secrets.choice(word_list)
            
            # Aplicar capitalización aleatoria
            if secrets.SystemRandom().random() < capitalize_ratio:
                word = word.capitalize()
            
            # Añadir números ocasionalmente
            if secrets.SystemRandom().random() < number_ratio:
                number = secrets.randbelow(100)
                if secrets.randbelow(2):
                    word = f"{word}{number}"
                else:
                    word = f"{number}{word}"
            
            # Añadir símbolos ocasionalmente
            if secrets.SystemRandom().random() < symbol_ratio:
                symbol = secrets.choice('!@#$%^&*')
                word = f"{word}{symbol}"
            
            selected_words.append(word)
        
        passphrase = separator.join(selected_words)
        
        # Guardar en historial
        self.generation_history.append({
            'password': passphrase,
            'timestamp': datetime.now().isoformat(),
            'config': {
                'words': words, 'wordlist_type': wordlist_type, 
                'separator': separator, 'capitalize_ratio': capitalize_ratio
            },
            'type': 'passphrase'
        })
        
        return passphrase
    
    def generate_pronounceable(self, length: int = 16, complexity_level: str = 'medium') -> str:
        """Genera contraseña pronunciable usando patrones de consonantes y vocales"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        
        complexity_settings = {
            'low': {'caps_ratio': 0.1, 'num_ratio': 0.1, 'symbol_ratio': 0.05},
            'medium': {'caps_ratio': 0.2, 'num_ratio': 0.2, 'symbol_ratio': 0.1},
            'high': {'caps_ratio': 0.3, 'num_ratio': 0.3, 'symbol_ratio': 0.2}
        }
        
        settings = complexity_settings.get(complexity_level, complexity_settings['medium'])
        password_chars = []
        
        # Generar patrón consonante-vocal
        for i in range(length):
            if i % 2 == 0:
                char = secrets.choice(consonants)
            else:
                char = secrets.choice(vowels)
            
            # Aplicar mayúsculas
            if secrets.SystemRandom().random() < settings['caps_ratio']:
                char = char.upper()
            
            password_chars.append(char)
        
        # Reemplazar algunos caracteres con números
        num_replacements = int(length * settings['num_ratio'])
        for _ in range(num_replacements):
            pos = secrets.randbelow(length)
            password_chars[pos] = str(secrets.randbelow(10))
        
        # Reemplazar algunos caracteres con símbolos
        symbol_replacements = int(length * settings['symbol_ratio'])
        for _ in range(symbol_replacements):
            pos = secrets.randbelow(length)
            password_chars[pos] = secrets.choice('!@#$%^&*')
        
        generated_password = ''.join(password_chars)
        
        # Guardar en historial
        self.generation_history.append({
            'password': generated_password,
            'timestamp': datetime.now().isoformat(),
            'config': {'length': length, 'complexity_level': complexity_level},
            'type': 'pronounceable'
        })
        
        return generated_password
    
    def generate_pattern_based(self, pattern: str) -> str:
        """Genera contraseña basada en un patrón específico"""
        pattern_map = {
            'C': self.charset_upper,     # Consonante mayúscula
            'c': 'bcdfghjklmnpqrstvwxyz', # Consonante minúscula
            'V': 'AEIOU',                # Vocal mayúscula
            'v': 'aeiou',                # Vocal minúscula
            'L': self.charset_upper,     # Letra mayúscula
            'l': self.charset_lower,     # Letra minúscula
            'd': self.charset_digits,    # Dígito
            's': self.charset_symbols,   # Símbolo
            'x': self.charset_lower + self.charset_upper + self.charset_digits,  # Cualquier alfanumérico
            'X': self.charset_lower + self.charset_upper + self.charset_digits + self.charset_symbols  # Cualquier carácter
        }
        
        password_chars = []
        for char in pattern:
            if char in pattern_map:
                password_chars.append(secrets.choice(pattern_map[char]))
            else:
                password_chars.append(char)  # Carácter literal
        
        generated_password = ''.join(password_chars)
        
        # Guardar en historial
        self.generation_history.append({
            'password': generated_password,
            'timestamp': datetime.now().isoformat(),
            'config': {'pattern': pattern},
            'type': 'pattern_based'
        })
        
        return generated_password
    
    def _build_charset(self, config: GenerationConfig) -> str:
        """Construye el conjunto de caracteres según la configuración"""
        charset = ""
        
        if config.use_lowercase:
            chars = self.charset_lower
            if config.avoid_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            charset += chars
        
        if config.use_uppercase:
            chars = self.charset_upper
            if config.avoid_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            charset += chars
        
        if config.use_digits:
            chars = self.charset_digits
            if config.avoid_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            charset += chars
        
        if config.use_symbols:
            if config.custom_symbols:
                charset += config.custom_symbols
            else:
                charset += self.charset_symbols
        
        # Excluir caracteres específicos
        if config.exclude_chars:
            charset = ''.join(c for c in charset if c not in config.exclude_chars)
        
        return charset
    
    def generate_multiple_secure(self, count: int, config: GenerationConfig) -> List[str]:
        """Genera múltiples contraseñas seguras"""
        passwords = []
        for _ in range(count):
            password = self.generate_cryptographically_secure(config)
            passwords.append(password)
        return passwords
    
    def export_history(self, filename: str = None, format_type: str = 'json') -> bool:
        """Exporta historial de generación en diferentes formatos"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = DATA_DIR / f"password_history_{timestamp}.{format_type}"
        
        try:
            if format_type == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.generation_history, f, indent=2, ensure_ascii=False)
            elif format_type == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    for entry in self.generation_history:
                        f.write(f"{entry['timestamp']}: {entry['password']} ({entry['type']})\n")
            elif format_type == 'csv':
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Password', 'Type', 'Config'])
                    for entry in self.generation_history:
                        writer.writerow([entry['timestamp'], entry['password'], 
                                       entry['type'], json.dumps(entry['config'])])
            return True
        except Exception as e:
            console.print(f"[red]Error exportando historial: {e}[/red]")
            return False

class AdvancedPasswordManagerUI:
    """Interfaz de usuario avanzada con Rich"""
    
    def __init__(self):
        self.ai_analyzer = AdvancedPasswordSecurityAI()
        self.generator = UltraSecurePasswordGenerator()
        self.console = Console()
        self.config = self._load_config()
        self.session_stats = {'analyzed': 0, 'generated': 0, 'start_time': datetime.now()}
    
    def _load_config(self) -> Dict:
        """Carga configuración del sistema"""
        config_file = DATA_DIR / 'config.json'
        default_config = {
            'default_length': 16,
            'avoid_ambiguous': True,
            'passphrase_words': 6,
            'passphrase_separator': '-',
            'theme': 'cyan',
            'auto_analysis': True,
            'save_history': True,
            'breach_check_timeout': 5,
            'wordlist_type': 'common',
            'generation_config': {
                'length': 16,
                'use_uppercase': True,
                'use_lowercase': True,
                'use_digits': True,
                'use_symbols': True,
                'avoid_ambiguous': True,
                'custom_symbols': '',
                'exclude_chars': '',
                'require_all_types': True
            }
        }
        
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except Exception:
                pass
        
        return default_config
    
    def _save_config(self) -> bool:
        """Guarda configuración del sistema"""
        try:
            config_file = DATA_DIR / 'config.json'
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    def show_animated_header(self):
        """Muestra header animado con información del sistema"""
        header_text = Text()
        header_text.append(TITLE, style=f"bold {self.config['theme']}")
        header_text.append("\n🔐 GOLIAT SISTEMA AVANZADO DE GESTIÓN DE CONTRASEÑAS AI v1.0.0 🔐", style=f"bold {self.config['theme']}")
        header_text.append("\n🚀 Desarrollado por: github.com/nytrek", style="dim")
        header_text.append(f"\n📊 Sesión actual: {self.session_stats['analyzed']} analizadas | {self.session_stats['generated']} generadas", style="dim")
        
        header_panel = Panel(
            Align.center(header_text),
            box=box.DOUBLE,
            border_style=self.config['theme'],
            padding=(1, 2)
        )
        
        self.console.print()
        self.console.print(header_panel)
        self.console.print()
    
    def show_enhanced_menu(self):
        """Muestra menú principal mejorado"""
        menu_items = [
            ("1", "🔍 Análisis de Seguridad Individual", "Analiza la fortaleza de una contraseña"),
            ("2", "🎲 Generador Ultra-Seguro", "Genera contraseñas criptográficamente seguras"),
            ("3", "📊 Análisis Masivo", "Analiza múltiples contraseñas simultáneamente"),
            ("4", "🔄 Generación Masiva", "Genera múltiples contraseñas seguras"),
            ("5", "📝 Generador de Frases", "Crea frases de contraseña memorables"),
            ("6", "⚖️ Comparador Avanzado", "Compara fortaleza entre contraseñas"),
            ("7", "🗂️ Gestión de Historial", "Exportar y gestionar contraseñas generadas"),
            ("8", "⚙️ Configuración Avanzada", "Personalizar comportamiento del sistema"),
            ("9", "🎯 Generador por Patrones", "Genera contraseñas siguiendo patrones específicos"),
            ("A", "🌐 Verificación de Brechas", "Verifica si contraseñas fueron comprometidas"),
            ("B", "📈 Dashboard y Estadísticas", "Ver estadísticas de uso y tendencias"),
            ("C", "🔊 Generador Pronunciable", "Genera contraseñas fáciles de pronunciar"),
            ("H", "❓ Ayuda y Documentación", "Guía de uso y mejores prácticas"),
            ("0", "🚪 Salir", "Cerrar el sistema")
        ]
        
        # Crear tabla del menú
        menu_table = Table(
            show_header=True, 
            header_style=f"bold {self.config['theme']}",
            box=box.ROUNDED, 
            border_style=self.config['theme'],
            title=f"[bold {self.config['theme']}]🏠 MENÚ PRINCIPAL[/bold {self.config['theme']}]"
        )
        menu_table.add_column("Opción", style=self.config['theme'], width=8, justify="center")
        menu_table.add_column("Función", style="white", width=30)
        menu_table.add_column("Descripción", style="dim", width=35)
        
        for option, function, description in menu_items:
            menu_table.add_row(f"[{option}]", function, description)
        
        self.console.print(menu_table)
    
    def format_time_duration_advanced(self, seconds: float) -> str:
        """Formatea duración de tiempo de manera avanzada"""
        if seconds < 0.001:
            return "Instantáneo ⚡"
        elif seconds < 1:
            return f"{seconds*1000:.1f} milisegundos ⚡"
        elif seconds < 60:
            return f"{seconds:.1f} segundos ⏱️"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutos ⏲️"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} horas 🕐"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} días 📅"
        elif seconds < 31536000 * 1000:
            return f"{seconds/31536000:.1f} años 🗓️"
        elif seconds < 31536000 * 1000000:
            return f"{seconds/(31536000*1000):.1f} miles de años 🕰️"
        elif seconds < 31536000 * 1000000000:
            return f"{seconds/(31536000*1000000):.1f} millones de años 🌍"
        else:
            return "Más tiempo que la edad del universo 🌌"
    
    def display_comprehensive_analysis(self, password: str, metrics: PasswordMetrics):
        """Muestra análisis comprehensivo con visualizaciones avanzadas"""
        
        # Panel principal de métricas
        metrics_table = Table(
            title="📊 Análisis Detallado de Seguridad", 
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        metrics_table.add_column("Métrica", style="cyan", width=25)
        metrics_table.add_column("Valor", style="white", width=30)
        metrics_table.add_column("Estado", width=15, justify="center")
        
        # Obtener configuración de nivel de seguridad
        level_config = SECURITY_LEVELS.get(metrics.complexity_level, SECURITY_LEVELS['VERY_WEAK'])
        level_color = level_config['color']
        level_emoji = level_config['emoji']
        
        # Agregar filas de métricas
        metrics_table.add_row(
            "🔢 Longitud",
            f"{len(password)} caracteres",
            "✅" if len(password) >= 12 else "❌"
        )
        
        metrics_table.add_row(
            "💪 Puntuación de Fortaleza",
            f"{metrics.strength_score:.1f}/100 puntos",
            f"[{level_color}]{level_emoji} {metrics.complexity_level}[/{level_color}]"
        )
        
        metrics_table.add_row(
            "🧮 Entropía Criptográfica",
            f"{metrics.entropy_bits:.1f} bits",
            "✅" if metrics.entropy_bits >= 50 else "❌"
        )
        
        # Mostrar múltiples escenarios de tiempo de crackeo
        crack_times = self.ai_analyzer.estimate_crack_time_advanced(password, metrics.entropy_bits)
        metrics_table.add_row(
            "⏱️ Tiempo Crackeo (Offline)",
            self.format_time_duration_advanced(crack_times['offline_slow']),
            "✅" if crack_times['offline_slow'] > 86400 else "❌"
        )
        
        # Estado de breach
        if metrics.breach_status:
            metrics_table.add_row(
                "🚨 Estado de Brechas",
                "COMPROMETIDA",
                "🚨"
            )
        else:
            metrics_table.add_row(
                "🛡️ Estado de Brechas",
                "Segura",
                "✅"
            )
        
        self.console.print(metrics_table)
        
        # Análisis de composición de caracteres
        char_table = Table(
            title="🔤 Análisis de Composición",
            box=box.SIMPLE,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        char_table.add_column("Tipo", style="cyan")
        char_table.add_column("Cantidad", justify="center")
        char_table.add_column("Porcentaje", justify="center")
        char_table.add_column("Estado", justify="center")
        
        total_chars = len(password)
        char_analysis = metrics.character_analysis
        
        char_types = [
            ("🔤 Minúsculas", char_analysis.get('lowercase', 0)),
            ("🔠 Mayúsculas", char_analysis.get('uppercase', 0)),
            ("🔢 Números", char_analysis.get('digits', 0)),
            ("⚡ Símbolos", char_analysis.get('special', 0)),
            ("🌟 Únicos", char_analysis.get('unique_chars', 0)),
            ("🔄 Repetidos", char_analysis.get('repeated_chars', 0))
        ]
        
        for char_type, count in char_types:
            percentage = (count / total_chars * 100) if total_chars > 0 else 0
            status = "✅" if count > 0 else "❌"
            if char_type == "🔄 Repetidos":
                status = "✅" if count == 0 else "⚠️"
            
            char_table.add_row(
                char_type,
                str(count),
                f"{percentage:.1f}%",
                status
            )
        
        self.console.print(char_table)
        
        # Tabla de tiempos de crackeo por escenario
        crack_table = Table(
            title="⏰ Tiempos de Crackeo por Escenario",
            box=box.SIMPLE,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        crack_table.add_column("Escenario de Ataque", style="cyan")
        crack_table.add_column("Velocidad", style="yellow")
        crack_table.add_column("Tiempo Estimado", style="white")
        crack_table.add_column("Nivel de Riesgo", justify="center")
        
        crack_scenarios = [
            ("🌐 Online con Throttling", "10/seg", crack_times['online_throttled'], "🟢 Bajo"),
            ("🌐 Online sin Throttling", "1K/seg", crack_times['online_unthrottled'], "🟡 Medio"),
            ("💻 Offline CPU", "100K/seg", crack_times['offline_slow'], "🟠 Alto"),
            ("🎮 Offline GPU", "100M/seg", crack_times['offline_fast'], "🔴 Muy Alto"),
            ("🏭 Offline Masivo", "100B/seg", crack_times['offline_massive'], "🚨 Crítico")
        ]
        
        for scenario, speed, time_val, risk in crack_scenarios:
            crack_table.add_row(
                scenario,
                speed,
                self.format_time_duration_advanced(time_val),
                risk
            )
        
        self.console.print(crack_table)
        
        # Panel de vulnerabilidades
        if metrics.vulnerabilities:
            vuln_text = "\n".join(f"• {vuln}" for vuln in metrics.vulnerabilities)
            vuln_panel = Panel(
                vuln_text,
                title="[red]🚨 Vulnerabilidades Detectadas[/red]",
                border_style="red",
                expand=False
            )
            self.console.print(vuln_panel)
        
        # Panel de recomendaciones
        if metrics.recommendations:
            rec_text = "\n".join(f"• {rec}" for rec in metrics.recommendations)
            rec_panel = Panel(
                rec_text,
                title="[yellow]💡 Recomendaciones de Seguridad[/yellow]",
                border_style="yellow",
                expand=False
            )
            self.console.print(rec_panel)
        
        # Barra de progreso de fortaleza visual
        progress_bar = "█" * int(metrics.strength_score / 5) + "░" * (20 - int(metrics.strength_score / 5))
        progress_text = f"Fortaleza: [{level_color}]{progress_bar}[/{level_color}] {metrics.strength_score:.1f}%"
        self.console.print(f"\n{progress_text}")
    
    def analyze_single_password_enhanced(self):
        """Análisis mejorado de contraseña individual"""
        self.console.print(f"\n[bold {self.config['theme']}]🔍 ANÁLISIS AVANZADO DE CONTRASEÑA[/bold {self.config['theme']}]\n")
        
        password = Prompt.ask("🔐 Ingrese la contraseña a analizar", password=True)
        
        if not password:
            self.console.print("[red]❌ Error: Contraseña vacía[/red]")
            return
        
        # Mostrar análisis en tiempo real con progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task1 = progress.add_task("🧮 Calculando entropía criptográfica...", total=100)
            progress.update(task1, advance=25)
            time.sleep(0.3)
            
            task2 = progress.add_task("🔍 Detectando patrones vulnerables...", total=100)
            progress.update(task1, advance=25)
            progress.update(task2, advance=50)
            time.sleep(0.4)
            
            task3 = progress.add_task("🌐 Verificando brechas de datos...", total=100)
            progress.update(task1, advance=25)
            progress.update(task2, advance=50)
            progress.update(task3, advance=75)
            time.sleep(0.5)
            
            progress.update(task1, completed=100)
            progress.update(task2, completed=100)
            progress.update(task3, completed=100)
            
            # Realizar análisis real
            metrics = self.ai_analyzer.analyze_password_comprehensive(password)
        
        self.session_stats['analyzed'] += 1
        
        # Mostrar resultados
        self.display_comprehensive_analysis(password, metrics)
        
        # Guardar en base de datos si está habilitado
        if self.config.get('save_history', True):
            self.ai_analyzer.db_manager.save_password_analysis(password, metrics, 'manual_analysis')
    
    def generate_ultra_secure_password(self):
        """Generación de contraseña ultra-segura con opciones avanzadas"""
        self.console.print(f"\n[bold {self.config['theme']}]🎲 GENERADOR ULTRA-SEGURO[/bold {self.config['theme']}]\n")
        
        # Configuración interactiva
        config = GenerationConfig()
        
        config.length = IntPrompt.ask("🔢 Longitud de la contraseña", default=self.config['default_length'], show_default=True)
        config.use_uppercase = Confirm.ask("🔠 ¿Incluir mayúsculas?", default=True)
        config.use_lowercase = Confirm.ask("🔤 ¿Incluir minúsculas?", default=True)
        config.use_digits = Confirm.ask("🔢 ¿Incluir números?", default=True)
        config.use_symbols = Confirm.ask("⚡ ¿Incluir símbolos especiales?", default=True)
        config.avoid_ambiguous = Confirm.ask("👁️ ¿Evitar caracteres ambiguos (0, O, l, 1)?", default=self.config['avoid_ambiguous'])
        
        # Opciones avanzadas
        if Confirm.ask("⚙️ ¿Configurar opciones avanzadas?", default=False):
            config.custom_symbols = Prompt.ask("⚡ Símbolos personalizados (vacío para usar predeterminados)", default="")
            config.exclude_chars = Prompt.ask("🚫 Caracteres a excluir", default="")
            config.require_all_types = Confirm.ask("✅ ¿Requerir al menos un carácter de cada tipo?", default=True)
        
        # Generar contraseña
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🎲 Generando contraseña ultra-segura...", total=None)
            time.sleep(0.4)
            
            try:
                password = self.generator.generate_cryptographically_secure(config)
                progress.update(task, description="✅ Contraseña generada exitosamente")
            except ValueError as e:
                self.console.print(f"[red]❌ Error en configuración: {e}[/red]")
                return
        
        self.session_stats['generated'] += 1
        
        # Mostrar contraseña generada
        password_panel = Panel(
            f"[bold green]{password}[/bold green]",
            title="[bold]🎯 Contraseña Ultra-Segura Generada[/bold]",
            border_style="green",
            expand=False
        )
        self.console.print(password_panel)
        
        # Mostrar configuración utilizada
        config_table = Table(title="⚙️ Configuración Utilizada", box=box.SIMPLE)
        config_table.add_column("Parámetro", style="cyan")
        config_table.add_column("Valor", style="white")
        
        config_items = [
            ("Longitud", f"{config.length} caracteres"),
            ("Mayúsculas", "✅" if config.use_uppercase else "❌"),
            ("Minúsculas", "✅" if config.use_lowercase else "❌"),
            ("Números", "✅" if config.use_digits else "❌"),
            ("Símbolos", "✅" if config.use_symbols else "❌"),
            ("Evitar ambiguos", "✅" if config.avoid_ambiguous else "❌"),
            ("Requiere todos los tipos", "✅" if config.require_all_types else "❌")
        ]
        
        for param, value in config_items:
            config_table.add_row(param, value)
        
        self.console.print(config_table)
        
        # Análisis automático si está habilitado
        if self.config.get('auto_analysis', True) and Confirm.ask("🔍 ¿Realizar análisis de seguridad automático?", default=True):
            self.console.print(f"\n[bold {self.config['theme']}]📊 Análisis Automático de la Contraseña Generada[/bold {self.config['theme']}]")
            metrics = self.ai_analyzer.analyze_password_comprehensive(password)
            self.display_comprehensive_analysis(password, metrics)
    
    def analyze_multiple_passwords(self):
        """Análisis masivo de múltiples contraseñas"""
        self.console.print(f"\n[bold {self.config['theme']}]📊 ANÁLISIS MASIVO DE CONTRASEÑAS[/bold {self.config['theme']}]\n")
        
        passwords = []
        self.console.print("🔐 Ingrese las contraseñas a analizar (presione Enter sin texto para finalizar):")
        
        counter = 1
        while True:
            password = Prompt.ask(f"Contraseña {counter} (o Enter para finalizar)", 
                                password=True, default="")
            if not password:
                break
            passwords.append(password)
            counter += 1
            
            if len(passwords) >= 20:  # Límite de seguridad
                if not Confirm.ask(f"Ya tiene {len(passwords)} contraseñas. ¿Continuar agregando?", default=False):
                    break
        
        if not passwords:
            self.console.print("[yellow]⚠️ No se ingresaron contraseñas[/yellow]")
            return
        
        self.console.print(f"\n🚀 Analizando {len(passwords)} contraseñas...")
        
        # Análisis con barra de progreso
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("🔍 Analizando contraseñas...", total=len(passwords))
            
            for i, password in enumerate(passwords):
                metrics = self.ai_analyzer.analyze_password_comprehensive(password)
                results.append((f"Contraseña {i+1}", password, metrics))
                progress.advance(task)
                time.sleep(0.05)  # Pequeña pausa para visualización
        
        self.session_stats['analyzed'] += len(passwords)
        
        # Mostrar resultados resumidos
        results_table = Table(
            title="📋 Resumen de Análisis Masivo", 
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        results_table.add_column("ID", style="cyan", width=12)
        results_table.add_column("Fortaleza", width=12, justify="center")
        results_table.add_column("Puntuación", width=10, justify="center")
        results_table.add_column("Entropía", width=10, justify="center")
        results_table.add_column("Longitud", width=8, justify="center")
        results_table.add_column("Brechas", width=8, justify="center")
        results_table.add_column("Estado", width=8, justify="center")
        
        # Estadísticas generales
        total_score = sum(r[2].strength_score for r in results)
        avg_score = total_score / len(results)
        breached_count = sum(1 for r in results if r[2].breach_status)
        weak_count = sum(1 for r in results if r[2].strength_score < 50)
        
        for name, password, metrics in results:
            level_config = SECURITY_LEVELS.get(metrics.complexity_level, SECURITY_LEVELS['VERY_WEAK'])
            level_color = level_config['color']
            level_emoji = level_config['emoji']
            
            results_table.add_row(
                name,
                f"[{level_color}]{metrics.complexity_level}[/{level_color}]",
                f"{metrics.strength_score:.1f}",
                f"{metrics.entropy_bits:.1f}",
                str(len(password)),
                "🚨" if metrics.breach_status else "✅",
                f"[{level_color}]{level_emoji}[/{level_color}]"
            )
        
        self.console.print(results_table)
        
        # Estadísticas del análisis
        stats_panel = Panel(
            f"""📊 **Estadísticas del Análisis**
            
🔢 **Total analizado:** {len(passwords)} contraseñas
📈 **Puntuación promedio:** {avg_score:.1f}/100
🚨 **Comprometidas:** {breached_count} ({breached_count/len(results)*100:.1f}%)
⚠️ **Débiles (< 50 pts):** {weak_count} ({weak_count/len(results)*100:.1f}%)
✅ **Fuertes (≥ 70 pts):** {len(results) - weak_count - breached_count} ({(len(results) - weak_count - breached_count)/len(results)*100:.1f}%)""",
            title="[bold cyan]📊 Resumen Estadístico[/bold cyan]",
            border_style="cyan"
        )
        self.console.print(stats_panel)
        
        # Opción de análisis detallado individual
        if Confirm.ask("🔍 ¿Ver análisis detallado de alguna contraseña específica?", default=False):
            while True:
                try:
                    choice = IntPrompt.ask(f"Seleccione contraseña (1-{len(results)}) o 0 para salir", show_choices=False)
                    if choice == 0:
                        break
                    if 1 <= choice <= len(results):
                        selected = results[choice - 1]
                        self.console.print(f"\n[bold {self.config['theme']}]📋 Análisis Detallado - {selected[0]}[/bold {self.config['theme']}]")
                        self.display_comprehensive_analysis(selected[1], selected[2])
                        if not Confirm.ask("¿Ver otra contraseña?", default=False):
                            break
                    else:
                        self.console.print("[red]❌ Número inválido[/red]")
                except Exception:
                    self.console.print("[red]❌ Entrada inválida[/red]")
    
    def generate_multiple_passwords(self):
        """Generación masiva de contraseñas"""
        self.console.print(f"\n[bold {self.config['theme']}]🔄 GENERACIÓN MASIVA DE CONTRASEÑAS[/bold {self.config['theme']}]\n")
        
        count = IntPrompt.ask("🔢 ¿Cuántas contraseñas generar?", default=5, show_default=True)
        if count > 50:
            if not Confirm.ask(f"⚠️ Generar {count} contraseñas puede tomar tiempo. ¿Continuar?", default=False):
                return
        
        # Configuración
        config = GenerationConfig()
        config.length = IntPrompt.ask("🔢 Longitud de cada contraseña", default=self.config['default_length'])
        config.avoid_ambiguous = Confirm.ask("👁️ ¿Evitar caracteres ambiguos?", default=self.config['avoid_ambiguous'])
        
        # Generar contraseñas
        passwords = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("🎲 Generando contraseñas ultra-seguras...", total=count)
            
            for i in range(count):
                password = self.generator.generate_cryptographically_secure(config)
                passwords.append(password)
                progress.advance(task)
                time.sleep(0.02)  # Pequeña pausa para visualización
        
        self.session_stats['generated'] += count
        
        # Mostrar contraseñas generadas con análisis rápido
        passwords_table = Table(
            title=f"🎯 {count} Contraseñas Ultra-Seguras Generadas", 
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        passwords_table.add_column("N°", style="cyan", width=5, justify="center")
        passwords_table.add_column("Contraseña", style="green", width=25)
        passwords_table.add_column("Fortaleza", width=12, justify="center")
        passwords_table.add_column("Entropía", width=10, justify="center")
        passwords_table.add_column("Estado", width=8, justify="center")
        
        # Análisis rápido de cada contraseña
        self.console.print("\n🔍 Realizando análisis rápido de seguridad...")
        with Progress(console=self.console) as progress:
            analysis_task = progress.add_task("Analizando...", total=count)
            
            for i, password in enumerate(passwords, 1):
                metrics = self.ai_analyzer.analyze_password_comprehensive(password)
                level_config = SECURITY_LEVELS.get(metrics.complexity_level, SECURITY_LEVELS['VERY_WEAK'])
                level_color = level_config['color']
                level_emoji = level_config['emoji']
                
                passwords_table.add_row(
                    str(i),
                    password,
                    f"[{level_color}]{metrics.complexity_level}[/{level_color}]",
                    f"{metrics.entropy_bits:.1f}",
                    f"[{level_color}]{level_emoji}[/{level_color}]"
                )
                progress.advance(analysis_task)
        
        self.console.print(passwords_table)
        
        # Opciones post-generación
        if Confirm.ask("💾 ¿Exportar contraseñas a archivo?", default=False):
            self.export_generated_passwords(passwords)
    
    def generate_advanced_passphrase(self):
        """Generador avanzado de frases de contraseña"""
        self.console.print(f"\n[bold {self.config['theme']}]📝 GENERADOR AVANZADO DE FRASES[/bold {self.config['theme']}]\n")
        
        # Mostrar opciones de wordlists disponibles
        wordlist_table = Table(title="📚 Wordlists Disponibles", box=box.SIMPLE)
        wordlist_table.add_column("Tipo", style="cyan")
        wordlist_table.add_column("Descripción", style="white")
        wordlist_table.add_column("Palabras", style="yellow", justify="center")
        
        wordlist_info = [
            ("common", "Palabras comunes en inglés", len(WORDLISTS['common'])),
            ("tech", "Terminología tecnológica", len(WORDLISTS['tech'])),
            ("nature", "Elementos de la naturaleza", len(WORDLISTS['nature'])),
            ("animals", "Nombres de animales", len(WORDLISTS['animals']))
        ]
        
        for wl_type, description, count in wordlist_info:
            wordlist_table.add_row(wl_type, description, str(count))
        
        self.console.print(wordlist_table)
        
        # Configuración de la frase
        wordlist_type = Prompt.ask("📚 Tipo de wordlist", choices=list(WORDLISTS.keys()), default=self.config['wordlist_type'])
        words = IntPrompt.ask("🔢 Número de palabras", default=self.config['passphrase_words'], show_default=True)
        separator = Prompt.ask("🔗 Separador entre palabras", default=self.config['passphrase_separator'], show_default=True)
        
        # Opciones avanzadas
        if Confirm.ask("⚙️ ¿Configurar opciones avanzadas?", default=False):
            capitalize_ratio = float(Prompt.ask("🔠 Ratio de capitalización (0.0-1.0)", default="0.3"))
            number_ratio = float(Prompt.ask("🔢 Ratio de números (0.0-1.0)", default="0.4"))
            symbol_ratio = float(Prompt.ask("⚡ Ratio de símbolos (0.0-1.0)", default="0.2"))
        else:
            capitalize_ratio, number_ratio, symbol_ratio = 0.3, 0.4, 0.2
        
        # Generar frase
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("📝 Creando frase de contraseña avanzada...", total=None)
            time.sleep(0.4)
            
            passphrase = self.generator.generate_advanced_passphrase(
                words, wordlist_type, separator, capitalize_ratio, number_ratio, symbol_ratio
            )
            
            progress.update(task, description="✅ Frase generada exitosamente")
        
        self.session_stats['generated'] += 1
        
        # Mostrar frase generada
        passphrase_panel = Panel(
            f"[bold green]{passphrase}[/bold green]",
            title="[bold]📝 Frase de Contraseña Generada[/bold]",
            border_style="green",
            expand=False
        )
        self.console.print(passphrase_panel)
        
        # Información de la configuración
        config_info = f"""⚙️ **Configuración Utilizada:**
        
📚 Wordlist: {wordlist_type} ({len(WORDLISTS[wordlist_type])} palabras)
🔢 Palabras: {words}
🔗 Separador: "{separator}"
🔠 Capitalización: {capitalize_ratio*100:.0f}%
🔢 Números: {number_ratio*100:.0f}%
⚡ Símbolos: {symbol_ratio*100:.0f}%"""
        
        config_panel = Panel(
            config_info,
            title="[bold yellow]⚙️ Configuración[/bold yellow]",
            border_style="yellow"
        )
        self.console.print(config_panel)
        
        # Análisis automático
        if self.config.get('auto_analysis', True) and Confirm.ask("🔍 ¿Realizar análisis de seguridad?", default=True):
            self.console.print(f"\n[bold {self.config['theme']}]📊 Análisis de la Frase Generada[/bold {self.config['theme']}]")
            metrics = self.ai_analyzer.analyze_password_comprehensive(passphrase)
            self.display_comprehensive_analysis(passphrase, metrics)
    
    def run_application(self):
        """Ejecuta la aplicación principal"""
        try:
            self.console.print(f"[bold {self.config['theme']}]🚀 Iniciando Sistema Avanzado de Gestión de Contraseñas v1.0.0...[/bold {self.config['theme']}]")
            time.sleep(1)
            
            while True:
                self.console.clear()
                self.show_animated_header()
                self.show_enhanced_menu()
                
                valid_choices = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "H"]
                choice = Prompt.ask("\n🎯 Seleccione una opción", choices=valid_choices).upper()
                
                if choice == "0":
                    self._show_goodbye_message()
                    break
                elif choice == "1":
                    self.analyze_single_password_enhanced()
                elif choice == "2":
                    self.generate_ultra_secure_password()
                elif choice == "3":
                    self.analyze_multiple_passwords()
                elif choice == "4":
                    self.generate_multiple_passwords()
                elif choice == "5":
                    self.generate_advanced_passphrase()
                elif choice == "6":
                    self.compare_passwords_advanced()
                elif choice == "7":
                    self.manage_history_and_export()
                elif choice == "8":
                    self.advanced_configuration()
                elif choice == "9":
                    self.generate_pattern_based_password()
                elif choice == "A":
                    self.check_breach_status()
                elif choice == "B":
                    self.show_dashboard_and_statistics()
                elif choice == "C":
                    self.generate_pronounceable_password()
                elif choice == "H":
                    self.show_help_and_documentation()
                
                if choice != "0":
                    input(f"\n[dim]Presione Enter para continuar...[/dim]")
                    
        except KeyboardInterrupt:
            self.console.print(f"\n\n[red]🛑 Programa interrumpido por el usuario[/red]")
        except Exception as e:
            self.console.print(f"\n[red]💥 Error inesperado: {e}[/red]")
            if Confirm.ask("¿Mostrar información de debug?", default=False):
                import traceback
                self.console.print(f"[red]{traceback.format_exc()}[/red]")
    
    def _show_goodbye_message(self):
        """Muestra mensaje de despedida"""
        session_duration = datetime.now() - self.session_stats['start_time']
        
        goodbye_text = f"""🎯 **Sesión Completada**

⏱️ Duración: {str(session_duration).split('.')[0]}
🔍 Contraseñas analizadas: {self.session_stats['analyzed']}
🎲 Contraseñas generadas: {self.session_stats['generated']}

🔐 **Recuerde:**
• Use contraseñas únicas para cada cuenta
• Cambie contraseñas comprometidas inmediatamente
• Active autenticación de dos factores cuando sea posible
• Considere usar un gestor de contraseñas profesional

🚀 **Desarrollado por:** github.com/nytrek
💝 **Gracias por usar nuestro sistema!**"""
        
        goodbye_panel = Panel(
            goodbye_text,
            title="[bold blue]👋 ¡Hasta la próxima![/bold blue]",
            border_style="blue",
            expand=False
        )
        self.console.print(goodbye_panel)
    
    def compare_passwords_advanced(self):
        """Comparador avanzado de fortaleza entre contraseñas"""
        self.console.print(f"\n[bold {self.config['theme']}]⚖️ COMPARADOR AVANZADO DE CONTRASEÑAS[/bold {self.config['theme']}]\n")
        
        passwords = []
        self.console.print("🔐 Ingrese las contraseñas a comparar (presione Enter sin texto para finalizar):")
        
        counter = 1
        while True:
            password = Prompt.ask(f"Contraseña {counter} (o Enter para finalizar)", 
                                password=True, default="")
            if not password:
                break
            passwords.append(password)
            counter += 1
            
            if len(passwords) >= 10:  # Límite de seguridad
                if not Confirm.ask(f"Ya tiene {len(passwords)} contraseñas. ¿Continuar agregando?", default=False):
                    break
        
        if len(passwords) < 2:
            self.console.print("[yellow]⚠️ Se necesitan al menos 2 contraseñas para comparar[/yellow]")
            return
        
        self.console.print(f"\n🚀 Analizando {len(passwords)} contraseñas para comparación...")
        
        # Análisis con barra de progreso
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("🔍 Analizando y comparando contraseñas...", total=len(passwords))
            
            for i, password in enumerate(passwords):
                metrics = self.ai_analyzer.analyze_password_comprehensive(password)
                results.append((f"Contraseña {i+1}", password, metrics))
                progress.advance(task)
                time.sleep(0.05)
        
        self.session_stats['analyzed'] += len(passwords)
        
        # Crear tabla comparativa
        comparison_table = Table(
            title="📊 Comparación Avanzada de Contraseñas", 
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        comparison_table.add_column("ID", style="cyan", width=12)
        comparison_table.add_column("Fortaleza", width=15, justify="center")
        comparison_table.add_column("Puntuación", width=10, justify="center")
        comparison_table.add_column("Entropía", width=10, justify="center")
        comparison_table.add_column("Longitud", width=8, justify="center")
        comparison_table.add_column("Tiempo Crackeo", width=25)
        comparison_table.add_column("Estado Brechas", width=12, justify="center")
        
        # Ordenar resultados por fortaleza
        sorted_results = sorted(results, key=lambda x: x[2].strength_score, reverse=True)
        
        for name, password, metrics in sorted_results:
            level_config = SECURITY_LEVELS.get(metrics.complexity_level, SECURITY_LEVELS['VERY_WEAK'])
            level_color = level_config['color']
            level_emoji = level_config['emoji']
            
            comparison_table.add_row(
                name,
                f"[{level_color}]{metrics.complexity_level}[/{level_color}]",
                f"{metrics.strength_score:.1f}",
                f"{metrics.entropy_bits:.1f}",
                str(len(password)),
                self.format_time_duration_advanced(metrics.crack_time_seconds),
                "🚨" if metrics.breach_status else "✅"
            )
        
        self.console.print(comparison_table)
        
        # Mostrar ganador
        best_name, best_password, best_metrics = sorted_results[0]
        best_panel = Panel(
            f"[bold green]{best_password}[/bold green]",
            title=f"[bold]🏆 Contraseña más fuerte: {best_name} ({best_metrics.strength_score:.1f} pts)[/bold]",
            border_style="green",
            expand=False
        )
        self.console.print(best_panel)
        
        # Mostrar peor contraseña
        worst_name, worst_password, worst_metrics = sorted_results[-1]
        worst_panel = Panel(
            f"[bold red]{worst_password}[/bold red]",
            title=f"[bold]⚠️ Contraseña más débil: {worst_name} ({worst_metrics.strength_score:.1f} pts)[/bold]",
            border_style="red",
            expand=False
        )
        self.console.print(worst_panel)
        
        # Recomendaciones de mejora
        if worst_metrics.strength_score < 70:
            self.console.print("\n[bold yellow]💡 Recomendaciones para mejorar la contraseña más débil:[/bold yellow]")
            for rec in worst_metrics.recommendations[:3]:
                self.console.print(f"• {rec}")
    
    def manage_history_and_export(self):
        """Gestión de historial y exportación"""
        self.console.print(f"\n[bold {self.config['theme']}]🗂️ GESTIÓN DE HISTORIAL Y EXPORTACIÓN[/bold {self.config['theme']}]\n")
        
        # Verificar si hay historial
        if not self.generator.generation_history:
            self.console.print("[yellow]⚠️ No hay contraseñas en el historial de generación[/yellow]")
            return
        
        # Mostrar historial reciente
        history_table = Table(
            title="📝 Historial Reciente de Contraseñas Generadas", 
            box=box.SIMPLE,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        history_table.add_column("N°", style="cyan", width=5, justify="center")
        history_table.add_column("Tipo", style="yellow", width=15)
        history_table.add_column("Contraseña", style="green")
        history_table.add_column("Generada en", style="dim", width=20)
        
        for i, entry in enumerate(self.generator.generation_history[-10:], 1):
            pwd = entry['password']
            display_pwd = f"{pwd[:5]}...{pwd[-3:]}" if len(pwd) > 10 else pwd
            history_table.add_row(
                str(i),
                entry['type'],
                display_pwd,
                datetime.fromisoformat(entry['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            )
        
        self.console.print(history_table)
        
        # Opciones de gestión
        self.console.print("\n[bold]⚙️ Opciones de Gestión:[/bold]")
        options_table = Table(show_header=False, box=box.SIMPLE)
        options_table.add_column("Opción", style="cyan", width=10)
        options_table.add_column("Descripción", style="white")
        
        options_table.add_row("1", "Ver detalles completos")
        options_table.add_row("2", "Exportar historial completo")
        options_table.add_row("3", "Limpiar historial")
        options_table.add_row("0", "Volver al menú principal")
        
        self.console.print(options_table)
        
        choice = Prompt.ask("Seleccione una opción", choices=["0", "1", "2", "3"])
        
        if choice == "1":
            self.show_full_history_details()
        elif choice == "2":
            self.export_generated_passwords()
        elif choice == "3":
            if Confirm.ask("⚠️ ¿Está seguro de limpiar todo el historial?", default=False):
                self.generator.generation_history = []
                self.console.print("[green]✅ Historial limpiado correctamente[/green]")
    
    def show_full_history_details(self):
        """Muestra detalles completos del historial"""
        if not self.generator.generation_history:
            self.console.print("[yellow]⚠️ No hay contraseñas en el historial[/yellow]")
            return
        
        # Mostrar tabla completa con análisis básico
        full_history_table = Table(
            title="📋 Historial Completo de Contraseñas Generadas", 
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        full_history_table.add_column("ID", style="cyan", width=5, justify="center")
        full_history_table.add_column("Tipo", width=15)
        full_history_table.add_column("Contraseña", style="green", width=25)
        full_history_table.add_column("Fortaleza", width=15, justify="center")
        full_history_table.add_column("Entropía", width=10, justify="center")
        full_history_table.add_column("Longitud", width=8, justify="center")
        full_history_table.add_column("Generada en", style="dim", width=20)
        
        # Análisis rápido de cada contraseña en historial
        with Progress(console=self.console) as progress:
            task = progress.add_task("Analizando contraseñas...", total=len(self.generator.generation_history))
            
            for i, entry in enumerate(self.generator.generation_history, 1):
                password = entry['password']
                metrics = self.ai_analyzer.analyze_password_comprehensive(password)
                level_config = SECURITY_LEVELS.get(metrics.complexity_level, SECURITY_LEVELS['VERY_WEAK'])
                level_color = level_config['color']
                
                full_history_table.add_row(
                    str(i),
                    entry['type'],
                    password,
                    f"[{level_color}]{metrics.complexity_level}[/{level_color}]",
                    f"{metrics.entropy_bits:.1f}",
                    str(len(password)),
                    datetime.fromisoformat(entry['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                )
                progress.advance(task)
        
        self.console.print(full_history_table)
        
        # Opción para ver detalles individuales
        if Confirm.ask("\n🔍 ¿Ver análisis detallado de alguna contraseña?", default=False):
            try:
                choice = IntPrompt.ask(f"Seleccione contraseña (1-{len(self.generator.generation_history)}) o 0 para salir")
                if choice == 0:
                    return
                if 1 <= choice <= len(self.generator.generation_history):
                    selected = self.generator.generation_history[choice-1]
                    self.console.print(f"\n[bold {self.config['theme']}]📋 Análisis Detallado - Contraseña #{choice}[/bold {self.config['theme']}]")
                    metrics = self.ai_analyzer.analyze_password_comprehensive(selected['password'])
                    self.display_comprehensive_analysis(selected['password'], metrics)
            except Exception:
                self.console.print("[red]❌ Selección inválida[/red]")
    
    def export_generated_passwords(self, passwords: List[str] = None):
        """Exporta contraseñas generadas a archivo"""
        if not passwords and not self.generator.generation_history:
            self.console.print("[yellow]⚠️ No hay contraseñas para exportar[/yellow]")
            return
        
        if not passwords:
            passwords = [entry['password'] for entry in self.generator.generation_history]
        
        self.console.print("\n📤 Formatos de exportación disponibles:")
        format_table = Table(show_header=False, box=box.SIMPLE)
        format_table.add_column("Opción", style="cyan", width=5)
        format_table.add_column("Formato", style="white")
        format_table.add_column("Descripción", style="dim")
        
        format_table.add_row("1", "Texto plano (.txt)", "Lista simple de contraseñas")
        format_table.add_row("2", "JSON (.json)", "Estructurado con metadatos")
        format_table.add_row("3", "CSV (.csv)", "Tabla con detalles")
        format_table.add_row("4", "HTML (.html)", "Reporte formateado")
        
        self.console.print(format_table)
        
        choice = Prompt.ask("Seleccione formato de exportación", choices=["1", "2", "3", "4"])
        formats = {"1": "txt", "2": "json", "3": "csv", "4": "html"}
        selected_format = formats[choice]
        
        # Nombre de archivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = DATA_DIR / f"passwords_export_{timestamp}.{selected_format}"
        filename = Prompt.ask("Ingrese nombre de archivo", default=str(default_filename))
        
        # Exportar
        if selected_format == "txt":
            with open(filename, "w", encoding="utf-8") as f:
                for pwd in passwords:
                    f.write(f"{pwd}\n")
        elif selected_format == "json":
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "count": len(passwords),
                "passwords": passwords,
                "system": "Password Manager AI v1.0"
            }
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
        elif selected_format == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Contraseña", "Longitud", "Fecha de Exportación"])
                for pwd in passwords:
                    writer.writerow([pwd, len(pwd), datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        elif selected_format == "html":
            self.export_to_html(passwords, filename)
        
        self.console.print(f"[green]✅ Exportación completada: {filename}[/green]")
    
    def export_to_html(self, passwords: List[str], filename: str):
        """Exporta contraseñas a un reporte HTML formateado"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Reporte de Contraseñas - Password Manager AI</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .title {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
                .subtitle {{ font-size: 16px; color: #7f8c8d; }}
                .info {{ margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #95a5a6; }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="title">Reporte de Contraseñas Generadas</div>
                <div class="subtitle">Password Manager AI v1.0</div>
            </div>
            
            <div class="info">
                <p><strong>Fecha de Exportación:</strong> {timestamp}</p>
                <p><strong>Total de Contraseñas:</strong> {len(passwords)}</p>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>N°</th>
                        <th>Contraseña</th>
                        <th>Longitud</th>
                        <th>Fortaleza Estimada</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Analizar cada contraseña para el reporte
        for i, pwd in enumerate(passwords, 1):
            metrics = self.ai_analyzer.analyze_password_comprehensive(pwd)
            html_content += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{pwd}</td>
                        <td>{len(pwd)}</td>
                        <td>{metrics.complexity_level} ({metrics.strength_score:.1f}/100)</td>
                    </tr>
            """
        
        html_content += """
                </tbody>
            </table>
            
            <div class="footer">
                <p>Reporte generado automáticamente por Password Manager AI v1.0</p>
                <p>github.com/nytrek</p>
            </div>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def advanced_configuration(self):
        """Configuración avanzada del sistema"""
        self.console.print(f"\n[bold {self.config['theme']}]⚙️ CONFIGURACIÓN AVANZADA[/bold {self.config['theme']}]\n")
        
        # Mostrar configuración actual
        config_table = Table(
            title="🔧 Configuración Actual del Sistema", 
            box=box.ROUNDED,
            show_header=True,
            header_style=f"bold {self.config['theme']}"
        )
        config_table.add_column("Parámetro", style="cyan", width=30)
        config_table.add_column("Valor Actual", style="white", width=20)
        config_table.add_column("Tipo", style="dim", width=15)
        
        config_items = [
            ("Tema de Interfaz", self.config['theme'], "str"),
            ("Longitud Predeterminada", str(self.config['default_length']), "int"),
            ("Evitar Caracteres Ambiguos", "✅" if self.config['avoid_ambiguous'] else "❌", "bool"),
            ("Análisis Automático", "✅" if self.config['auto_analysis'] else "❌", "bool"),
            ("Guardar Historial", "✅" if self.config['save_history'] else "❌", "bool"),
            ("Palabras en Frase", str(self.config['passphrase_words']), "int"),
            ("Separador de Frase", self.config['passphrase_separator'], "str"),
            ("Tipo de Wordlist", self.config['wordlist_type'], "str"),
            ("Timeout Verificación Brechas", str(self.config['breach_check_timeout']), "int")
        ]
        
        for param, value, dtype in config_items:
            config_table.add_row(param, str(value), dtype)
        
        self.console.print(config_table)
        
        # Opciones de modificación
        self.console.print("\n[bold]🔧 Opciones de Configuración:[/bold]")
        options_table = Table(show_header=False, box=box.SIMPLE)
        options_table.add_column("Opción", style="cyan", width=5)
        options_table.add_column("Parámetro", style="white")
        
        options_table.add_row("1", "Cambiar tema de interfaz")
        options_table.add_row("2", "Cambiar longitud predeterminada")
        options_table.add_row("3", "Alternar evitar caracteres ambiguos")
        options_table.add_row("4", "Alternar análisis automático")
        options_table.add_row("5", "Alternar guardar historial")
        options_table.add_row("6", "Configurar generación de frases")
        options_table.add_row("7", "Restaurar valores predeterminados")
        options_table.add_row("0", "Volver al menú principal")
        
        self.console.print(options_table)
        
        choice = Prompt.ask("Seleccione una opción", choices=["0", "1", "2", "3", "4", "5", "6", "7"])
        
        if choice == "1":
            themes = ["cyan", "blue", "green", "yellow", "magenta", "red", "white"]
            new_theme = Prompt.ask("Seleccione nuevo tema", choices=themes, default=self.config['theme'])
            self.config['theme'] = new_theme
            self.console.print(f"[green]✅ Tema cambiado a: {new_theme}[/green]")
        elif choice == "2":
            new_length = IntPrompt.ask("Longitud predeterminada", default=self.config['default_length'])
            if 6 <= new_length <= 50:
                self.config['default_length'] = new_length
                self.console.print(f"[green]✅ Longitud predeterminada cambiada a: {new_length}[/green]")
            else:
                self.console.print("[red]❌ Longitud inválida (6-50 caracteres)[/red]")
        elif choice == "3":
            self.config['avoid_ambiguous'] = not self.config['avoid_ambiguous']
            status = "activado" if self.config['avoid_ambiguous'] else "desactivado"
            self.console.print(f"[green]✅ Evitar caracteres ambiguos: {status}[/green]")
        elif choice == "4":
            self.config['auto_analysis'] = not self.config['auto_analysis']
            status = "activado" if self.config['auto_analysis'] else "desactivado"
            self.console.print(f"[green]✅ Análisis automático: {status}[/green]")
        elif choice == "5":
            self.config['save_history'] = not self.config['save_history']
            status = "activado" if self.config['save_history'] else "desactivado"
            self.console.print(f"[green]✅ Guardar historial: {status}[/green]")
        elif choice == "6":
            self.config['passphrase_words'] = IntPrompt.ask(
                "Número de palabras en frase", default=self.config['passphrase_words'])
            self.config['passphrase_separator'] = Prompt.ask(
                "Separador entre palabras", default=self.config['passphrase_separator'])
            self.config['wordlist_type'] = Prompt.ask(
                "Tipo de wordlist", choices=list(WORDLISTS.keys()), default=self.config['wordlist_type'])
            self.console.print("[green]✅ Configuración de frases actualizada[/green]")
        elif choice == "7":
            if Confirm.ask("⚠️ ¿Restaurar configuración predeterminada?", default=False):
                self.config = self._load_config()  # Recarga configuración por defecto
                self.console.print("[green]✅ Configuración restaurada a valores predeterminados[/green]")
        
        # Guardar cambios
        if choice != "0":
            self._save_config()
    
    def generate_pattern_based_password(self):
        """Generador de contraseñas por patrones"""
        self.console.print(f"\n[bold {self.config['theme']}]🎯 GENERADOR POR PATRONES[/bold {self.config['theme']}]\n")
        
        # Explicación de patrones
        pattern_help = """
        [bold]🎓 Guía de Patrones:[/bold]
        Use los siguientes caracteres para definir su patrón:
          C = Consonante mayúscula (B, D, F, etc.)
          c = Consonante minúscula (b, d, f, etc.)
          V = Vocal mayúscula (A, E, I, etc.)
          v = Vocal minúscula (a, e, i, etc.)
          L = Letra mayúscula
          l = Letra minúscula
          d = Dígito (0-9)
          s = Símbolo especial (!@#$%^&*)
          x = Cualquier carácter alfanumérico
          X = Cualquier carácter (incluye símbolos)
          
        Ejemplos:
          "Cvcvds" -> H3ll0!
          "lll-ddd-lll" -> abc-123-def
          "XsddX" -> K@12j
        """
        help_panel = Panel(pattern_help.strip(), title="[bold]📚 Ayuda de Patrones[/bold]", border_style="yellow")
        self.console.print(help_panel)
        
        pattern = Prompt.ask("⌨️ Ingrese su patrón (ej: 'Cvcds')")
        
        if not pattern:
            self.console.print("[red]❌ Patrón vacío[/red]")
            return
        
        # Generar contraseña
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🎯 Generando contraseña por patrón...", total=None)
            time.sleep(0.5)
            
            try:
                password = self.generator.generate_pattern_based(pattern)
                progress.update(task, description="✅ Contraseña generada exitosamente")
            except (KeyError, ValueError) as e:
                self.console.print(f"[red]❌ Error en patrón: {e}[/red]")
                return
        
        self.session_stats['generated'] += 1
        
        # Mostrar contraseña generada
        password_panel = Panel(
            f"[bold green]{password}[/bold green]",
            title="[bold]🔑 Contraseña Generada por Patrón[/bold]",
            border_style="green",
            expand=False
        )
        self.console.print(password_panel)
        
        # Mostrar análisis automático
        if self.config.get('auto_analysis', True) and Confirm.ask("🔍 ¿Realizar análisis de seguridad?", default=True):
            self.console.print(f"\n[bold {self.config['theme']}]📊 Análisis de la Contraseña Generada[/bold {self.config['theme']}]")
            metrics = self.ai_analyzer.analyze_password_comprehensive(password)
            self.display_comprehensive_analysis(password, metrics)
    
    def check_breach_status(self):
        """Verificación de brechas de seguridad"""
        self.console.print(f"\n[bold {self.config['theme']}]🌐 VERIFICACIÓN DE BRECHAS DE SEGURIDAD[/bold {self.config['theme']}]\n")
        
        password = Prompt.ask("🔐 Ingrese la contraseña a verificar", password=True)
        
        if not password:
            self.console.print("[red]❌ Contraseña vacía[/red]")
            return
        
        # Verificar brecha
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("🌐 Consultando bases de datos de brechas...", total=100)
            
            # Simular progreso
            for i in range(5):
                progress.update(task, advance=20)
                time.sleep(0.3)
            
            # Realizar verificación
            is_breached, breach_count = self.ai_analyzer.check_password_breach(
                password, self.config['breach_check_timeout'])
            
            progress.update(task, completed=100)
        
        # Mostrar resultados
        if is_breached:
            breach_panel = Panel(
                f"🚨 [bold red]¡CONTRASEÑA COMPROMETIDA![/bold red]\n\n"
                f"Esta contraseña ha aparecido en [bold]{breach_count}[/bold] brechas de datos conocidas\n\n"
                f"[yellow]Recomendación:[/yellow] Cambie esta contraseña inmediatamente en todos los servicios donde la use",
                title="[red]ALERTA DE SEGURIDAD[/red]",
                border_style="red",
                expand=False
            )
            self.console.print(breach_panel)
        else:
            safe_panel = Panel(
                "🛡️ [bold green]Contraseña segura[/bold green]\n\n"
                "No se encontró en bases de datos de brechas conocidas",
                title="✅ RESULTADO DE VERIFICACIÓN",
                border_style="green",
                expand=False
            )
            self.console.print(safe_panel)
        
        self.session_stats['analyzed'] += 1
    
    def show_dashboard_and_statistics(self):
        """Dashboard y estadísticas de uso"""
        self.console.print(f"\n[bold {self.config['theme']}]📈 DASHBOARD Y ESTADÍSTICAS[/bold {self.config['theme']}]\n")
        
        # Estadísticas de sesión
        session_duration = datetime.now() - self.session_stats['start_time']
        
        session_stats = Table(
            title="📊 Estadísticas de Sesión", 
            box=box.SIMPLE,
            show_header=False
        )
        session_stats.add_column("Métrica", style="cyan", width=30)
        session_stats.add_column("Valor", style="white")
        
        session_stats.add_row("Duración de sesión", str(session_duration).split('.')[0])
        session_stats.add_row("Contraseñas analizadas", str(self.session_stats['analyzed']))
        session_stats.add_row("Contraseñas generadas", str(self.session_stats['generated']))
        
        self.console.print(session_stats)
        self.console.print()
        
        # Estadísticas históricas desde la base de datos
        db_stats = self.ai_analyzer.db_manager.get_statistics()
        
        if db_stats['total_analyzed'] > 0:
            history_stats = Table(
                title="📋 Estadísticas Históricas", 
                box=box.SIMPLE,
                show_header=False
            )
            history_stats.add_column("Métrica", style="cyan", width=30)
            history_stats.add_column("Valor", style="white")
            
            history_stats.add_row("Total analizado", str(db_stats['total_analyzed']))
            history_stats.add_row("Fortaleza promedio", f"{db_stats['average_strength']:.1f}/100")
            history_stats.add_row("Entropía promedio", f"{db_stats['average_entropy']:.1f} bits")
            
            # Distribución de fortaleza
            dist = db_stats['strength_distribution']
            strength_dist = "\n".join(
                f"{level}: {count} ({count/db_stats['total_analyzed']*100:.1f}%)"
                for level, count in dist.items()
            )
            history_stats.add_row("Distribución de fortaleza", strength_dist)
            
            self.console.print(history_stats)
        else:
            self.console.print("[yellow]⚠️ No hay datos históricos disponibles[/yellow]")
        
        # Gráfico de distribución de fortaleza
        if db_stats['total_analyzed'] > 0:
            self.console.print("\n[bold]📊 Distribución de Fortaleza:[/bold]")
            dist = db_stats['strength_distribution']
            levels = ['EXCELLENT', 'STRONG', 'MODERATE', 'WEAK', 'VERY_WEAK']
            level_colors = {
                'EXCELLENT': 'bright_green',
                'STRONG': 'green',
                'MODERATE': 'yellow',
                'WEAK': 'orange1',
                'VERY_WEAK': 'red'
            }
            
            for level in levels:
                count = dist.get(level, 0)
                if count > 0:
                    percentage = count / db_stats['total_analyzed'] * 100
                    bar = "█" * int(percentage / 5)  # Cada 5% = un bloque
                    self.console.print(
                        f"[{level_colors.get(level, 'white')}]{level:<10}[/{level_colors.get(level, 'white')}] "
                        f"{bar} {percentage:.1f}% ({count} contraseñas)"
                    )
    
    def generate_pronounceable_password(self):
        """Generador de contraseñas pronunciables"""
        self.console.print(f"\n[bold {self.config['theme']}]🔊 GENERADOR DE CONTRASEÑAS PRONUNCIABLES[/bold {self.config['theme']}]\n")
        
        # Configuración
        length = IntPrompt.ask("🔢 Longitud de la contraseña", default=self.config['default_length'], show_default=True)
        complexity = Prompt.ask(
            "⚙️ Nivel de complejidad", 
            choices=["bajo", "medio", "alto"], 
            default="medio"
        )
        
        # Generar contraseña
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("🔊 Creando contraseña pronunciable...", total=None)
            time.sleep(0.5)
            
            password = self.generator.generate_pronounceable(length, complexity)
            progress.update(task, description="✅ Contraseña generada exitosamente")
        
        self.session_stats['generated'] += 1
        
        # Mostrar contraseña generada
        password_panel = Panel(
            f"[bold green]{password}[/bold green]",
            title="[bold]🔊 Contraseña Pronunciable Generada[/bold]",
            border_style="green",
            expand=False
        )
        self.console.print(password_panel)
        
        # Información de pronunciación
        pronunciation = " ".join([password[i:i+3] for i in range(0, len(password), 3)])
        self.console.print(f"\n📢 Pronunciación sugerida: [bold]{pronunciation}[/bold]")
        
        # Mostrar análisis automático
        if self.config.get('auto_analysis', True) and Confirm.ask("🔍 ¿Realizar análisis de seguridad?", default=True):
            self.console.print(f"\n[bold {self.config['theme']}]📊 Análisis de la Contraseña Generada[/bold {self.config['theme']}]")
            metrics = self.ai_analyzer.analyze_password_comprehensive(password)
            self.display_comprehensive_analysis(password, metrics)
    
    def show_help_and_documentation(self):
        """Muestra ayuda y documentación del sistema"""
        self.console.print(f"\n[bold {self.config['theme']}]❓ AYUDA Y DOCUMENTACIÓN[/bold {self.config['theme']}]\n")
        
        help_content = """
        [bold underline]🔐 SISTEMA AVANZADO DE GESTIÓN DE CONTRASEÑAS AI v1.0.0[/bold underline]
        
        [bold]🎯 Objetivo:[/bold] Proporcionar herramientas avanzadas para generar, analizar y gestionar contraseñas seguras
        
        [bold]📌 Características Principales:[/bold]
          • Análisis de seguridad avanzado con IA
          • Generación de contraseñas ultra-seguras
          • Detección de contraseñas comprometidas en brechas
          • Herramientas para gestión masiva de contraseñas
          • Estadísticas detalladas y dashboard
          • Personalización avanzada del sistema
        
        [bold]🔍 Análisis Individual:[/bold]
          Analiza en profundidad una contraseña, mostrando:
          - Puntuación de fortaleza (0-100)
          - Entropía criptográfica (bits)
          - Tiempo estimado de crackeo
          - Vulnerabilidades detectadas
          - Recomendaciones de mejora
        
        [bold]🎲 Generador Ultra-Seguro:[/bold]
          Genera contraseñas criptográficamente seguras con:
          - Personalización completa de caracteres
          - Exclusión de caracteres ambiguos
          - Requerimiento de múltiples tipos de caracteres
          - Símbolos personalizados
        
        [bold]📊 Análisis Masivo:[/bold]
          Analiza múltiples contraseñas simultáneamente mostrando:
          - Comparación de fortalezas
          - Detección de contraseñas comprometidas
          - Estadísticas generales del conjunto
        
        [bold]🔄 Generación Masiva:[/bold]
          Genera múltiples contraseñas seguras en un solo paso
          - Configuración uniforme para todas
          - Exportación a múltiples formatos
        
        [bold]📝 Generador de Frases:[/bold]
          Crea frases de contraseña memorables usando:
          - Diferentes wordlists (común, técnica, naturaleza)
          - Capitalización aleatoria
          - Inserción de números y símbolos
        
        [bold]⚙️ Configuración Avanzada:[/bold]
          Personaliza el comportamiento del sistema:
          - Tema de interfaz
          - Longitud predeterminada
          - Comportamiento de análisis automático
          - Gestión de historial
          - Parámetros de generación
        
        [bold]📈 Mejores Prácticas:[/bold]
          1. Use contraseñas únicas para cada servicio
          2. Longitud mínima de 12 caracteres
          3. Combine mayúsculas, minúsculas, números y símbolos
          4. Evite información personal y patrones comunes
          5. Use autenticación de dos factores (2FA)
          6. Cambie contraseñas comprometidas inmediatamente
          7. Considere usar un gestor de contraseñas profesional
        
        [bold]🚀 Desarrollado por:[/bold] github.com/nytrek
        [bold]📄 Licencia:[/bold] MIT
        """
        
        help_panel = Panel(
            help_content.strip(),
            title="[bold]📚 Documentación del Sistema[/bold]",
            border_style=self.config['theme'],
            expand=False
        )
        self.console.print(help_panel)
        
        # Ejemplos de uso
        examples = """
        [bold]💡 Ejemplos de Uso:[/bold]
        
        1. Analizar una contraseña existente:
           • Seleccione opción 1 en el menú principal
           • Ingrese la contraseña a analizar
        
        2. Generar una contraseña ultra-segura:
           • Seleccione opción 2 en el menú principal
           • Configure los parámetros de generación
           • Revise el análisis automático de seguridad
        
        3. Verificar si una contraseña fue comprometida:
           • Seleccione opción A en el menú principal
           • Ingrese la contraseña a verificar
        
        4. Generar una frase de contraseña:
           • Seleccione opción 5 en el menú principal
           • Elija el tipo de palabras y separador
        """
        
        examples_panel = Panel(
            examples.strip(),
            title="[bold]💡 Ejemplos Prácticos[/bold]",
            border_style="yellow",
            expand=False
        )
        self.console.print(examples_panel)

# Ejecutar la aplicación
if __name__ == "__main__":
    manager = AdvancedPasswordManagerUI()

    manager.run_application()
