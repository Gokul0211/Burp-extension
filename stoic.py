#!/usr/bin/env python3
"""
Advanced Endpoint Scanner - Enterprise Edition
Extracts API endpoints, routes, and service configurations from JavaScript applications
with recursive lazy-loading discovery, AST analysis, and intelligent confidence tiering.

Key Features:
1. Recursive feedback loop for lazy-loaded chunks
2. Multi-pass analysis with increasing route depth
3. AST-based extraction for computed properties and templates
4. Intelligent Confidence Scoring (Tiering) logic
5. Library/Vendor fingerprinting for noise reduction
"""
import requests
from bs4 import BeautifulSoup
import re
import json
import urllib.parse
import time
import sys
import os
import hashlib
from collections import defaultdict, deque
import argparse
import logging

# Try importing esprima for AST analysis
try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try importing Pandas for Excel export
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ==============================================================================
# CONFIGURATION
# ==============================================================================
IGNORED_DOMAINS = [
    "google", "facebook", "twitter", "linkedin", "sentry", "datadog", "newrelic", 
    "segment", "hotjar", "optimizely", "intercom", "cloudflare", "cloudfront", 
    "jsdelivr", "cdnjs", "unpkg", "microsoftonline", "azure", "chinacloudapi", 
    "opencagedata", "tinymce", "w3.org", "gstatic", "bootstrapcdn", "fontawesome",
    "vimeo.com", "vzaar.com",
    # React error decoder and docs pages (appear in vendor bundles via RPC_RETURN_CONCAT)
    "reactjs.org", "react.dev",
    # XML schema namespaces (appear in xlsx/SheetJS bundles)
    "openxmlformats.org", "schemas.openxmlformats.org",
    "schemas.microsoft.com", "schema.org",
    # Mozilla developer docs (appear in polyfill/compat bundles)
    "mozilla.org", "mdn.",
]

NOISE_KEYWORDS = [
    'helvetica', 'arial', 'courier', 'times', 'verdana',
    '__html2canvas__', '_pseudoelement_',
    'klmnopqrstuvwxyz',
    'expressionchangedafterithasbeenchecked',
    # Specific garbage from real scans
    'caused by:', 'valid digit info', 'ngdirectivedef', 
    'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef',
    'node_modules', 'sourcemap',
    # Template literals that leaked
    'animation-timing-function', 'sheet ${', 'sheet,', 'sheet[',
    # Error messages
    ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup',
    # Common JS syntax
    'on_property', 'template.html'
]

BASE_URL_BLACKLIST = [
    r'w3\.org', r'xmlns', r'2000/svg', r'1999/xhtml',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

STRICT_BLOCKS = [
    'webpack', '__webpack', 'sourcemap',
    # Angular framework internals
    'ngdirectivedef', 'ngpipedef', 'ngmoduledef',
    'nginjectabledef', 'nginjectordef',
    # Template files
    'template.html',
    # Excel internal structures
    '/xl/worksheets/',
    # Error/constant fragments
    'on_property',
    # Excel/OOXML internal constants (from xlsx/SheetJS vendor bundle)
    'SummaryInformation', 'DocumentSummaryInformation',
    'EncryptionInfo', 'EncryptedPackage', '!DataSpaces',
    # OOXML XML tag fragment paths (appear as string literals in SheetJS)
    'a:styleSheet', 'a:sheets', 'a:dimension', 'a:cellXfs', 'a:numFmts', 'a:cellStyleXfs',
    # Node crypto polyfill package names (from browserify/webpack bundles)
    'elliptic', 'browserify-sign', 'create-ecdh', 'browserify-cipher',
    'public-encrypt', 'diffie-hellman', 'create-hmac',
    'pbkdf2', 'randombytes', 'randomfill',
]

FALSE_POSITIVE_PATTERNS = [
    r'^https?:$',
    r'w3\.org',
    r'xmlns',
    r'/1999/xhtml',
    r'/2000/svg',
    r'ExpressionChangedAfterItHasBeenCheckedError',
    r'klmnopqrstuvwxyz',
]

API_INDICATORS = [
    r'/api/', r'/v\d+/', r'/odata/', r'/rest/', r'/graphql', 
    r'\.json$', r'/endpoint', r'/service', r'/rpc',
    r'/fetch', r'/get', r'/post', r'/update', r'/delete',
    r'/pdf', r'/export', r'/data',
    r'/admin', r'/user', r'/auth',
    r'/dashboard', r'/master', r'/project',
    r'^#/', r'^/#/'
]

HASH_ROUTE_PATTERNS = [
    r'["\'](/[^/]+/#/[^"\']+)["\']',
    r'["\'](#/[^"\']+)["\']',
    r'["\'](/#/[^"\']+)["\']',
]

# MOFIDIED: Removed 'runtime' as per instructions
LOW_VALUE_JS = [
    'polyfill', 'polyfills', 'core-js', 'zone.js', 
    'es2015', 'es5', 'babel', 'tslib'
]

NOISE_PATTERNS = [
    r'^http:-',
    r'^http:/[^/]',
    r'^https?:px',
    r'^https?://[^/]*$',
    r'\$\{',
    r'\{\{',
    r'undefined',
    r'\bnull\b',
    r'/xl/worksheets/',
    r'\s',
    r'\(\$',
    r'\?\$',
    r'caused by:',
    r'valid digit info',
    r'animation-timing-function',
    r'/[a-z]$',
    r'(?:^|/)(?:px|ms|em|rem|vh|vw)$',
    r'\?id=\$\{',
    r':\$\{',
    r'\(!',
    r'\[\w+\]$', 
    r'/sheet\s',
    r'sheet\$',
    r'sheet,',
    r'sheet\[',
    r'sheet\(',
    r'//\s*$',
    r':\\n',
    r'\}\\n',
    # Hex/unicode escape sequences in path (binary constants from xlsx/crypto bundles)
    r'\\x[0-9a-fA-F]{2}',
    r'\\u[0-9a-fA-F]{4}',
    # Developer local absolute paths embedded in source maps
    r'/(?:Users|home|Documents|Desktop|Downloads|AppData)/[A-Za-z]',
    r'^[A-Z]:[/\\]',
]

# ⭐ IMPROVEMENT 1: Common endpoints for forced probing
COMMON_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/admin",
    "/api/internal",
    "/api/private",
    "/api/debug",
    "/admin",
    "/internal",
    "/private",
    "/graphql",
    "/rest",
    "/v1",
    "/v2",
    "/v3",
    "/odata",
    "/rpc",
    "/service",
    "/services",
    "/endpoint",
    "/endpoints",
]

# ==============================================================================
# CLASS: LIBRARY FINGERPRINT (Identify Vendor Code)
# ==============================================================================
class LibraryFingerprint:
    """Identifies source files that belong to third-party libraries."""
    
    VENDOR_INDICATORS = [
        'node_modules', 'webpack', 'chunk', 'vendor', 'bundle', 'min.js',
        'react', 'angular', 'vue', 'axios', 'jquery', 'lodash', 'moment',
        'xlsx', 'sheetjs', 'chart.js', 'd3', 'fontawesome'
    ]

    @staticmethod
    def is_vendor(file_path):
        if not file_path:
            return False
        
        path_lower = file_path.lower()
        
        # Check for known vendor paths/names
        for ind in LibraryFingerprint.VENDOR_INDICATORS:
            if ind in path_lower:
                return True
        
        # Check for hashes often found in vendor chunks (e.g., 2.7b57cd2c.chunk.js)
        # 8+ hex chars usually indicate a built artifact
        if re.search(r'[a-f0-9]{8,}', path_lower):
            # But exclude typical main application files if clearly named
            if 'main.' in path_lower or 'app.' in path_lower or 'index.' in path_lower:
                return False
            return True
            
        return False

# ==============================================================================
# CLASS: ENDPOINT CLASSIFIER (Confidence Tiering)
# ==============================================================================
class EndpointClassifier:
    """
    Assigns confidence scores and tags to endpoints instead of hard filtering.
    """
    BLOCKED_DOMAINS = [
        'schemas.openxmlformats.org', 'reactjs.org', 'w3.org', 
        'schemas.microsoft.com', 'mozilla.org', 'purl.org', 
        'openxmlformats.org'
    ]
    
    POLYFILL_NAMES = [
        'browserify-sign', 'elliptic', 'create-ecdh', 'browserify-cipher',
        'public-encrypt', 'diffie-hellman', 'create-hash', 'create-hmac',
        'pbkdf2', 'randombytes', 'randomfill', 'bn.js'
    ]

    @staticmethod
    def is_hard_garbage(endpoint):
        """
        Returns True ONLY for guaranteed non-API artifacts (XML, Binary).
        These are safe to drop completely.
        """
        if not endpoint:
            return True
        s = str(endpoint)
        # Hard block XML/HTML tags and Binary control chars
        if '<' in s or '>' in s or '\x05' in s or '!DataSpaces' in s:
            return True
        return False

    @staticmethod
    def score_and_classify(endpoint, extraction_type, is_vendor):
        """
        Returns (score, category, tags) tuple.
        Score range: 0 to 100+
        """
        score = 50  # Base score
        tags = []
        category = "UNKNOWN"
        s = str(endpoint).lower()

        # --- 1. Extraction Source Scoring ---
        if extraction_type in ['STATIC_CODE', 'RPC_CALL', 'AST_HTTP_CALL', 'AST_TEMPLATE_LITERAL']:
            score += 30
            tags.append("explicit_code_reference")
        elif extraction_type == 'ARRAY_HARVEST':
            score -= 10
            tags.append("implicit_string_harvest")

        # --- 2. Vendor Context ---
        if is_vendor:
            score -= 20
            tags.append("vendor_source")
            if extraction_type == 'ARRAY_HARVEST':
                score -= 20 # Heavy penalty for scraping strings from vendor bundles

        # --- 3. Content Heuristics ---
        
        # Single Word Check (No slashes)
        if '/' not in s and '.' not in s:
            # Dangerous if from vendor
            if is_vendor or extraction_type == 'ARRAY_HARVEST':
                score -= 30
                tags.append("single_word_artifact")
            else:
                # Could be "GetUser", "Login" from app code - keep but penalize slightly
                score -= 5
        
        # External Domains
        for domain in EndpointClassifier.BLOCKED_DOMAINS:
            if domain in s:
                score = 10 # Keep low but alive
                category = "EXTERNAL_REFERENCE"
                tags.append("external_schema")
                return score, category, tags

        # Polyfills / Internals
        if any(poly in s for poly in EndpointClassifier.POLYFILL_NAMES):
            score = 0
            category = "LIBRARY_ARTIFACT"
            tags.append("polyfill_noise")
            return score, category, tags

        # Excel/Office specific
        if 'a:dimension' in s or 'a:sheets' in s:
            score = 0
            category = "LIBRARY_ARTIFACT"
            tags.append("xml_artifact")
            return score, category, tags

        # Strong API Signals
        if '/api/' in s or '/v1/' in s or '/v2/' in s:
            score += 20
            tags.append("api_pattern")
        
        if any(verb in endpoint for verb in ['Get', 'Post', 'Put', 'Delete', 'Create', 'Update']):
            score += 15
            tags.append("naming_convention")

        # Determine Final Category based on Score
        if score >= 70:
            category = "HIGH_CONFIDENCE"
        elif score >= 40:
            category = "MEDIUM_CONFIDENCE"
        elif score >= 10:
            category = "LOW_CONFIDENCE"
        else:
            category = "NOISE_CANDIDATE"

        # ⭐ IMPROVEMENT 2: Drop score=0 endpoints completely
        final_score = max(0, score)
        if final_score == 0:
            return None  # Signal to caller to skip this endpoint entirely
        
        return final_score, category, tags

# ==============================================================================
# 🚀 LEGENDARY FEATURE 1: GRAPHQL INTROSPECTION ENGINE
# ==============================================================================
class GraphQLIntrospector:
    """
    Automatically discovers and introspects GraphQL endpoints.
    Extracts complete schema: queries, mutations, types, fields.
    """
    
    def __init__(self, session):
        self.session = session
        self.graphql_endpoints = []
        self.schemas = {}
        
        # Standard GraphQL introspection query
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              description
              type { ...TypeRef }
            }
            type { ...TypeRef }
          }
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        """
    
    def scan(self, discovered_endpoints):
        """Scan all discovered endpoints for GraphQL"""
        print(f"\n[GRAPHQL] Scanning for GraphQL endpoints...")
        
        graphql_candidates = []
        
        # Find potential GraphQL endpoints
        for endpoint_data in discovered_endpoints:
            endpoint = endpoint_data.get('endpoint', '')
            if self._looks_like_graphql(endpoint):
                graphql_candidates.append(endpoint)
        
        print(f"  Found {len(graphql_candidates)} potential GraphQL endpoints")
        
        # Introspect each candidate
        for endpoint in graphql_candidates:
            self._introspect_endpoint(endpoint)
        
        return self.schemas
    
    def _looks_like_graphql(self, url):
        """Check if URL looks like a GraphQL endpoint"""
        graphql_patterns = [
            '/graphql', '/gql', '/api/graphql', '/v1/graphql',
            '/query', '/api/query', '/graphql/v1'
        ]
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in graphql_patterns)
    
    def _introspect_endpoint(self, endpoint):
        """Send introspection query to endpoint"""
        print(f"  [→] Introspecting: {endpoint}")
        
        try:
            response = self.session.post(
                endpoint,
                json={'query': self.introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and '__schema' in data['data']:
                    schema = data['data']['__schema']
                    self._parse_schema(endpoint, schema)
                    print(f"  [✓] Successfully introspected!")
                    return True
            
        except Exception as e:
            pass
        
        return False
    
    def _parse_schema(self, endpoint, schema):
        """Parse GraphQL schema and extract all operations"""
        operations = {
            'queries': [],
            'mutations': [],
            'subscriptions': [],
            'types': []
        }
        
        # Extract all types
        for type_def in schema.get('types', []):
            if type_def['name'].startswith('__'):
                continue  # Skip introspection types
            
            type_name = type_def['name']
            type_kind = type_def['kind']
            
            if type_kind == 'OBJECT':
                fields = type_def.get('fields', [])
                
                # Check if this is Query type
                if schema.get('queryType', {}).get('name') == type_name:
                    for field in fields:
                        operations['queries'].append({
                            'name': field['name'],
                            'description': field.get('description', ''),
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })
                
                # Check if this is Mutation type
                elif schema.get('mutationType', {}).get('name') == type_name:
                    for field in fields:
                        operations['mutations'].append({
                            'name': field['name'],
                            'description': field.get('description', ''),
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })
                
                # Check if this is Subscription type
                elif schema.get('subscriptionType', {}).get('name') == type_name:
                    for field in fields:
                        operations['subscriptions'].append({
                            'name': field['name'],
                            'description': field.get('description', ''),
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })
                
                # Store all types
                operations['types'].append({
                    'name': type_name,
                    'kind': type_kind,
                    'fields': [f['name'] for f in fields] if fields else []
                })
        
        self.schemas[endpoint] = operations
        
        # Print summary
        print(f"    • Queries: {len(operations['queries'])}")
        print(f"    • Mutations: {len(operations['mutations'])}")
        print(f"    • Subscriptions: {len(operations['subscriptions'])}")
        print(f"    • Types: {len(operations['types'])}")

# ==============================================================================
# 🚀 LEGENDARY FEATURE 2: WEBSOCKET DISCOVERY & MESSAGE CAPTURE
# ==============================================================================
class WebSocketDiscovery:
    """
    Discovers WebSocket endpoints and captures messages.
    Intercepts ws:// and wss:// connections during dynamic phase.
    """
    
    def __init__(self):
        self.websocket_endpoints = []
        self.captured_messages = {}
    
    def discover_from_js(self, js_code, source):
        """Extract WebSocket endpoints from JavaScript code"""
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.connect\s*\(\s*[\'"`](wss?://[^\'"`]+)[\'"`]',
            r'[\'"`](wss?://[^\'"`]+)[\'"`]',
            r'socketUrl\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'wsUrl\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        found = []
        for pattern in ws_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                ws_url = match.group(1)
                if self._is_valid_websocket(ws_url):
                    found.append({
                        'endpoint': ws_url,
                        'source': source,
                        'protocol': 'wss' if ws_url.startswith('wss') else 'ws'
                    })
        
        return found
    
    def _is_valid_websocket(self, url):
        """Check if URL is a valid WebSocket endpoint"""
        if not url:
            return False
        
        url_lower = url.lower()
        
        # Must start with ws:// or wss:// or be a path
        if not (url_lower.startswith('ws://') or url_lower.startswith('wss://') or url_lower.startswith('/')):
            return False
        
        # Skip noise
        noise_patterns = ['example.com', 'localhost', '127.0.0.1', 'test.']
        if any(noise in url_lower for noise in noise_patterns):
            return False
        
        return True
    
    def intercept_playwright_websockets(self, page):
        """
        Set up WebSocket interception in Playwright page.
        Captures WebSocket connections and messages.
        """
        try:
            # Inject WebSocket interceptor into page
            page.evaluate("""
                (function() {
                    window.__ws_endpoints = [];
                    window.__ws_messages = [];
                    
                    const OriginalWebSocket = window.WebSocket;
                    
                    window.WebSocket = function(url, protocols) {
                        window.__ws_endpoints.push({
                            url: url,
                            timestamp: Date.now()
                        });
                        
                        const ws = new OriginalWebSocket(url, protocols);
                        
                        const originalSend = ws.send;
                        ws.send = function(data) {
                            window.__ws_messages.push({
                                type: 'outgoing',
                                url: url,
                                data: data.toString().substring(0, 500),
                                timestamp: Date.now()
                            });
                            return originalSend.apply(this, arguments);
                        };
                        
                        ws.addEventListener('message', function(event) {
                            window.__ws_messages.push({
                                type: 'incoming',
                                url: url,
                                data: event.data.toString().substring(0, 500),
                                timestamp: Date.now()
                            });
                        });
                        
                        return ws;
                    };
                })();
            """)
        except:
            pass
    
    def extract_captured_websockets(self, page):
        """Extract captured WebSocket data from page"""
        try:
            endpoints = page.evaluate("() => window.__ws_endpoints || []")
            messages = page.evaluate("() => window.__ws_messages || []")
            
            for endpoint in endpoints:
                if endpoint['url'] not in self.websocket_endpoints:
                    self.websocket_endpoints.append(endpoint['url'])
            
            for msg in messages:
                url = msg['url']
                if url not in self.captured_messages:
                    self.captured_messages[url] = []
                self.captured_messages[url].append(msg)
        except:
            pass

# ==============================================================================
# CLASS: ENHANCED VARIABLE RESOLVER WITH METHOD CALL SUPPORT
# ==============================================================================
class EnhancedVariableResolver:
    """Resolves variables AND method calls including framework patterns"""
    
    def __init__(self):
        self.variables = {}
        self.file_variables = {}
        self.global_scope = {}
        self.potential_bases = {}
        self.property_accesses = {}
        self.obfuscated_strings = {}
        self.methods = {}
        self.service_properties = {}
        
        # Pre-compile regex patterns for performance
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance"""
        self.pattern1 = re.compile(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern2 = re.compile(r'this\.(url|serverURL|baseURL|apiURL|apiUrl|rootUrl|baseUrl)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern3 = re.compile(r"this\.(url|serverURL|baseURL|apiURL)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\[([\"'])([a-zA-Z_$][a-zA-Z0-9_$]*)\3\]")
        self.pattern4 = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern5 = re.compile(r'\b([a-zA-Z_$][a-zA-Z0-9_$]{2,})\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern6 = re.compile(r'\b([a-z]{1,2})\s*=\s*["\']([^"\']{5,100}?)["\']')
        self.pattern7 = re.compile(r'(\w+)\s*:\s*["\']([^"\']{3,100}?)["\']')
        self.pattern8 = re.compile(r'["\']([/][^"\']{3,100}?)["\']\s*(?:,|])')
        
    def extract_all_variables(self, code, filename):
        """Extract ALL variables, methods, and service properties"""
        file_vars = {}
        
        # STEP 1: Extract method definitions FIRST
        self._extract_method_definitions(code, filename)
        
        # STEP 2: Extract obfuscated string arrays
        self._extract_obfuscated_strings(code, filename)
        
        # STEP 3: Extract service properties
        self._extract_service_properties(code, filename, file_vars)
        
        # STEP 4: Extract regular variable patterns using pre-compiled patterns
        
        # Pattern 1: var/let/const declarations
        for match in self.pattern1.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 90)
        
        # Pattern 2: this.url = ... or this.serverURL = ...
        for match in self.pattern2.finditer(code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 98)
                self._register_variable(prop, var_value, filename, file_vars, 95)
                self.property_accesses[prop] = var_value
        
        # Pattern 3: this.url = someObj.serverURL or this.url = config.url
        for match in self.pattern3.finditer(code):
            prop = match.group(1)
            source_obj = match.group(2)
            source_prop = match.group(4)
            self.property_accesses[prop] = f"{source_obj}.{source_prop}"
        
        # Pattern 4: Object property assignments (this.prop = value)
        for match in self.pattern4.finditer(code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 95)
                self._register_variable(prop, var_value, filename, file_vars, 90)
                self.property_accesses[prop] = var_value
        
        # Pattern 5: Simple assignments
        for match in self.pattern5.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if var_name not in file_vars and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 70)
        
        # Pattern 6: Minified variable assignments (single/double letter)
        for match in self.pattern6.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if self._is_url_like(var_value) and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 60)
        
        # Pattern 7: Object literal properties
        for match in self.pattern7.finditer(code):
            key = match.group(1)
            value = match.group(2)
            if self._is_url_like(value) and not self._is_noise_value(value):
                self._register_variable(key, value, filename, file_vars, 65)

        # Pattern 8: Array items that look like URLs (FIXED - using hash instead of truncation)
        for match in self.pattern8.finditer(code):
            val = match.group(1)
            if self._is_url_like(val) and not self._is_noise_value(val):
                # FIXED: Use hash to avoid key collisions
                val_hash = hashlib.md5(val.encode()).hexdigest()[:8]
                self._register_variable(f"ARRAY_ITEM_{val_hash}", val, filename, file_vars, 60)
        
        self.file_variables[filename] = file_vars
        return file_vars
    
    def _extract_method_definitions(self, code, filename):
        """Extract method definitions and their return values"""
        # Pattern 1: methodName(){return "value"} - Made more flexible to handle nested braces
        pattern1 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern1.finditer(code):
            method_name = match.group(1)
            return_value = match.group(2)
            if self._is_url_like(return_value):
                self.methods[method_name] = return_value
                self.methods[f"this.{method_name}"] = return_value
        
        # Pattern 2: methodName(){return condition ? "val1" : "val2"}
        pattern2 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return[^}]+\?[^:]+:(?:[^}]|\{[^}]*\})*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern2.finditer(code):
            method_name = match.group(1)
            # Extract all string literals from the ternary
            ternary_section = code[match.start():match.end()]
            strings = re.findall(r'["\']([^"\']+)["\']', ternary_section)
            for s in strings:
                if self._is_url_like(s):
                    self.methods[method_name] = s
                    self.methods[f"this.{method_name}"] = s
                    break
        
        # Pattern 3: methodName(){...return location.origin + "/api"}
        pattern3 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+location\.origin\s*\+\s*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern3.finditer(code):
            method_name = match.group(1)
            suffix = match.group(2)
            # Store as a pattern that needs base URL resolution
            self.methods[method_name] = f"ORIGIN{suffix}"
            self.methods[f"this.{method_name}"] = f"ORIGIN{suffix}"
        
        # Pattern 4: Environment object support - Extract common config patterns
        pattern4 = re.compile(r'(?:apiUrl|baseUrl|serverUrl|apiEndpoint)\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
            url = match.group(1)
            if self._is_url_like(url):
                # Store with a recognizable key
                self.methods['environmentApiUrl'] = url
    
    def _extract_service_properties(self, code, filename, file_vars):
        """Extract service property patterns like this.propertyName=this.methodCall()+'/path'"""
        # Pattern: this.propertyName = this.methodCall() + "/path"
        pattern = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        
        for match in pattern.finditer(code):
            property_name = match.group(1)
            method_name = match.group(2)
            path_suffix = match.group(3)
            
            # Try to resolve the method
            method_result = self._resolve_method(method_name)
            
            if method_result:
                # Combine method result with suffix
                full_endpoint = method_result + path_suffix
                
                # Register as a service property
                self.service_properties[property_name] = {
                    'endpoint': full_endpoint,
                    'method_call': f"this.{method_name}()",
                    'suffix': path_suffix,
                    'source': filename
                }
                
                # Also register as a regular variable
                self._register_variable(property_name, full_endpoint, filename, file_vars, 95)
                self._register_variable(f"this.{property_name}", full_endpoint, filename, file_vars, 98)
    
    def _resolve_method(self, method_name):
        """Resolve a method call to its return value"""
        # Check direct method name
        if method_name in self.methods:
            return self.methods[method_name]
        
        # Check with this. prefix
        if f"this.{method_name}" in self.methods:
            return self.methods[f"this.{method_name}"]
        
        # Common method names that return API base URLs
        common_methods = {
            'getRootUrl': '/api',
            'getBaseUrl': '/api',
            'getApiUrl': '/api',
            'getServerUrl': '/api',
            'getApiBaseUrl': '/api'
        }
        
        if method_name in common_methods:
            return f"ORIGIN{common_methods[method_name]}"
        
        return None
    
    def _extract_obfuscated_strings(self, code, filename):
        """Extract string arrays used in obfuscated code"""
        pattern = re.compile(r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{[^}]*const\s+\w+\s*=\s*\[([^\]]+)\]', re.DOTALL)
        
        for match in pattern.finditer(code):
            func_name = match.group(1)
            array_content = match.group(2)
            
            string_pattern = r'["\']([^"\']+)["\']'
            strings = re.findall(string_pattern, array_content)
            
            for idx, string in enumerate(strings):
                if self._is_url_like(string) and not self._is_noise_value(string):
                    key = f"{func_name}_{idx}"
                    self.obfuscated_strings[key] = string
    
    def _is_noise_value(self, value):
        """Check if value is noise"""
        v = value.lower()
        
        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return True
        
        if len(value) < 2:
            return True
        
        return False
    
    def _register_variable(self, var_name, var_value, filename, file_vars, confidence):
        """Register a variable with confidence scoring"""
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, var_value, re.IGNORECASE):
                return
        
        file_vars[var_name] = var_value
        
        if var_name not in self.variables or self.variables[var_name]['confidence'] < confidence:
            self.variables[var_name] = {
                'value': var_value,
                'source_file': filename,
                'confidence': confidence
            }
        
        if self._could_be_base_url(var_value):
            self.potential_bases[var_name] = var_value
        
        if self._is_base_url(var_value):
            self.global_scope[var_name] = var_value
    
    def _is_url_like(self, value):
        """Check if value looks like a URL or endpoint"""
        if len(value) < 2:
            return False
        return (
            value.startswith('http') or 
            value.startswith('/') or
            value.startswith('#/') or
            value.startswith('ORIGIN') or
            any(term in value.lower() for term in ['api', 'endpoint', 'service', 'rest', 'graphql', 
                                                    'fetch', 'data', 'dashboard', 'master', 'project'])
        )
    
    def _could_be_base_url(self, value):
        """Check if this could potentially be a base URL"""
        if len(value) < 3:
            return False
        
        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')):
            return False
        
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        return True
    
    def _is_base_url(self, value):
        """Check if this looks like a base URL"""
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        if len(value) < 5:
            return False
        
        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')):
            return False
        
        patterns = [
            r'^https?://[^/]+',
            r'^/',
            r'^#/',
            r'^ORIGIN',
        ]
        
        return any(re.search(p, value) for p in patterns)
    
    def resolve(self, var_name):
        """Resolve a variable name to its value"""
        if var_name in self.variables:
            return self.variables[var_name]['value']
        
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        
        if var_name in self.service_properties:
            return self.service_properties[var_name]['endpoint']
        
        return None
    
    def resolve_with_fallback(self, var_name):
        """Resolve variable with multiple fallback strategies"""
        if var_name in self.global_scope:
            return self.global_scope[var_name]
        if var_name in self.potential_bases:
            return self.potential_bases[var_name]
        if var_name in self.variables:
            return self.variables[var_name]['value']
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        if var_name in self.service_properties:
            return self.service_properties[var_name]['endpoint']
        
        if f"this.{var_name}" in self.variables:
            return self.variables[f"this.{var_name}"]['value']
        
        for prop in ['url', 'serverURL', 'baseURL', 'apiURL', 'rootUrl', 'baseUrl']:
            if var_name == prop and prop in self.property_accesses:
                return self.property_accesses[prop]
        
        return None
    
    def resolve_method_call(self, method_call_str):
        """Resolve a method call like 'this.getRootUrl()' to its return value"""
        method_call_str = method_call_str.strip()
        
        if method_call_str.endswith('()'):
            method_call_str = method_call_str[:-2]
        
        if method_call_str in self.methods:
            return self.methods[method_call_str]
        
        if method_call_str.startswith('this.'):
            method_name = method_call_str[5:]
            if method_name in self.methods:
                return self.methods[method_name]
        else:
            if f"this.{method_call_str}" in self.methods:
                return self.methods[f"this.{method_call_str}"]
        
        return None
    
    def get_all_base_urls(self):
        """Get all potential base URLs found"""
        return {**self.global_scope, **self.potential_bases, **self.property_accesses}
    
    def get_all_service_properties(self):
        """Get all service properties found"""
        return self.service_properties

# ==============================================================================
# AST UTILITIES & EXTRACTORS
# ==============================================================================

def walk(node, visitor):
    """Depth-first AST walk. Calls visitor(node) for every node."""
    if node is None:
        return
    if not hasattr(node, 'type'):
        return
    try:
        visitor(node)
    except Exception:
        pass
    for key in vars(node):
        child = getattr(node, key, None)
        if child is None:
            continue
        if isinstance(child, list):
            for item in child:
                if hasattr(item, 'type'):
                    walk(item, visitor)
        elif hasattr(child, 'type'):
            walk(child, visitor)

class AliasResolver:
    """
    EXTRACTOR 4: AliasResolver (runs FIRST — feeds scope to Extractors 1-3)
    Builds a name → resolved_string map from all assignments in the file.
    """
    MAX_DEPTH = 8

    def __init__(self, existing_resolver_bindings=None):
        self.scope = dict(existing_resolver_bindings or {})
        self._dirty = True

    def build_scope(self, ast_body):
        for _ in range(self.MAX_DEPTH):
            prev = len(self.scope)
            walk(ast_body, self._visit)
            if len(self.scope) == prev:
                break
        return self.scope

    def _visit(self, node):
        if node.type == 'VariableDeclarator' and node.init:
            name = getattr(node.id, 'name', None)
            if name:
                val = self._resolve(node.init)
                if val is not None:
                    self.scope[name] = val

        if node.type == 'AssignmentExpression' and node.operator == '=':
            lhs = node.left
            if lhs.type == 'Identifier':
                val = self._resolve(node.right)
                if val is not None:
                    self.scope[lhs.name] = val
            elif lhs.type == 'MemberExpression' and not lhs.computed:
                if hasattr(lhs.object, 'type'):
                    obj  = getattr(lhs.object,   'name', '')
                    prop = getattr(lhs.property, 'name', '')
                    if obj and prop:
                        val = self._resolve(node.right)
                        if val is not None:
                            self.scope[f'{obj}.{prop}'] = val

    def _resolve(self, node, depth=0):
        if depth > self.MAX_DEPTH:
            return None
        if node is None:
            return None
        if node.type == 'Literal':
            return str(node.value) if isinstance(node.value, (str, int, float)) else None
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._resolve(node.left,  depth+1)
            r = self._resolve(node.right, depth+1)
            if l is not None and r is not None:
                return l + r
            if l is not None:
                return l
            return None
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    v = self._resolve(node.expressions[i], depth+1)
                    parts.append(v if v is not None else '')
            return ''.join(parts)
        if node.type == 'MemberExpression' and not node.computed:
            obj  = getattr(node.object,   'name', '')
            prop = getattr(node.property, 'name', '')
            # 🔥 FINAL FIX 1.1: Try nested resolution first (e.g., API.users.delete)
            nested_key = f'{obj}.{prop}'
            if nested_key in self.scope:
                return self.scope[nested_key]
            # Fallback to object resolution
            return self.scope.get(f'{obj}.{prop}')
        # ⭐ ENHANCEMENT 2.1: Add CallExpression resolution (for method calls returning URLs)
        if node.type == 'CallExpression':
            return self._resolve_call_expression(node, depth)
        # 🔥 FINAL FIX 1.2: Add ObjectExpression resolution for nested objects
        if node.type == 'ObjectExpression':
            return self._resolve_object_expression(node, depth)
        return None
    
    # ⭐ ENHANCEMENT 2.1: New method to resolve method calls that return base URLs
    def _resolve_call_expression(self, node, depth):
        """Resolve method calls like getApiBase() or this.getRootUrl()"""
        if depth > self.MAX_DEPTH:
            return None
        
        callee = node.callee
        
        # Handle simple function calls: getApiBase()
        if callee.type == 'Identifier':
            method_name = callee.name
            # Check if we know what this method returns
            if method_name in self.scope:
                return self.scope[method_name]
        
        # Handle member expressions: this.getApiBase() or obj.getUrl()
        elif callee.type == 'MemberExpression' and not callee.computed:
            obj_name = getattr(callee.object, 'name', '')
            prop_name = getattr(callee.property, 'name', '')
            
            # Try to resolve this.methodName()
            if obj_name == 'this':
                method_key = f'this.{prop_name}'
                if method_key in self.scope:
                    return self.scope[method_key]
            
            # Try obj.method()
            key = f'{obj_name}.{prop_name}'
            if key in self.scope:
                return self.scope[key]
        
        return None
    
    # 🔥 FINAL FIX 1.3: New method to resolve nested object expressions
    def _resolve_object_expression(self, node, depth):
        """
        Resolve nested object expressions like:
        const API = { users: { delete: '/DeleteUser' } }
        """
        if depth > self.MAX_DEPTH:
            return None
        
        result = {}
        
        for prop in node.properties:
            if not hasattr(prop, 'key') or not hasattr(prop, 'value'):
                continue
            
            # Get property key
            if prop.key.type == 'Identifier':
                key = prop.key.name
            elif prop.key.type == 'Literal':
                key = str(prop.key.value)
            else:
                continue
            
            # Resolve property value
            val = self._resolve(prop.value, depth + 1)
            
            if val is not None:
                result[key] = val
        
        # Return first string value found (if any)
        for v in result.values():
            if isinstance(v, str) and len(v) > 2:
                return v
        
        return None

class ComputedPropertyExtractor:
    """
    EXTRACTOR 1: ComputedPropertyExtractor
    Finds endpoints constructed via obj[expr] syntax.
    """
    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        if node.type != 'MemberExpression':
            return
        if not node.computed:
            return

        prop = node.property

        if prop.type == 'Literal' and isinstance(prop.value, str):
            candidate = prop.value
            if self._looks_like_path(candidate):
                self._emit(candidate, 'computed_literal_key')

        elif prop.type == 'Identifier':
            resolved = self.scope.get(prop.name)
            if resolved and self._looks_like_path(resolved):
                self._emit(resolved, 'computed_scope_key', prop.name)

        elif prop.type == 'BinaryExpression' and prop.operator == '+':
            parts = self._flatten_binary(prop)
            combined = ''.join(p for p in parts if isinstance(p, str))
            if combined and self._looks_like_path(combined):
                self._emit(combined, 'computed_concat_key')

    def _flatten_binary(self, node, depth=0):
        if depth > 12:
            return []
        if node.type == 'Literal':
            return [node.value if isinstance(node.value, str) else None]
        if node.type == 'Identifier':
            return [self.scope.get(node.name)]
        if node.type == 'BinaryExpression' and node.operator == '+':
            return (self._flatten_binary(node.left, depth+1) +
                    self._flatten_binary(node.right, depth+1))
        return [None]

    def _looks_like_path(self, s):
        if not isinstance(s, str) or len(s) < 2:
            return False
        return s.startswith('/') or '/api' in s or '/v' in s

    def _emit(self, path, source, alias=None):
        self.found.append({
            'method':     'GET',
            'endpoint':   path,
            'type':       'AST_COMPUTED_KEY',
            'classification': 'BACKEND_API',
            'source':     source,
            'alias_name': alias,
            'ast_extracted': True,
            'confidence_bonus': 1,
        })

class TemplateLiteralExtractor:
    """
    EXTRACTOR 2: TemplateLiteralExtractor
    Resolves multi-line and nested template strings.
    """
    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        if node.type == 'CallExpression':
            if self._is_http_call(node):
                for arg in node.arguments:
                    if arg.type == 'TemplateLiteral':
                        result = self._resolve_template(arg)
                        if result:
                            method = self._infer_method(node)
                            self._emit(result, method, 'template_in_http_call')

        if node.type == 'VariableDeclarator' and node.init:
            if node.init.type == 'TemplateLiteral':
                result = self._resolve_template(node.init)
                if result and self._looks_like_path(result):
                    self.scope[node.id.name] = result
                    self._emit(result, 'GET', 'template_variable')

    def _resolve_template(self, node):
        parts = []
        quasis = node.quasis
        exprs  = node.expressions

        for i, quasi in enumerate(quasis):
            parts.append(quasi.value.cooked or '')
            if i < len(exprs):
                expr = exprs[i]
                resolved = self._resolve_expr(expr)
                parts.append(resolved if resolved else '{var}')

        result = ''.join(str(p) for p in parts)
        return result if len(result) > 2 else None

    def _resolve_expr(self, node):
        if node.type == 'Identifier':
            return self.scope.get(node.name, '')
        if node.type == 'Literal':
            return str(node.value)
        if node.type == 'MemberExpression' and not node.computed:
            obj  = node.object.name  if node.object.type  == 'Identifier' else ''
            prop = node.property.name if node.property.type == 'Identifier' else ''
            key  = f'{obj}.{prop}'
            return self.scope.get(key, '')
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._resolve_expr(node.left)  or ''
            r = self._resolve_expr(node.right) or ''
            return l + r
        return ''

    def _is_http_call(self, node):
        callee = node.callee
        HTTP_FNS = {'fetch', 'get', 'post', 'put', 'delete', 'patch',
                    'request', 'head', 'options'}
        if callee.type == 'Identifier' and callee.name in HTTP_FNS:
            return True
        if callee.type == 'MemberExpression':
            if hasattr(callee.property,'name') and callee.property.name in HTTP_FNS:
                return True
        return False

    def _infer_method(self, node):
        if node.callee.type == 'MemberExpression':
            name = getattr(node.callee.property, 'name', '').upper()
            if name in ('POST','PUT','DELETE','PATCH','GET','HEAD'):
                return name
        return 'GET'

    def _looks_like_path(self, s):
        return isinstance(s, str) and (s.startswith('/') or '/api' in s)

    def _emit(self, path, method, source):
        self.found.append({
            'method':     method,
            'endpoint':   path,
            'type':       'AST_TEMPLATE_LITERAL',
            'classification': 'BACKEND_API',
            'source':     source,
            'ast_extracted': True,
            'confidence_bonus': 2,
        })

class BranchLogicExtractor:
    """
    EXTRACTOR 3: BranchLogicExtractor
    Handles ternary operators, switch/case, and if/else logic.
    """
    def __init__(self, scope):
        self.scope = scope
        self.found = []

    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found

    def _visit(self, node):
        if node.type == 'ConditionalExpression':
            for branch in (node.consequent, node.alternate):
                val = self._try_extract_string(branch)
                if val and self._looks_like_path(val):
                    self._emit(val, 'GET', 'ternary_branch')

        if node.type == 'SwitchStatement':
            for case in node.cases:
                for stmt in case.consequent:
                    self._scan_for_paths_in_stmt(stmt)

        if node.type == 'IfStatement':
            for branch in filter(None, [node.consequent, node.alternate]):
                self._scan_for_paths_in_stmt(branch)

    def _scan_for_paths_in_stmt(self, node):
        if node is None:
            return
        if node.type == 'ReturnStatement' and node.argument:
            val = self._try_extract_string(node.argument)
            if val and self._looks_like_path(val):
                self._emit(val, 'GET', 'branch_return')
        if node.type == 'ExpressionStatement':
            expr = node.expression
            if expr.type == 'AssignmentExpression':
                val = self._try_extract_string(expr.right)
                if val and self._looks_like_path(val):
                    self._emit(val, 'GET', 'branch_assignment')
        if node.type == 'BlockStatement':
            for stmt in node.body:
                self._scan_for_paths_in_stmt(stmt)

    def _try_extract_string(self, node):
        if node is None:
            return None
        if node.type == 'Literal' and isinstance(node.value, str):
            return node.value
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._try_extract_string(node.left)  or ''
            r = self._try_extract_string(node.right) or ''
            combined = l + r
            return combined if combined else None
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    parts.append(self._try_extract_string(node.expressions[i]) or '')
            return ''.join(parts)
        return None

    def _looks_like_path(self, s):
        return isinstance(s, str) and len(s) > 1 and (s.startswith('/') or '/api' in s)

    def _emit(self, path, method, source):
        self.found.append({
            'method':     method,
            'endpoint':   path,
            'type':       'AST_BRANCH_LOGIC',
            'classification': 'BACKEND_API',
            'source':     source,
            'ast_extracted': True,
            'confidence_bonus': 1,
        })

class ASTExtractionLayer:
    """
    Orchestrates all four AST extractors.
    On parse failure, returns [] so regex pipeline continues unaffected.
    """
    def __init__(self, existing_bindings=None):
        self.existing_bindings = existing_bindings or {}
        self.logger = logging.getLogger('ASTExtractionLayer')

    def extract(self, js_source, source_label=''):
        if not ESPRIMA_AVAILABLE:
            return []

        MAX_JS_SIZE = 3 * 1024 * 1024
        if len(js_source.encode('utf-8')) > MAX_JS_SIZE:
            return []

        try:
            tree = esprima.parseScript(js_source, tolerant=True, jsx=False)
        except Exception:
            try:
                tree = esprima.parseModule(js_source, tolerant=True)
            except Exception:
                return []

        resolver = AliasResolver(self.existing_bindings)
        scope    = resolver.build_scope(tree)

        results = []
        extractors = [
            ComputedPropertyExtractor(scope),
            TemplateLiteralExtractor(scope),
            BranchLogicExtractor(scope),
            # ⭐ ENHANCEMENT 2.2: Add ObjectExpression extractor
            ObjectExpressionExtractor(scope),
        ]
        for extractor in extractors:
            try:
                found = extractor.extract(tree)
                results.extend(found)
            except Exception:
                pass

        for ep in results:
            ep.setdefault('source', source_label)

        return results

# ⭐ ENHANCEMENT 2.2: New extractor for object property access patterns
class ObjectExpressionExtractor:
    """
    EXTRACTOR 4: ObjectExpressionExtractor
    Handles patterns like: service["DeleteUser"], obj[key], endpoints.users
    """
    def __init__(self, scope):
        self.scope = scope
        self.found = []
    
    def extract(self, ast_body):
        walk(ast_body, self._visit)
        return self.found
    
    def _visit(self, node):
        # Handle object literals with URL values
        if node.type == 'ObjectExpression':
            for prop in node.properties:
                if hasattr(prop, 'value'):
                    val = self._try_extract_value(prop.value)
                    if val and self._looks_like_path(val):
                        key_name = self._get_property_key(prop)
                        self._emit(val, 'GET', 'object_property', key_name)
        
        # Handle variable declarations with object assignments
        if node.type == 'VariableDeclarator' and node.init:
            if node.init.type == 'ObjectExpression':
                for prop in node.init.properties:
                    if hasattr(prop, 'value'):
                        val = self._try_extract_value(prop.value)
                        if val and self._looks_like_path(val):
                            key_name = self._get_property_key(prop)
                            self._emit(val, 'GET', 'object_var_property', key_name)
    
    def _get_property_key(self, prop):
        """Extract the property key name"""
        if hasattr(prop, 'key'):
            if prop.key.type == 'Identifier':
                return prop.key.name
            elif prop.key.type == 'Literal':
                return str(prop.key.value)
        return None
    
    def _try_extract_value(self, node):
        """Try to extract a string value from various node types"""
        if node.type == 'Literal' and isinstance(node.value, str):
            return node.value
        if node.type == 'Identifier':
            return self.scope.get(node.name)
        if node.type == 'BinaryExpression' and node.operator == '+':
            l = self._try_extract_value(node.left) or ''
            r = self._try_extract_value(node.right) or ''
            return l + r if (l or r) else None
        if node.type == 'TemplateLiteral':
            parts = []
            for i, quasi in enumerate(node.quasis):
                parts.append(quasi.value.cooked or '')
                if i < len(node.expressions):
                    expr_val = self._try_extract_value(node.expressions[i])
                    parts.append(expr_val if expr_val else '{var}')
            return ''.join(parts)
        return None
    
    def _looks_like_path(self, s):
        if not isinstance(s, str) or len(s) < 2:
            return False
        return s.startswith('/') or '/api' in s or s.startswith('http')
    
    def _emit(self, path, method, source, key_name=None):
        self.found.append({
            'method': method,
            'endpoint': path,
            'type': 'AST_OBJECT_PROPERTY',
            'classification': 'BACKEND_API',
            'source': source,
            'key_name': key_name,
            'ast_extracted': True,
            'confidence_bonus': 2,
        })


# ==============================================================================
# CLASS: ENHANCED RPC PATTERN EXTRACTOR WITH METHOD CALL SUPPORT
# ==============================================================================
class EnhancedRPCExtractor:
    """Extracts RPC-style endpoint definitions with method call support"""
    
    def __init__(self, resolver):
        self.resolver = resolver
        self.endpoints = []
    
    def extract_rpc_patterns(self, code, filename):
        """Extract RPC concatenation patterns including method calls"""
        found = []
        
        # Pattern: this.property = this.method() + "path"
        pattern_method = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern_method.finditer(code):
            property_name = match.group(1)
            method_name = match.group(2)
            suffix = match.group(3)
            
            if self._is_noise(method_name, suffix):
                continue
            
            base_url = self.resolver.resolve_method_call(f"this.{method_name}")
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(property_name)
                    
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'this.{property_name} = this.{method_name}() + "{suffix}"',
                        'key': property_name,
                        'type': 'RPC_METHOD_CALL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 98
                    })
        
        # Pattern 1: Object property with concatenation (key: var + "endpoint")
        pattern1 = re.compile(r'(\w+)\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern1.finditer(code):
            key = match.group(1)
            var_name = match.group(2)
            endpoint_suffix = match.group(3)
            
            if self._is_noise(var_name, endpoint_suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + endpoint_suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(key)
                    
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'{var_name} + "{endpoint_suffix}"',
                        'key': key,
                        'type': 'RPC_OBJECT_PROPERTY',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 95
                    })
        
        # Pattern 2: Variable assignment with concatenation (url = base + "path")
        pattern2 = re.compile(r'(?:var|let|const)?\s*(\w+)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern2.finditer(code):
            result_var = match.group(1)
            base_var = match.group(2)
            suffix = match.group(3)
            
            if self._is_noise(base_var, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(base_var)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{base_var} + "{suffix}"',
                        'type': 'RPC_VARIABLE_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 90
                    })
        
        # Pattern 3: Template literals (`${base}path`)
        pattern3 = re.compile(r'`\$\{([a-zA-Z_$][a-zA-Z0-9_$.]*)\}([^`]+)`')
        for match in pattern3.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'`${{{var_name}}}{suffix}`',
                        'type': 'RPC_TEMPLATE_LITERAL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 85
                    })
        
        # Pattern 4: Method calls with concatenation
        pattern4 = re.compile(r'(?:get|post|put|delete|patch|fetch|postDataFromUrl|getDataFromUrl|postDataFromUrlWithoutSerialize|getDataFromUrlAndSendData|getRawDataFromUrl)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    ctx_before = code[max(0, match.start()-50):match.start()]
                    method = self._extract_method_from_context(ctx_before, code[match.start():match.start()+20])
                    
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'{var_name} + "{suffix}"',
                        'type': 'RPC_HTTP_CALL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 95
                    })
        
        # Pattern 5: Chained concatenation
        pattern5 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern5.finditer(code):
            var_name = match.group(1)
            part1 = match.group(2)
            part2 = match.group(3)
            
            if self._is_noise(var_name, part1 + part2):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + part1 + part2
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{var_name} + "{part1}" + "{part2}"',
                        'type': 'RPC_CHAINED_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 80
                    })
        
        # Pattern 6: Return statements
        pattern6 = re.compile(r'return\s+([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern6.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'return {var_name} + "{suffix}"',
                        'type': 'RPC_RETURN_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 85
                    })
        
        # Pattern 7: Array/Object literal with concatenation
        pattern7 = re.compile(r'[\[{,]\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern7.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)
            
            if self._is_noise(var_name, suffix):
                continue
            
            base_url = self.resolver.resolve_with_fallback(var_name)
            
            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{var_name} + "{suffix}"',
                        'type': 'RPC_ARRAY_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 80
                    })
        
        return found
    
    def _is_valid_endpoint(self, endpoint):
        """Validate if endpoint looks legitimate - AGGRESSIVE FILTERING"""
        if not endpoint or len(endpoint) < 3:
            return False
        
        # CRITICAL FIX 1: Reject endpoints with spaces (URLs shouldn't have spaces unless encoded)
        if ' ' in endpoint:
            return False
        
        # CRITICAL FIX 2: Reject template literal syntax that wasn't resolved
        if '${' in endpoint or '{{' in endpoint or '`' in endpoint:
            return False
        
        # CRITICAL FIX 3: Reject unbalanced parenthesis/brackets (indicates parsing error)
        try:
            if endpoint.count('(') != endpoint.count(')'):
                return False
            if endpoint.count('[') != endpoint.count(']'):
                return False
            if endpoint.count('{') != endpoint.count('}'):
                return False
        except:
            return False
        
        # CRITICAL FIX 4: Reject URLs with "undefined" or "null" literals
        if 'undefined' in endpoint.lower() or '/null' in endpoint or '/null/' in endpoint:
            return False
        
        # Check standard noise patterns
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, endpoint, re.IGNORECASE):
                return False
        
        endpoint_lower = endpoint.lower()
        
        # Check against noise keywords
        for keyword in NOISE_KEYWORDS:
            if keyword in endpoint_lower:
                return False
        
        # CRITICAL FIX 5: Reject Excel/internal framework paths
        if '/xl/' in endpoint_lower or 'worksheet' in endpoint_lower:
            return False
        
        # CRITICAL FIX 6: Reject Angular internal files
        if any(x in endpoint_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']):
            return False
        
        # Normalize ORIGIN placeholder
        if endpoint.startswith('ORIGIN'):
            endpoint = endpoint.replace('ORIGIN', '/')
        
        # Must start with valid protocol or path
        if not (endpoint.startswith('http') or endpoint.startswith('/') or endpoint.startswith('#/')):
            return False
        
        # Validation for http URLs
        if endpoint.startswith('http'):
            try:
                parsed = urllib.parse.urlparse(endpoint)
                if not parsed.netloc:
                    return False
                # CRITICAL FIX 7: Reject if path is empty or just slash (too generic)
                if not parsed.path or parsed.path == '/':
                    return False
                # CRITICAL FIX 8: Reject paths that are clearly not APIs (single letter paths)
                path_parts = [p for p in parsed.path.split('/') if p]
                if len(path_parts) == 1 and len(path_parts[0]) <= 2:
                    return False
            except:
                return False
        
        # CRITICAL FIX 9: Must contain typical URL separators or patterns
        valid_indicators = ['/', '.json', '.xml', '?', '=', 'api', 'get', 'post', 'update', 'delete', 'fetch']
        if not any(x in endpoint_lower for x in valid_indicators):
            return False
        
        # CRITICAL FIX 10: Reject if it looks like a file extension that's not an API
        if endpoint_lower.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.ttf', '.eot')):
            return False
        
        # CRITICAL FIX 11: Reject malformed query strings
        if '?' in endpoint:
            query_part = endpoint.split('?')[1] if len(endpoint.split('?')) > 1 else ''
            # If query exists but is just special chars, reject
            if query_part and not any(c.isalnum() for c in query_part):
                return False
        
        return True
    
    def _is_noise(self, var_name, suffix):
        """Check if this is noise pattern - ULTRA STRICT"""
        combined = (var_name + suffix).lower()
        
        # CRITICAL: Check all noise keywords
        for keyword in NOISE_KEYWORDS:
            if keyword in combined:
                return True
        
        # CRITICAL: Reject if suffix is too short (likely error)
        if len(suffix) < 2:
            return True
        
        # CRITICAL: Reject if suffix is just special chars or spaces
        if suffix.strip() in [':', '/', '?', '=', ',', '.', '-', '_']:
            return True
        
        # CRITICAL: Reject error message patterns
        if any(x in combined for x in ['caused by', 'valid digit', 'error', ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup']):
            return True
        
        # CRITICAL: Reject template syntax
        if any(x in suffix for x in ['${', '{{', '`', '\\n', '\\r']):
            return True
        
        # CRITICAL: Reject CSS/style fragments
        if any(x in suffix for x in ['animation-timing', 'sheet ${', 'sheet,', 'sheet[', 'sheet(', 'sheet.']):
            return True
        
        # CRITICAL: Reject single letter suffixes (like ' x', ' a')
        if suffix.strip() and len(suffix.strip()) == 1:
            return True
        
        # CRITICAL: Reject CSS units
        if suffix.strip() in ['px', 'ms', 'em', 'rem', 'vh', 'vw', 'pt', '%']:
            return True
        
        # CRITICAL: Reject if it's clearly a constant name, not a path
        if suffix.strip().isupper() and '_' in suffix:  # Like ON_PROPERTY
            return True
        
        return False
    
    def _guess_method_from_key(self, key):
        """Guess HTTP method from property key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'all']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        elif any(x in k for x in ['patch']):
            return 'PATCH'
        return 'GET'
    
    def _extract_method_from_context(self, before, after):
        """Extract HTTP method from surrounding context"""
        combined = (before + after).upper()
        
        for method in ['POST', 'PUT', 'DELETE', 'PATCH', 'GET']:
            if method in combined:
                return method
        
        return 'GET'

# ==============================================================================
# ENHANCED STATIC ANALYZER
# ==============================================================================
class EnhancedStaticAnalyzer:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.normalizer = URLNormalizer(base_url)
        self.endpoints = []
        self.confidence_scores = defaultdict(int)
        self.resolver = EnhancedVariableResolver()
        self.rpc_extractor = EnhancedRPCExtractor(self.resolver)
        self.analyzed_js_files = set()  # Track analyzed files to avoid duplicates

    def scan(self, js_urls, json_urls):
        print(f"\n[PHASE 2] Enhanced Analysis with Method Call Resolution")
        print(f"  Processing: {len(js_urls)} JS files, {len(json_urls)} JSON configs")
        
        # STEP 1: Extract ALL variables and methods
        print(f"\n  [Step 1/4] Extracting variables and methods...")
        js_contents = {}
        
        for i, url in enumerate(js_urls, 1):
            if i % 10 == 0:
                print(f"    Progress: [{i}/{len(js_urls)}]", end='\r')
            
            if any(x in url.lower() for x in LOW_VALUE_JS):
                continue
                
            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    filename = url.split('/')[-1]
                    js_contents[url] = r.text
                    self.resolver.extract_all_variables(r.text, filename)
                    self.analyzed_js_files.add(url)
            except requests.exceptions.Timeout:
                pass  # Skip files that timeout
            except Exception as e:
                pass  # Skip files with errors
        
        print(f"\n    [+] Extracted {len(self.resolver.variables)} unique variables")
        print(f"    [+] Found {len(self.resolver.methods)} method definitions")
        print(f"    [+] Found {len(self.resolver.service_properties)} service properties")
        print(f"    [+] Found {len(self.resolver.get_all_base_urls())} potential base URLs")
        
        # Show discovered methods
        if self.resolver.methods:
            print(f"\n  [Discovered Methods]")
            for method, value in list(self.resolver.methods.items())[:10]:
                print(f"    {method}() = {value}")
        
        # Show discovered service properties
        if self.resolver.service_properties:
            print(f"\n  [Discovered Service Properties]")
            for prop, data in list(self.resolver.service_properties.items())[:20]:
                print(f"    this.{prop} = {data['method_call']} + \"{data['suffix']}\"")
                print(f"      → {data['endpoint']}")
        
        # STEP 2: Extract RPC patterns
        print(f"\n  [Step 2/4] Extracting RPC patterns with method calls...")
        rpc_count = 0
        
        for url, code in js_contents.items():
            filename = url.split('/')[-1]
            rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)
            
            for ep in rpc_endpoints:
                full_url = self.normalizer.normalize(ep['endpoint'])
                
                self.add_endpoint(
                    full_url, 
                    ep['method'], 
                    [], 
                    ep['type'], 
                    ep['source'], 
                    ep['classification'], 
                    ep['confidence']
                )
                rpc_count += 1
            
            # Check for Array Harvested Items
            for var_name, var_data in self.resolver.variables.items():
                if var_name.startswith("ARRAY_ITEM_"):
                    full_url = self.normalizer.normalize(var_data['value'])
                    # Infer method from the last path segment name instead of hardcoding GET.
                    # e.g. DeleteTask → DELETE, CreateToken → POST, UpdateQuestion → PUT
                    ep_name = full_url.rstrip('/').split('/')[-1]
                    inferred_method = self._guess_method_from_key(ep_name)
                    self.add_endpoint(
                        full_url,
                        inferred_method,
                        [],
                        "ARRAY_HARVEST",
                        var_data['source_file'],
                        "BACKEND_API",
                        60
                    )

        print(f"    [+] Found {rpc_count} RPC-style endpoints")
        
        # STEP 3: Extract service property endpoints
        print(f"\n  [Step 3/4] Extracting service property endpoints...")
        service_count = 0
        
        for prop_name, prop_data in self.resolver.service_properties.items():
            full_url = self.normalizer.normalize(prop_data['endpoint'])
            method = self._guess_method_from_key(prop_name)
            
            self.add_endpoint(
                full_url,
                method,
                [],
                'SERVICE_PROPERTY',
                prop_data['source'],
                'BACKEND_API',
                97
            )
            service_count += 1
        
        print(f"    [+] Found {service_count} service property endpoints")
        
        # STEP 4: Standard analysis
        print(f"\n  [Step 4/4] Standard endpoint analysis...")
        
        for json_url in json_urls:
            self.analyze_json_config(json_url)
        
        for url, code in js_contents.items():
            self.analyze_code(code, url)
        
        # 🚀 LEGENDARY INTEGRATION 1: WebSocket Discovery from JavaScript
        print(f"\n  [WebSocket Discovery] Scanning JavaScript for WebSocket endpoints...")
        ws_discovery = WebSocketDiscovery()
        ws_count = 0
        
        for url, code in js_contents.items():
            ws_endpoints = ws_discovery.discover_from_js(code, url)
            for ws_ep in ws_endpoints:
                self.add_endpoint(
                    ws_ep['endpoint'],
                    'WS',
                    [],
                    'WEBSOCKET',
                    ws_ep['source'],
                    'WEBSOCKET_ENDPOINT',
                    85
                )
                ws_count += 1
        
        if ws_count > 0:
            print(f"    [+] Found {ws_count} WebSocket endpoints")
        
        # 🔥 FINAL FIX 2: Strict confidence filtering - remove all low-quality endpoints
        pre_filter_count = len(self.endpoints)
        self.endpoints = [
            ep for ep in self.endpoints
            if not (
                # Remove zero-confidence vendor garbage
                (ep.get("confidence_score", 0) == 0 and ep.get("origin", {}).get("is_vendor", False))
                or
                # 🚀 ULTIMATE FIX 2.3: Raised from 20 to 40 (matches add_endpoint threshold)
                (ep.get("confidence_score", 0) < 40 and ep.get("classification") in ["LIBRARY_ARTIFACT", "NOISE_CANDIDATE"])
                or
                # 🚀 ULTIMATE FIX 2.4: Also remove vendor sources with confidence < 40
                (ep.get("confidence_score", 0) < 40 and ep.get("origin", {}).get("is_vendor", False))
                or
                # Remove external references unless high confidence
                (ep.get("classification") == "EXTERNAL_REFERENCE" and ep.get("confidence_score", 0) < 50)
            )
        ]
        filtered_count = pre_filter_count - len(self.endpoints)
        if filtered_count > 0:
            print(f"    [FILTER] Removed {filtered_count} low-confidence/vendor endpoints")
        
        # 🚀 LEGENDARY INTEGRATION 2: GraphQL Introspection
        print(f"\n  [GraphQL Introspection] Scanning for GraphQL APIs...")
        graphql = GraphQLIntrospector(self.session)
        graphql_schemas = graphql.scan(self.endpoints)
        
        # Add all discovered GraphQL operations as endpoints
        graphql_ops_count = 0
        for gql_endpoint, schema in graphql_schemas.items():
            # Add each query as an endpoint
            for query in schema['queries']:
                self.add_endpoint(
                    f"{gql_endpoint}?query={query['name']}",
                    'POST',
                    query['args'],
                    'GRAPHQL_QUERY',
                    gql_endpoint,
                    'GRAPHQL_API',
                    95
                )
                graphql_ops_count += 1
            
            # Add each mutation as an endpoint
            for mutation in schema['mutations']:
                self.add_endpoint(
                    f"{gql_endpoint}?mutation={mutation['name']}",
                    'POST',
                    mutation['args'],
                    'GRAPHQL_MUTATION',
                    gql_endpoint,
                    'GRAPHQL_API',
                    95
                )
                graphql_ops_count += 1
        
        if graphql_ops_count > 0:
            print(f"    [+] Discovered {graphql_ops_count} GraphQL operations from {len(graphql_schemas)} endpoints")
        
        print(f"\n  [+] Total endpoints discovered: {len(self.endpoints)}")
        
        return self.endpoints

    def analyze_json_config(self, json_url):
        """Extract ALL string values from JSON config files"""
        try:
            r = self.session.get(json_url, timeout=10, verify=False)
            if r.status_code != 200:
                return
            
            data = r.json()
            filename = json_url.split('/')[-1]
            
            self._extract_from_json(data, filename, json_url)
            
        except json.JSONDecodeError:
            pass  # Not valid JSON
        except requests.exceptions.Timeout:
            pass  # Timeout
        except Exception:
            pass  # Other errors

    def _extract_from_json(self, data, filename, source_url, path=''):
        """Recursively extract ALL string values from JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                if isinstance(value, str):
                    if len(value) > 3 and not value.isspace():
                        method = self._guess_method_from_key(key)
                        classification = self._classify_json_value(value, key)
                        
                        if classification != "NOISE":
                            full_url = self.normalizer.normalize(value)
                            
                            self.add_endpoint(
                                full_url, 
                                method, 
                                [], 
                                "JSON_CONFIG", 
                                filename, 
                                classification, 
                                75
                            )
                        
                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, filename, source_url, current_path)
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, filename, source_url, f"{path}[{i}]")

    def _classify_json_value(self, value, key):
        """Determine if a JSON string value is an endpoint"""
        v = value.lower()
        k = key.lower()
        
        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return "NOISE"
        
        if any(re.search(p, value) for p in NOISE_PATTERNS):
            return "NOISE"
        
        if any(re.search(p, value, re.IGNORECASE) for p in API_INDICATORS):
            return "BACKEND_API"
        
        api_key_indicators = ['api', 'endpoint', 'url', 'service', 'path', 'route', 'dashboard']
        if any(ind in k for ind in api_key_indicators):
            if value.startswith('/') or value.startswith('http') or value.startswith('#/'):
                return "BACKEND_API"
        
        if value.startswith('http'):
            if not any(d in v for d in IGNORED_DOMAINS):
                return "EXTERNAL_API"
        
        if (value.startswith('/') or value.startswith('#/')) and len(value) > 3:
            if '/' in value[1:] or '#' in value:
                return "FRONTEND_ROUTE"
        
        return "NOISE"

    def _guess_method_from_key(self, key):
        """Guess HTTP method from key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'view', 'all', 'dash']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        return 'GET'

    def analyze_code(self, code, source):
        """Analyze JavaScript code for endpoints"""
        if any(x in source.lower() for x in LOW_VALUE_JS):
            return

        # -------------------------------------------------------------------------
        # AST INTEGRATION START
        # -------------------------------------------------------------------------
        try:
            simple_bindings = {}
            if hasattr(self, 'resolver'):
                for k, v in self.resolver.variables.items():
                    if isinstance(v, dict) and 'value' in v:
                        simple_bindings[k] = v['value']
                    elif isinstance(v, str):
                        simple_bindings[k] = v

            ast_layer = ASTExtractionLayer(existing_bindings=simple_bindings)
            ast_endpoints = ast_layer.extract(code, source)
            
            for ep in ast_endpoints:
                url = ep.get('endpoint')
                method = ep.get('method', 'GET')
                # Base confidence 95 + bonus
                bonus = ep.get('confidence_bonus', 0)
                confidence = 95 + (bonus * 2)
                
                # Extract extra fields strictly for AST endpoints
                extra = {
                    'ast_extracted': ep.get('ast_extracted', False),
                    'alias_name': ep.get('alias_name')
                }
                
                self.add_endpoint(
                    url,
                    method,
                    [], 
                    ep.get('type'),
                    source,
                    ep.get('classification', 'BACKEND_API'),
                    confidence,
                    extra_fields=extra
                )
        except Exception:
            # Fallback contract: never suppress regex output on AST failure
            pass
        # -------------------------------------------------------------------------
        # AST INTEGRATION END
        # -------------------------------------------------------------------------

        # HTTP patterns
        for m in re.finditer(r'this\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTP_THIS", "BACKEND_API", 95)
        
        for m in re.finditer(r'\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTP", "BACKEND_API", 90)
        
        for m in re.finditer(r'this\.httpclient\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTPCLIENT_THIS", "BACKEND_API", 95)
        
        for m in re.finditer(r'\.httpclient\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(2))
            self.process(full_url, m.group(1).upper(), m.start(), code, source, "HTTPCLIENT", "BACKEND_API", 90)
        
        # Router patterns
        for m in re.finditer(r'this\.router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTER_NAV_THIS", "FRONTEND_ROUTE", 85)
        
        for m in re.finditer(r'this\.route\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTE_NAV_THIS", "FRONTEND_ROUTE", 85)
        
        for m in re.finditer(r'router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTER_NAV", "FRONTEND_ROUTE", 80)
        
        for m in re.finditer(r'route\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTE_NAV", "FRONTEND_ROUTE", 80)
        
        for m in re.finditer(r'window\.open\s*\(\s*[\'"]([^\'"]+)[\'"]', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN", "OPEN_REDIRECT_SINK", 90)
        
        # Fetch API
        for m in re.finditer(r'fetch\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            method = self.detect_method(code, m.start())
            self.process(full_url, method, m.start(), code, source, "FETCH_API", "BACKEND_API", 85)
        
        # Location patterns
        for m in re.finditer(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            path = m.group(1)
            clean_path = self._extract_clean_route(path)
            if clean_path:
                full_url = self.normalizer.normalize(clean_path)
                self.process(full_url, "GET", m.start(), code, source, "LOCATION_ORIGIN", "FRONTEND_ROUTE", 85)
        
        # Hash routes
        for pattern in HASH_ROUTE_PATTERNS:
            for m in re.finditer(pattern, code):
                route = m.group(1)
                if self._is_valid_route(route):
                    full_url = self.normalizer.normalize(route)
                    self.process(full_url, "GET", m.start(), code, source, "HASH_ROUTE", "FRONTEND_ROUTE", 75)
        
        for m in re.finditer(r'window\.open\s*\(\s*location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            path = m.group(1)
            clean_path = self._extract_clean_route(path)
            if clean_path:
                full_url = self.normalizer.normalize(clean_path)
                self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN_ROUTE", "FRONTEND_ROUTE", 88)
        
        # String literals with API patterns
        for m in re.finditer(r'["\']([/#][^\'"]{3,100}?)["\']', code):
            url = m.group(1)
            if self.has_api_pattern(url):
                cls = self.classify(url)
                if cls != "NOISE":
                    full_url = self.normalizer.normalize(url)
                    self.process(full_url, self.detect_method(code, m.start()), m.start(), code, source, "STATIC_CODE", cls, 50)

    def analyze_code_from_dynamic(self, code, source):
        """
        Special method for analyzing code discovered during dynamic phase.
        This is called from the feedback loop.
        """
        filename = source.split('/')[-1] if '/' in source else source
        
        # Extract variables and methods from this new code
        self.resolver.extract_all_variables(code, filename)
        
        # Extract RPC patterns
        rpc_endpoints = self.rpc_extractor.extract_rpc_patterns(code, filename)
        for ep in rpc_endpoints:
            full_url = self.normalizer.normalize(ep['endpoint'])
            self.add_endpoint(
                full_url, 
                ep['method'], 
                [], 
                ep['type'] + '_DYNAMIC', 
                ep['source'], 
                ep['classification'], 
                ep['confidence']
            )
        
        # Run standard code analysis
        self.analyze_code(code, source)

    def _extract_clean_route(self, path):
        """Extract clean route from JavaScript concatenation"""
        path = path.strip()
        
        if '+' in path:
            path = path.split('+')[0]
        
        if '(' in path and ')' in path:
            parts = re.split(r'[()]', path)
            for part in parts:
                if '#/' in part:
                    path = part
                    break
        
        path = path.strip('"\'')
        
        if self._is_valid_route(path):
            return path
        return None
    
    def _is_valid_route(self, route):
        """Check if route is valid"""
        if not route:
            return False
        
        route_lower = route.lower()
        
        for keyword in NOISE_KEYWORDS:
            if keyword in route_lower:
                return False
        
        return ('#/' in route or route.startswith('/') or route.startswith('#/'))

    def process(self, url, method, pos, code, source, type, classification, confidence):
        if self.is_valid(url):
            params = self.extract_params(code, pos + len(url))
            self.add_endpoint(url, method, params, type, source, classification, confidence)

    def add_endpoint(self, url, method, params, type, source, classification, confidence, extra_fields=None):
        # NEW: Validation Gate
        if EndpointClassifier.is_hard_garbage(url):
            return

        url = self._clean_url(url)
        
        if not url:
            return
        
        # CRITICAL FIX: Normalize trailing slashes for deduplication
        # /api/users and /api/users/ should be treated as the same
        url_normalized = url.rstrip('/')
        
        url_lower = url_normalized.lower()
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return
        
        if any(re.search(p, url_normalized) for p in NOISE_PATTERNS):
            return
        
        # ADDITIONAL FIX: Reject if URL path is too short (likely noise)
        try:
            parsed = urllib.parse.urlparse(url_normalized)
            if parsed.path and len(parsed.path.strip('/')) < 2:
                return  # Paths like /x or /a are noise
        except:
            pass
        
        # Deduplicate on URL only (not method+URL).
        # When the same endpoint is found by multiple extractors, keep the highest-confidence
        # entry's method. If a non-GET method is found later, always promote to it because
        # GET is the default fallback and a specific method is always more accurate.
        for e in self.endpoints:
            existing_url = e['endpoint'].rstrip('/')
            if existing_url == url_normalized:
                # Always merge parameters
                e['parameters'] = sorted(list(set(e['parameters'] + params)))[:10]
                existing_conf = self.confidence_scores.get(f"ANY:{url_normalized}", 0)
                if confidence > existing_conf:
                    # Higher confidence found: upgrade method, type, classification, source
                    e['method'] = method
                    e['type'] = type
                    e['classification'] = classification
                    e['source'] = source if isinstance(source, str) else str(source)[:80]
                    self.confidence_scores[f"ANY:{url_normalized}"] = confidence
                    if extra_fields:
                        e.update(extra_fields)
                elif method != 'GET' and e['method'] == 'GET':
                    # Even at equal/lower confidence: never let a hardcoded GET
                    # override a specifically-detected method (POST/PUT/DELETE/PATCH)
                    e['method'] = method
                return
        
        # --- NEW SCORING LOGIC INTEGRATION START ---
        is_vendor = LibraryFingerprint.is_vendor(source)
        score_result = EndpointClassifier.score_and_classify(url, type, is_vendor)
        
        # ⭐ IMPROVEMENT 2: Drop endpoints that returned None (score=0)
        if score_result is None:
            return  # Skip this endpoint entirely
        
        final_score, final_cat, tags = score_result
        
        # ⭐ ENHANCEMENT 3.1: Aggressive vendor garbage filtering
        # Reject endpoints with confidence_score == 0 from vendor sources
        if final_score == 0 and is_vendor:
            return  # Skip vendor garbage completely
        
        # 🚀 ULTIMATE FIX 2.1: Raised threshold from 20 to 40 to eliminate confidence 10-30 noise
        if final_score < 40 and final_cat in ["LIBRARY_ARTIFACT", "NOISE_CANDIDATE"]:
            return  # Skip low-value noise (confidence < 40)
        
        # 🚀 ULTIMATE FIX 2.2: Also filter vendor sources with low confidence (10-30 range)
        if final_score < 40 and is_vendor:
            return  # Skip ALL vendor content below confidence 40
        
        # Use new classification if original was generic BACKEND_API
        # Keep original if it was specific (e.g. FRONTEND_ROUTE) and high confidence
        if classification == "BACKEND_API" and final_cat != "HIGH_CONFIDENCE":
            pass # Keep strict
        else:
             # If our new classifier says it's noise/low confidence, update classification
             if final_cat in ["LIBRARY_ARTIFACT", "NOISE_CANDIDATE", "EXTERNAL_REFERENCE"]:
                 classification = final_cat

        entry = {
            "endpoint": url,  # Use original URL (with or without trailing slash as originally found)
            "method": method, 
            "parameters": params, 
            "type": type, 
            "source": source if isinstance(source, str) else source.split('/')[-1][:80],
            "classification": classification,
            "confidence_score": final_score,
            "origin": {
                "is_vendor": is_vendor,
                "extraction_type": type
            },
            "tags": tags
        }
        if extra_fields:
            entry.update(extra_fields)
            
        self.endpoints.append(entry)
        self.confidence_scores[f"ANY:{url_normalized}"] = confidence
        # --- NEW SCORING LOGIC INTEGRATION END ---
    
    def _clean_url(self, url):
        """Clean malformed URLs"""
        url = str(url).strip()
        
        if url.startswith('ORIGIN'):
            url = url.replace('ORIGIN', '')
        
        if url.startswith('https://') and 'window.open' in url:
            match = re.search(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', url)
            if match:
                path = match.group(1)
                clean_path = self._extract_clean_route(path)
                if clean_path:
                    return self.normalizer.normalize(clean_path)
            return None
        
        url = url.replace('\"', '')
        
        if '(' in url and ')' in url and ('window.open' in url or 'location.origin' in url):
            match = re.search(r'["\']([^"\']+)["\']', url)
            if match:
                url = match.group(1)
        
        if ')' in url:
            url = url.split(')')[0]
        if ',' in url and '_self' in url:
            url = url.split(',')[0]
        
        return url

    def is_valid(self, url):
        """Validate URL - ULTRA STRICT"""
        if not url:
            return False
            
        url = url.strip()
        if len(url) < 3 or ' ' in url: 
            return False
        
        url_lower = url.lower()
        
        # CRITICAL: Check noise keywords first
        for keyword in NOISE_KEYWORDS:
            if keyword in url_lower:
                return False
        
        # CRITICAL: Check strict blocks
        if any(b in url.lower() for b in STRICT_BLOCKS): 
            return False
        
        # CRITICAL: Check noise patterns
        for p in FALSE_POSITIVE_PATTERNS:
            if re.search(p, url, re.IGNORECASE): 
                return False
        
        # CRITICAL: Additional specific checks from real scan
        # Block single letter paths like /x, /a
        if re.search(r'/[a-zA-Z]$', url):
            return False
        
        # Block CSS unit paths like /px, /ms
        if re.search(r'/(?:px|ms|em|rem|vh|vw|pt)$', url):
            return False
        
        # Block unresolved template syntax
        if any(x in url for x in ['${', '{{', '`', '\\n']):
            return False
        
        # Block URLs with "undefined" or "null" in path
        if '/undefined/' in url or '/null/' in url or url.endswith('/undefined') or url.endswith('/null'):
            return False
        
        # Block framework internal files
        if url.endswith('.js') and any(x in url_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']):
            return False
        
        # Block template.html
        if 'template.html' in url_lower:
            return False
        
        # Block Excel internal paths
        if '/xl/' in url_lower or 'worksheet' in url_lower:
            return False
        
        # Block error message fragments
        if any(x in url_lower for x in ['caused by:', 'valid digit', 'animation-timing-function']):
            return False
        
        # Block ON_PROPERTY and other leaked constants
        if 'ON_PROPERTY' in url or 'ON_INIT' in url:
            return False
        
        if url.startswith('#/'):
            return True
        
        # Block non-API file extensions
        if url.lower().endswith(('.js', '.css', '.png', '.svg', '.woff', '.jpg', '.jpeg', '.gif', '.ico', '.ttf', '.eot', '.woff2')):
            return False
        
        return True

    def has_api_pattern(self, url):
        """Check for API patterns"""
        return any(re.search(p, url, re.IGNORECASE) for p in API_INDICATORS)

    def classify(self, url):
        """Classify endpoint type"""
        u = url.lower()
        if self.has_api_pattern(url): 
            return "BACKEND_API"
        if any(x in u for x in ['/login', '/dashboard', '/profile', '/#/', '/admin']): 
            return "FRONTEND_ROUTE"
        if u.startswith('#/'):
            return "FRONTEND_ROUTE"
        if u.startswith('http'): 
            return "EXTERNAL_API" if not any(d in u for d in IGNORED_DOMAINS) else "NOISE"
        if (u.startswith('/') or u.startswith('#/')) and len(u) > 3:
            return "FRONTEND_ROUTE"
        return "NOISE"

    def detect_method(self, code, pos):
        """Detect HTTP method from context"""
        ctx = code[max(0, pos-200):min(len(code), pos+200)].upper()
        for m in ["POST", "PUT", "DELETE", "PATCH"]:
            if m in ctx: 
                return m
        return "GET"

    def extract_params(self, code, pos):
        """Extract parameter names"""
        ctx = code[pos:pos+500]
        matches = re.findall(r'[{,]\s*["\']?([a-zA-Z0-9_]{2,20})["\']?\s*:', ctx)
        
        # Tier 1: JavaScript reserved words
        js_keywords = {
            'var', 'let', 'const', 'if', 'else', 'true', 'false', 'null', 'this', 'return',
            'switch', 'case', 'default', 'break', 'function', 'class', 'typeof', 'void',
            'undefined', 'new', 'delete', 'in', 'instanceof', 'do', 'while', 'for', 'try',
            'catch', 'finally', 'throw', 'export', 'import', 'from', 'as', 'async', 'await'
        }
        
        # Tier 2: React/JSX/UI noise keys that appear in the 500-char window around
        # a fetch() call in JSX files (component state, event handlers, UI props).
        # These are NOT API parameters — they are React component internals.
        react_noise = {
            # Component state
            'loading', 'loaded', 'pending', 'status', 'isLoading', 'isFetching',
            'isError', 'isSuccess', 'error',
            # JSX event handlers
            'onClick', 'onChange', 'onSubmit', 'onBlur', 'onFocus',
            'onKeyDown', 'onKeyUp', 'onKeyPress', 'onMouseEnter', 'onMouseLeave',
            # UI component props
            'label', 'title', 'message', 'description', 'placeholder',
            'buttons', 'actions', 'variant', 'size', 'color', 'icon',
            'disabled', 'visible', 'hidden', 'checked', 'selected',
            # React Router props (appear near navigate/redirect calls)
            'path', 'pathname', 'component', 'render', 'exact', 'strict',
            'location', 'history', 'match', 'to', 'push', 'replace',
            # Modal/dialog patterns (common near delete/confirm endpoints)
            'open', 'close', 'toggle', 'show', 'hide', 'confirm', 'cancel',
            # Style and layout props
            'style', 'className', 'children', 'ref',
        }
        
        full_blacklist = js_keywords | react_noise
        
        clean = []
        for p in matches:
            if p.lower() not in full_blacklist:
                if len(p) > 2:
                    clean.append(p)
        
        return sorted(list(set(clean)))[:8]

# ==============================================================================
# URL NORMALIZER
# ==============================================================================
class URLNormalizer:
    """Normalizes endpoints to complete URLs"""
    
    def __init__(self, base_url):
        self.base_url = base_url
        self.base_url = base_url.rstrip('/')  # Ensure no trailing slash on base
        parsed = urllib.parse.urlparse(base_url)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc
        self.base_path = parsed.path.rstrip('/')
    
    def normalize(self, endpoint):
        """Convert endpoint to complete URL"""
        if endpoint.startswith('http://') or endpoint.startswith('https://'):
            return endpoint
        
        if endpoint.startswith('//'):
            return f'{self.scheme}:{endpoint}'
        
        if endpoint.startswith('/'):
            if '#/' in endpoint:
                return f'{self.scheme}://{self.netloc}{endpoint}'
            return f'{self.scheme}://{self.netloc}{endpoint}'
        
        if endpoint.startswith('#/'):
            return f'{self.scheme}://{self.netloc}{self.base_path}{endpoint}'
        
        if '#/' in endpoint:
            if endpoint.startswith('/'):
                return f'{self.scheme}://{self.netloc}{endpoint}'
            else:
                return f'{self.scheme}://{self.netloc}/{endpoint}'
        
        return f'{self.scheme}://{self.netloc}/{endpoint}'

# ==============================================================================
# FEDERATION HUNTER - ENHANCED WITH RECURSIVE DISCOVERY
# ==============================================================================
class EnhancedFederationHunter:
    def __init__(self, session, target_url):
        self.session = session
        self.target_url = target_url
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.found_js_files = set()
        self.found_json_files = set()
        self.scan_queue = deque()

    def run(self):
        print(f"\n[PHASE 1] Discovery (JS + JSON)")
        
        self.check_config_files()
        self.crawl_html()

        print(f"  Deep scanning JavaScript files...")
        processed_files = set()
        scan_errors = 0
        
        while self.scan_queue:
            url = self.scan_queue.popleft()
            if url in processed_files: 
                continue
            processed_files.add(url)
            
            if any(x in url.lower() for x in LOW_VALUE_JS): 
                continue

            try:
                r = self.session.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    self.hunt_webpack_chunks(r.text, url)
                    self.hunt_config_references(r.text, url)
                elif r.status_code == 403:
                    print(f"\n  [!] 403 Forbidden on {url.split('/')[-1]} - Site may be blocking scraper")
                    scan_errors += 1
            except requests.exceptions.Timeout:
                scan_errors += 1
            except Exception as e:
                if scan_errors < 3:  # Only show first few errors
                    print(f"\n  [!] Error fetching {url.split('/')[-1]}: {type(e).__name__}")
                scan_errors += 1
        
        if scan_errors > 0:
            print(f"  [!] {scan_errors} files failed to download")

        # ⭐ IMPROVEMENT 1: Forced endpoint probing for common API paths
        self._probe_common_endpoints()

        print(f"  [+] JS: {len(self.found_js_files)}, JSON: {len(self.found_json_files)}")
        return list(self.found_js_files), list(self.found_json_files)
    
    def _probe_common_endpoints(self):
        """⭐ IMPROVEMENT 1: Probe common API endpoints that may not be linked"""
        print(f"  Probing {len(COMMON_ENDPOINTS)} common endpoints...")
        
        found_count = 0
        for endpoint in COMMON_ENDPOINTS:
            test_url = self.base_url + endpoint
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Consider 200, 401, 403 as "exists" (endpoint is present even if blocked)
                if response.status_code in [200, 401, 403]:
                    found_count += 1
                    if found_count <= 5:  # Only print first 5 to avoid spam
                        print(f"    • Found: {endpoint} (Status: {response.status_code})")
            except:
                pass  # Endpoint doesn't exist, continue
        
        if found_count > 0:
            print(f"  [+] Probing discovered {found_count} active endpoints")
        else:
            print(f"  [-] No common endpoints found via probing")

    def check_config_files(self):
        """Check common config file locations"""
        config_paths = [
            '/assets/config/environment.json',
            '/assets/config/config.json',
            '/config/environment.json',
            '/environment.json',
            '/config.json',
        ]
        
        for path in config_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=8, verify=False)
                if r.status_code == 200:
                    try:
                        r.json()
                        self.found_json_files.add(url)
                        print(f"  [*] Found config: {path}")
                    except json.JSONDecodeError:
                        pass  # Not valid JSON
            except requests.exceptions.Timeout:
                pass  # Config file doesn't exist, timeout is expected
            except Exception as e:
                # Only print unexpected errors
                if "404" not in str(e) and "Connection" not in str(e):
                    print(f"  [!] Error checking {path}: {e}")

    def hunt_config_references(self, code, source_url):
        """Extract JSON file references from JS code"""
        json_refs = re.findall(r'["\']([^"\']+\.json)["\']', code)
        base = source_url.rsplit('/', 1)[0] + '/'
        
        for ref in json_refs:
            if any(x in ref.lower() for x in ['sourcemap', 'webpack']):
                continue
            
            if ref.startswith('http'):
                full_url = ref
            elif ref.startswith('/'):
                full_url = urllib.parse.urljoin(self.base_url, ref)
            else:
                full_url = urllib.parse.urljoin(base, ref.lstrip('./'))
            
            if self.base_url in full_url and full_url not in self.found_json_files:
                try:
                    r = self.session.get(full_url, timeout=5, verify=False)
                    if r.status_code == 200:
                        try:
                            r.json()
                            self.found_json_files.add(full_url)
                        except json.JSONDecodeError:
                            pass
                except requests.exceptions.Timeout:
                    pass
                except Exception:
                    pass

    def crawl_html(self):
        """Crawl HTML for script tags"""
        print(f"  [*] Fetching HTML from {self.target_url}...")
        try:
            # Add verify=False to handle self-signed certs
            r = self.session.get(self.target_url, timeout=15, verify=False)
            print(f"  [*] Status Code: {r.status_code}")
            
            if r.status_code != 200:
                print(f"  [!] Non-200 status code. Content length: {len(r.text)}")
                # Still try to parse even with non-200 status
            
            soup = BeautifulSoup(r.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            print(f"  [*] Found {len(scripts)} script tags in HTML")
            
            if len(scripts) == 0:
                print(f"  [!] WARNING: No <script> tags found. This might be a dynamic SPA.")
                print(f"  [!] HTML preview (first 500 chars):")
                print(f"      {r.text[:500]}")
            
            for s in scripts:
                url = urllib.parse.urljoin(self.target_url, s['src'])
                if not any(b in url for b in IGNORED_DOMAINS):
                    if url not in self.found_js_files:
                        self.found_js_files.add(url)
                        self.scan_queue.append(url)
                        
        except requests.exceptions.SSLError as e:
            print(f"  [!] SSL Error: {e}")
            print(f"  [!] Try adding verify=False or check SSL certificate")
        except requests.exceptions.ConnectionError as e:
            print(f"  [!] Connection Error: {e}")
            print(f"  [!] Cannot reach target. Check internet connection.")
        except Exception as e:
            print(f"  [!] CRITICAL ERROR in crawl_html: {type(e).__name__}: {e}")

    def hunt_webpack_chunks(self, code, source_url):
        """Hunt for webpack chunk patterns"""
        suffix_match = re.search(r'\)\s*\+\s*["\']([^"\']+\.js)["\']', code)
        if suffix_match:
            suffix = suffix_match.group(1)
            candidates = re.finditer(r'["\']([\w-]+)["\']\s*:\s*["\']([^"\']+)["\']', code)
            base_url = source_url.rsplit('/', 1)[0] + '/'
            
            for match in candidates:
                val = match.group(2)
                if len(val) < 2 or len(val) > 100 or ' ' in val: 
                    continue
                clean_val = val.lstrip('./')
                if clean_val.startswith('/'):
                    full_chunk_url = urllib.parse.urljoin(self.base_url, clean_val + suffix)
                else:
                    full_chunk_url = urllib.parse.urljoin(base_url, clean_val + suffix)
                
                if full_chunk_url not in self.found_js_files:
                    self.found_js_files.add(full_chunk_url)
                    self.scan_queue.append(full_chunk_url)

# ==============================================================================
# DYNAMIC INTERCEPTOR - ENHANCED WITH FEEDBACK LOOP
# ==============================================================================
class DynamicInterceptor:
    """
    Enhanced Dynamic Interceptor with recursive feedback loop.
    
    Key improvements:
    1. Captures lazy-loaded JS files and feeds them back to static analyzer
    2. Multi-pass navigation with increasing depth
    3. Better handling of authentication redirects
    4. Intelligent route prioritization
    """
    
    def __init__(self, target_url, analyzer, cookies=None, max_routes=25, max_depth=3):
        self.target_url = target_url
        self.analyzer = analyzer  # Feedback loop to static analyzer
        self.domain = urllib.parse.urlparse(target_url).netloc
        self.base_url = f"{urllib.parse.urlparse(target_url).scheme}://{urllib.parse.urlparse(target_url).netloc}"
        self.cookies = cookies
        self.endpoints = []
        self.seen_requests = set()
        self.analyzed_js_files = set()  # Track JS files we've already analyzed
        self.discovered_routes = set()
        self.max_routes = max_routes
        self.max_depth = max_depth
        self.session_storage_data = {}
        self.local_storage_data = {}

    def run(self, static_endpoints=[]):
        if not PLAYWRIGHT_AVAILABLE: 
            print(f"\n[PHASE 3] SKIP — Playwright not installed")
            print(f"  Install: pip install playwright && python -m playwright install chromium")
            self.skip_reason = 'playwright_not_installed'
            return []
            
        print(f"\n[PHASE 3] Dynamic Discovery with Recursive Feedback Loop")
        print(f"  Max routes per depth: {self.max_routes}, Max depth: {self.max_depth}")
        self.skip_reason = None
        
        # Multi-pass navigation with increasing depth
        for depth in range(1, self.max_depth + 1):
            print(f"\n  [Depth {depth}/{self.max_depth}] Navigating routes...")
            
            # Get routes for this depth level
            routes = self._get_routes_for_depth(static_endpoints, depth)
            
            if not routes:
                print(f"    No new routes at depth {depth}")
                break
            
            print(f"    Routes to visit: {len(routes)}")
            
            # Navigate with feedback loop
            self._navigate_routes_with_feedback(routes, depth)
            
            print(f"    Analyzed {len(self.analyzed_js_files)} JS files so far")
            print(f"    Discovered {len(self.discovered_routes)} unique routes")
            print(f"    Captured {len(self.endpoints)} API calls")
        
        print(f"\n  [+] Total dynamic endpoints: {len(self.endpoints)}")
        print(f"  [+] Total JS files analyzed: {len(self.analyzed_js_files)}")
        
        return self.endpoints

    def _get_routes_for_depth(self, static_endpoints, depth):
        """Get routes to visit at a specific depth level"""
        routes = []
        
        if depth == 1:
            # First pass: start with target URL
            routes = [self.target_url]
            
            # Add high-priority frontend routes
            for e in static_endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in routes:
                        routes.append(clean)
        else:
            # Subsequent passes: use newly discovered routes
            routes = list(self.discovered_routes)
            
            # Also check for any new routes from the analyzer
            for e in self.analyzer.endpoints:
                if e['classification'] == 'FRONTEND_ROUTE':
                    clean = self._clean_route(e['endpoint'])
                    if clean and clean not in self.discovered_routes:
                        routes.append(clean)
        
        # Prioritize routes with hash fragments and deeper paths
        routes = self._prioritize_routes(routes, depth)
        
        # Limit routes per depth
        return routes[:self.max_routes]

    def _clean_route(self, endpoint):
        """Clean and normalize a route for navigation - WITH AGGRESSIVE FILTERING"""
        if not endpoint:
            return None
        
        # Remove quotes and whitespace
        clean = endpoint.replace('"', '').replace("'", "").strip()
        
        # CRITICAL FIX 1: Reject routes containing 'undefined' or 'null' string literals
        if 'undefined' in clean.lower() or '/null' in clean or '/null/' in clean:
            return None
        
        # CRITICAL FIX 2: Reject routes with template syntax
        if '${' in clean or '{{' in clean or '`' in clean:
            return None
        
        # CRITICAL FIX 3: Reject routes with spaces (malformed)
        if ' ' in clean:
            return None
        
        # CRITICAL FIX 4: Reject internal framework files
        if any(x in clean.lower() for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'template.html', '/xl/']):
            return None
        
        # Build full URL
        if clean.startswith('http'):
            full = clean
        elif clean.startswith('/'):
            full = urllib.parse.urljoin(self.base_url, clean)
        else:
            return None
        
        # Only return if it's from our domain
        if self.domain in full:
            return full
        
        return None

    def _prioritize_routes(self, routes, depth):
        """Prioritize routes based on depth and characteristics"""
        def route_score(route):
            score = 0
            
            # Prefer hash routes at all depths
            if '#/' in route:
                score += 100
            
            # Prefer deeper paths
            path_depth = route.count('/')
            score += path_depth * 10
            
            # Prefer routes with meaningful names (not just IDs)
            if any(keyword in route.lower() for keyword in ['dashboard', 'admin', 'user', 'profile', 'settings', 'manage', 'list', 'view', 'edit']):
                score += 50
            
            # Penalize routes that look like they need parameters
            if re.search(r'/\d+$', route) or re.search(r'/:[\w]+', route):
                score -= 30
            
            return score
        
        return sorted(routes, key=route_score, reverse=True)

    def _navigate_routes_with_feedback(self, routes, depth):
        """Navigate routes and feed discovered JS back to analyzer"""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1920, 'height': 1080}
            )
            
            # Set cookies
            if self.cookies:
                context.add_cookies([
                    {"name": k, "value": v, "domain": self.domain, "path": "/"} 
                    for k, v in self.cookies.items()
                ])
            
            page = context.new_page()
            
            # ⭐ IMPROVEMENT 3 & 4: Inject runtime interception for fetch/XHR/axios + lazy chunk detection
            interceptor_script = """
            // Runtime API call interception
            window.__api_calls = window.__api_calls || [];
            window.__lazy_chunks = window.__lazy_chunks || [];
            
            // Intercept fetch
            const originalFetch = window.fetch;
            window.fetch = function() {
                const url = arguments[0];
                if (typeof url === 'string') {
                    window.__api_calls.push({type: 'fetch', url: url, method: arguments[1]?.method || 'GET'});
                } else if (url instanceof Request) {
                    window.__api_calls.push({type: 'fetch', url: url.url, method: url.method});
                }
                return originalFetch.apply(this, arguments);
            };
            
            // Intercept XMLHttpRequest
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                window.__api_calls.push({type: 'xhr', url: url, method: method});
                return originalOpen.apply(this, arguments);
            };
            
            // Intercept axios (if present)
            if (window.axios) {
                const originalRequest = window.axios.request;
                window.axios.request = function(config) {
                    window.__api_calls.push({type: 'axios', url: config.url, method: config.method?.toUpperCase() || 'GET'});
                    return originalRequest.apply(this, arguments);
                };
            }
            
            // ⭐ IMPROVEMENT 4: Detect import() lazy chunks
            const originalImport = window.import;
            if (originalImport) {
                window.import = function(path) {
                    window.__lazy_chunks.push(path);
                    return originalImport.apply(this, arguments);
                };
            }
            """
            
            # Inject the script before any navigation
            page.add_init_script(interceptor_script)
            
            # 🚀 LEGENDARY INTEGRATION 3: Set up WebSocket interception
            ws_discovery = WebSocketDiscovery()
            ws_discovery.intercept_playwright_websockets(page)
            
            # Subscribe to response events for feedback loop
            page.on("response", self._handle_response)
            
            # ⭐ ENHANCEMENT 1.1: Add request interceptor for XHR/Fetch (captures outgoing API calls)
            page.on("request", self._handle_request)
            
            # Navigate each route
            for i, route in enumerate(routes, 1):
                print(f"      [{i}/{len(routes)}] {route[:80]}", end='\r')
                
                try:
                    # Navigate and wait for network to settle
                    response = page.goto(route, wait_until="networkidle", timeout=20000)
                    
                    # Check if we got redirected to login
                    if response and 'login' in page.url.lower() and 'login' not in route.lower():
                        print(f"\n      [!] AUTH REQUIRED: Redirected to login page")
                        print(f"      [!] Dynamic phase will have limited coverage")
                        print(f"      [!] Re-run with auth cookies for full results")
                        self.skip_reason = 'auth_redirect'
                        break
                    
                    # Extract any newly discovered routes from the page
                    self._extract_routes_from_page(page)
                    
                    # ⭐ ENHANCEMENT 1.2: Active crawling - click buttons to trigger API calls
                    self._active_crawl_interactions(page)
                    
                    # Small delay to let any async requests complete
                    time.sleep(0.5)
                    
                    # Try to extract storage data (for state preservation)
                    self._extract_storage_data(page)
                    
                    # 🚀 LEGENDARY INTEGRATION 4: Extract WebSocket connections
                    ws_discovery.extract_captured_websockets(page)
                    
                except Exception as e:
                    # Don't let one failure stop the whole scan
                    continue
            
            # 🚀 LEGENDARY INTEGRATION 5: Add discovered WebSocket endpoints to results
            for ws_url in ws_discovery.websocket_endpoints:
                self.endpoints.append({
                    "endpoint": ws_url,
                    "method": "WS",
                    "parameters": [],
                    "type": "WEBSOCKET_DYNAMIC",
                    "source": "Playwright",
                    "classification": "WEBSOCKET_ENDPOINT",
                    "confidence_score": 90
                })
            
            if len(ws_discovery.websocket_endpoints) > 0:
                print(f"\n      [WebSocket] Discovered {len(ws_discovery.websocket_endpoints)} WebSocket connections")
                for ws_url in ws_discovery.websocket_endpoints[:5]:
                    print(f"        • {ws_url}")
            
            # Print captured WebSocket messages summary
            if ws_discovery.captured_messages:
                total_messages = sum(len(msgs) for msgs in ws_discovery.captured_messages.values())
                print(f"      [WebSocket] Captured {total_messages} messages from {len(ws_discovery.captured_messages)} connections")
            
            # ⭐ IMPROVEMENT 3: Extract intercepted API calls from runtime interception
            try:
                api_calls = page.evaluate("window.__api_calls || []")
                if api_calls:
                    print(f"      [Runtime] Intercepted {len(api_calls)} API calls")
                    for call in api_calls:
                        url = call.get('url', '')
                        method = call.get('method', 'GET')
                        call_type = call.get('type', 'unknown')
                        
                        # Add to endpoints if not already seen
                        req_key = f"{method}:{url}"
                        if req_key not in self.seen_requests and url:
                            self.seen_requests.add(req_key)
                            self.endpoints.append({
                                "endpoint": url,
                                "method": method,
                                "parameters": [],
                                "type": f"RUNTIME_{call_type.upper()}",
                                "source": "RuntimeInterception",
                                "classification": "API_ENDPOINT",
                                "confidence_score": 85
                            })
            except Exception as e:
                pass
            
            # ⭐ IMPROVEMENT 4: Extract and process lazy-loaded chunks
            try:
                lazy_chunks = page.evaluate("window.__lazy_chunks || []")
                if lazy_chunks:
                    print(f"      [LazyChunks] Found {len(lazy_chunks)} import() calls")
                    for chunk_path in lazy_chunks:
                        try:
                            # Resolve relative paths
                            if not chunk_path.startswith('http'):
                                chunk_url = urllib.parse.urljoin(self.target_url, chunk_path)
                            else:
                                chunk_url = chunk_path
                            
                            # Only process if not already analyzed
                            if chunk_url not in self.analyzed_js_files:
                                print(f"        • Analyzing: {chunk_url[:60]}...")
                                self.analyzed_js_files.add(chunk_url)
                                
                                # Fetch and analyze the chunk
                                try:
                                    import requests
                                    resp = requests.get(chunk_url, timeout=10, verify=False)
                                    chunk_code = resp.text
                                    
                                    # Feed it to the analyzer's feedback loop
                                    self.analyzer._analyze_js_content(chunk_code, chunk_url)
                                except Exception as e:
                                    pass
                        except Exception as e:
                            pass
            except Exception as e:
                pass
            
            print()  # New line after progress
            browser.close()

    def _extract_routes_from_page(self, page):
        """Extract route references from the current page"""
        try:
            # Extract from href attributes
            links = page.query_selector_all('a[href]')
            for link in links[:50]:  # Limit to prevent hanging
                try:
                    href = link.get_attribute('href')
                    if href:
                        clean = self._clean_route(href)
                        if clean and clean not in self.discovered_routes:
                            self.discovered_routes.add(clean)
                except:
                    pass
            
            # Extract from router-link or similar SPA navigation
            spa_links = page.query_selector_all('[routerlink], [ui-sref], [ng-href], [to]')
            for link in spa_links[:50]:
                try:
                    for attr in ['routerlink', 'ui-sref', 'ng-href', 'to']:
                        value = link.get_attribute(attr)
                        if value:
                            clean = self._clean_route(value)
                            if clean and clean not in self.discovered_routes:
                                self.discovered_routes.add(clean)
                except:
                    pass
            
            # 🔥 FINAL FIX 3.1: Extract routes from JavaScript window.location usage
            try:
                js_routes = page.evaluate('''() => {
                    const routes = [];
                    // Try to extract from window.__ROUTES__ or similar globals
                    if (window.__ROUTES__) routes.push(...window.__ROUTES__);
                    if (window.routes) routes.push(...window.routes);
                    if (window.app && window.app.routes) routes.push(...window.app.routes);
                    return routes.filter(r => typeof r === 'string');
                }''')
                for route in js_routes:
                    clean = self._clean_route(route)
                    if clean and clean not in self.discovered_routes:
                        self.discovered_routes.add(clean)
            except:
                pass
                    
        except:
            pass

    def _extract_storage_data(self, page):
        """Extract localStorage and sessionStorage for state preservation"""
        try:
            # This could be used to maintain auth state across navigations
            local_storage = page.evaluate('() => { return JSON.stringify(localStorage); }')
            session_storage = page.evaluate('() => { return JSON.stringify(sessionStorage); }')
            
            if local_storage:
                self.local_storage_data = json.loads(local_storage)
            if session_storage:
                self.session_storage_data = json.loads(session_storage)
        except:
            pass

    def _handle_response(self, response):
        """
        Handle all responses - the core of the feedback loop.
        
        This captures:
        1. New JavaScript files → feeds back to static analyzer
        2. API calls → adds to endpoints list
        3. Route references → adds to discovered routes
        """
        url = response.url
        
        # Skip ignored domains
        if any(b in url for b in IGNORED_DOMAINS):
            return
        
        # Skip if already seen
        if url in self.seen_requests:
            return
        
        self.seen_requests.add(url)
        
        try:
            content_type = response.headers.get("content-type", "").lower()
            
            # 1. FEEDBACK LOOP: Capture and analyze new JavaScript files
            if url.endswith('.js') or "javascript" in content_type:
                if url not in self.analyzer.analyzed_js_files:
                    self.analyzer.analyzed_js_files.add(url)
                    self.analyzed_js_files.add(url)
                    
                    try:
                        # Download JS content
                        code = response.text()
                        
                        if len(code) > 100:  # Ignore empty files
                            # CRITICAL: Feed back to static analyzer
                            self.analyzer.analyze_code_from_dynamic(code, url)
                    except:
                        pass
            
            # 2. Capture API calls (JSON responses)
            elif "application/json" in content_type:
                try:
                    endpoint = url.split('?')[0]
                    
                    # Try to infer HTTP method from request
                    method = "GET"  # Default assumption for responses
                    
                    # Extract parameters from query string
                    params = []
                    parsed = urllib.parse.urlparse(url)
                    if parsed.query:
                        params.extend(urllib.parse.parse_qs(parsed.query).keys())
                    
                    self.endpoints.append({
                        "endpoint": endpoint,
                        "method": method,
                        "parameters": list(set(params)),
                        "type": "DYNAMIC_API_CALL",
                        "source": "Browser",
                        "classification": "VERIFIED_API"
                    })
                except:
                    pass
            
            # 3. Extract route references from HTML responses
            elif "text/html" in content_type:
                try:
                    html = response.text()
                    
                    # Extract hash routes from HTML
                    hash_routes = re.findall(r'href=["\']([^"\']*#/[^"\']+)["\']', html)
                    for route in hash_routes:
                        clean = self._clean_route(route)
                        if clean and clean not in self.discovered_routes:
                            self.discovered_routes.add(clean)
                except:
                    pass
                    
        except:
            pass

    # ⭐ ENHANCEMENT 1.3: Request interceptor to capture XHR/Fetch API calls
    def _handle_request(self, request):
        """
        Intercept outgoing requests to capture API calls (XHR/Fetch).
        This captures the METHOD correctly from the actual request.
        """
        url = request.url
        
        # Skip ignored domains
        if any(b in url for b in IGNORED_DOMAINS):
            return
        
        # Only capture XHR and Fetch requests (these are API calls)
        if request.resource_type in ["xhr", "fetch"]:
            try:
                endpoint = url.split('?')[0]
                method = request.method
                
                # Extract parameters from query string
                params = []
                parsed = urllib.parse.urlparse(url)
                if parsed.query:
                    params.extend(urllib.parse.parse_qs(parsed.query).keys())
                
                # Only record if from our domain
                if self.domain in url:
                    self.endpoints.append({
                        "endpoint": endpoint,
                        "method": method,
                        "parameters": list(set(params)),
                        "type": "DYNAMIC_XHR_INTERCEPT",
                        "source": "Browser_Request",
                        "classification": "VERIFIED_API",
                        "confidence_score": 100
                    })
            except:
                pass

    # ⭐ ENHANCEMENT 1.4: Active crawling - interact with page elements
    def _active_crawl_interactions(self, page):
        """
        Actively interact with page elements to trigger lazy-loaded API calls.
        This is what Burp does - click buttons, open dropdowns, etc.
        ⭐ IMPROVEMENT 5: Enhanced with authenticated role simulation
        """
        try:
            # ⭐ IMPROVEMENT 5: Click admin, settings, and authenticated UI elements
            admin_selectors = [
                'a[href*="admin"]:visible',
                'a[href*="dashboard"]:visible', 
                'a[href*="settings"]:visible',
                'a[href*="profile"]:visible',
                'a[href*="management"]:visible',
                'button:has-text("Admin"):visible',
                'button:has-text("Settings"):visible',
                '[role="button"]:has-text("Menu"):visible',
                '.admin-link:visible',
                '.settings-link:visible',
                '.nav-item:visible',
                '.menu-item:visible'
            ]
            
            for selector in admin_selectors:
                try:
                    elements = page.query_selector_all(selector)
                    for elem in elements[:2]:  # Click up to 2 of each type
                        try:
                            elem.click(timeout=1000)
                            time.sleep(0.5)  # Wait for navigation/API calls
                        except:
                            pass
                except:
                    pass
            
            # 🚀 ULTIMATE FIX 1.1: More aggressive button clicking (increased from 10 to 20)
            buttons = page.query_selector_all("button:visible")
            for i, button in enumerate(buttons[:20]):  # INCREASED limit to discover more lazy APIs
                try:
                    button.click(timeout=1000)
                    time.sleep(0.3)  # Let API call complete
                except:
                    pass
            
            # 🚀 ULTIMATE FIX 1.2: Click submit/action buttons specifically (often trigger hidden APIs)
            action_buttons = page.query_selector_all("button[type='submit']:visible, input[type='submit']:visible, button.submit:visible, button.action:visible")
            for i, btn in enumerate(action_buttons[:10]):
                try:
                    btn.click(timeout=1000)
                    time.sleep(0.4)
                except:
                    pass
            
            # Click all clickable divs/spans (common in modern SPAs)
            clickables = page.query_selector_all("[ng-click]:visible, [onclick]:visible, .clickable:visible")
            for i, elem in enumerate(clickables[:5]):  # Limit to 5
                try:
                    elem.click(timeout=1000)
                    time.sleep(0.3)
                except:
                    pass
            
            # 🚀 ULTIMATE FIX 1.3: Click tabs (often lazy-load content)
            tabs = page.query_selector_all("[role='tab']:visible, .tab:visible, .nav-link:visible")
            for i, tab in enumerate(tabs[:8]):
                try:
                    tab.click(timeout=1000)
                    time.sleep(0.4)  # Give time for lazy-loaded APIs
                except:
                    pass
            
            # Open all dropdowns/selects (triggers data loading)
            selects = page.query_selector_all("select:visible")
            for select in selects[:5]:
                try:
                    select.click(timeout=500)
                    time.sleep(0.2)
                except:
                    pass
            
            # Hover over elements (can trigger lazy loading)
            hovers = page.query_selector_all("[data-hover]:visible, .has-dropdown:visible")
            for hover in hovers[:5]:
                try:
                    hover.hover(timeout=500)
                    time.sleep(0.2)
                except:
                    pass
            
            # 🚀 ULTIMATE FIX 1.4: Scroll to trigger infinite scroll / lazy loading
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                time.sleep(0.3)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(0.5)  # Give time for lazy-loaded content APIs
            except:
                pass
            
            # 🔥 FINAL FIX 3.2: Navigate internal links discovered on page
            try:
                internal_links = page.query_selector_all("a[href^='/']:visible, a[href^='#/']:visible")
                # 🚀 ULTIMATE FIX 1.5: Increased from 3 to 5 links for better route coverage
                for i, link in enumerate(internal_links[:5]):  # INCREASED for more discovery
                    try:
                        href = link.get_attribute('href')
                        if href and len(href) > 2:
                            # Build full URL
                            if href.startswith('/'):
                                target_url = f"{self.base_url}{href}"
                            else:
                                target_url = f"{self.base_url}/{href}"
                            
                            # Only navigate if not visited and is internal
                            if target_url not in self.seen_requests and self.domain in target_url:
                                try:
                                    page.goto(target_url, wait_until="networkidle", timeout=5000)
                                    time.sleep(0.5)  # Let any lazy-loaded API calls fire
                                    # Go back to continue crawling this page
                                    page.go_back(wait_until="networkidle", timeout=3000)
                                except:
                                    pass
                    except:
                        pass
            except:
                pass
                    
        except:
            pass  # Don't let interaction failures stop the scan


# ==============================================================================
# REPORT GENERATION & EXCEL CONVERSION
# ==============================================================================
def json_to_excel(input_file, output_file):
    """Converts JSON report to Excel format"""
    if not PANDAS_AVAILABLE:
        print("\n[!] Pandas not installed. Skipping Excel conversion.")
        return

    current_dir = os.getcwd()
    input_path = os.path.join(current_dir, input_file)
    output_path = os.path.join(current_dir, output_file)

    print(f"\n[PHASE 5] Excel Conversion")
    print(f"  Work Dir: {current_dir}")
    
    if not os.path.exists(input_path):
        print(f"  [X] ERROR: Input file '{input_file}' not found.")
        return

    try:
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        endpoints = data.get('endpoints', []) if isinstance(data, dict) else data
        rows = []
        
        for item in endpoints:
            params = item.get('parameters', [])
            params_formatted = ", ".join(params) if isinstance(params, list) else str(params)
            
            rows.append({
                "Endpoint": item.get('endpoint', ''),
                "Method": item.get('method', 'GET'),
                "Parameters": params_formatted,
                "Source File": item.get('source', 'Unknown'),
                "Type": item.get('type', ''),
                "Classification": item.get('classification', ''),
                "Confidence": item.get('confidence_score', '')
            })
            
        df = pd.DataFrame(rows)
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='API_Endpoints')
            worksheet = writer.sheets['API_Endpoints']
            for column in df:
                col_idx = df.columns.get_loc(column) + 1
                worksheet.column_dimensions[chr(64 + col_idx)].width = 25 
        
        print(f"  [+] SUCCESS! Created: {output_file}")
        
    except Exception as e:
        print(f"  [X] ERROR Converting to Excel: {str(e)}")

def save_report(static, dynamic, filename="results.json", source_maps=None, interceptor=None):
    print(f"\n[PHASE 4] Generating Report with Confidence Tiering")
    
    # Merge and deduplicate on URL-only key (not method+URL).
    # This collapses duplicates that arise when ARRAY_HARVEST and STATIC_CODE
    # find the same endpoint — ARRAY_HARVEST defaults to GET, STATIC_CODE gets
    # the real method. We keep the highest-confidence entry's method.
    merged = {}
    for item in static + dynamic:
        key = item['endpoint'].rstrip('/')          # URL-only key
        if key not in merged:
            merged[key] = dict(item)               # first occurrence
        else:
            existing = merged[key]
            # Dynamic verified calls always win
            if item.get('type', '').startswith('DYNAMIC'):
                existing['classification'] = 'VERIFIED_API'
                existing['confidence_score'] = 100
                existing['type'] = item['type']
                existing['method'] = item.get('method', existing['method'])
            else:
                new_conf = item.get('confidence_score', 0)
                old_conf = existing.get('confidence_score', 0)
                if new_conf > old_conf:
                    # Higher confidence: take its method and type
                    existing['method'] = item['method']
                    existing['type'] = item['type']
                    existing['confidence_score'] = new_conf
                elif item.get('method', 'GET') != 'GET' and existing.get('method') == 'GET':
                    # Specific method always beats default GET fallback
                    existing['method'] = item['method']
            # Always merge parameters
            existing['parameters'] = sorted(list(set(
                existing.get('parameters', []) + item.get('parameters', [])
            )))[:10]
    
    # ⭐ ENHANCEMENT 3.3: Final filtering pass - remove low-confidence noise
    # This is the last line of defense to ensure clean output
    pre_filter_count = len(merged)
    filtered_results = []
    
    for endpoint in merged.values():
        conf_score = endpoint.get('confidence_score', 0)
        classification = endpoint.get('classification', '')
        is_vendor = endpoint.get('origin', {}).get('is_vendor', False)
        
        # Skip vendor garbage with confidence_score == 0
        if conf_score == 0 and is_vendor:
            continue
        
        # 🚀 ULTIMATE FIX 2.5: Raised from 20 to 40 for final filtering
        if conf_score < 40 and classification in ["LIBRARY_ARTIFACT", "NOISE_CANDIDATE"]:
            continue
        
        # 🚀 ULTIMATE FIX 2.6: Also filter vendor sources with confidence < 40 in final pass
        if conf_score < 40 and is_vendor:
            continue
        
        # Skip external references unless high confidence
        if classification == "EXTERNAL_REFERENCE" and conf_score < 50:
            continue
        
        filtered_results.append(endpoint)
    
    filtered_count = pre_filter_count - len(filtered_results)
    if filtered_count > 0:
        print(f"  [FILTER] Removed {filtered_count} low-confidence vendor/noise endpoints")
    
    # Sort by Confidence Score
    results = sorted(filtered_results, key=lambda x: x.get('confidence_score', 0), reverse=True)
    
    # Group by Category for Summary
    summary = defaultdict(int)
    for r in results:
        summary[r.get('classification', 'UNKNOWN')] += 1
        
    report = {
        "scan_metadata": {
            "scanner": "Advanced Endpoint Scanner - Enterprise Edition",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(results),
            "dynamic_phase": {
                "ran": PLAYWRIGHT_AVAILABLE,
                "endpoints_found": len(dynamic),
                "skip_reason": getattr(interceptor, 'skip_reason', None) if interceptor else (
                    'playwright_not_installed' if not PLAYWRIGHT_AVAILABLE else None
                ),
                "routes_visited": len(getattr(interceptor, 'discovered_routes', set())) if interceptor else 0,
            }
        },
        "summary": dict(summary),
        "source_maps_found": len(source_maps) if source_maps else 0,
        "endpoints": results,
        "discovered_source_maps": source_maps if source_maps else []
    }
    
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*70}\nSCAN COMPLETE\n{'='*70}")
    print(f"  Total Endpoints:          {len(results)}")
    print(f"  High Confidence:          {summary['HIGH_CONFIDENCE']}")
    print(f"  Medium Confidence:        {summary['MEDIUM_CONFIDENCE']}")
    print(f"  Low Confidence:           {summary['LOW_CONFIDENCE']}")
    print(f"  Verified Runtime:         {summary['VERIFIED_API']}")
    print(f"  Vendor/Artifacts:         {summary['LIBRARY_ARTIFACT'] + summary['NOISE_CANDIDATE']}")
    # 🚀 LEGENDARY INTEGRATION 6: Show GraphQL and WebSocket counts
    if summary.get('GRAPHQL_API', 0) > 0:
        print(f"  GraphQL Operations:       {summary['GRAPHQL_API']}")
    if summary.get('WEBSOCKET_ENDPOINT', 0) > 0:
        print(f"  WebSocket Endpoints:      {summary['WEBSOCKET_ENDPOINT']}")
    print(f"\n[FILE] JSON saved: {filename}")
    
    json_to_excel(filename, 'results.xlsx')

# ==============================================================================
# SOURCE MAP ENGINE - LEGITIMATE PASSIVE EXTRACTION
# ==============================================================================

class SourceMapEngine:
    """
    Passive source map harvester - only extracts what's publicly exposed.
    Detects, downloads, and extracts source maps from discovered JS files.
    """
    
    def __init__(self, session, base_url, output_dir="sourcemaps"):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.output_dir = output_dir
        self.maps_dir = os.path.join(output_dir, "maps")
        self.extracted_dir = os.path.join(output_dir, "extracted")
        
        # Create directories
        os.makedirs(self.maps_dir, exist_ok=True)
        os.makedirs(self.extracted_dir, exist_ok=True)
        
        self.source_map_urls = []
        self.extracted_files = []
    
    def harvest(self, js_files):
        """
        Main entry point - detects, downloads, extracts source maps.
        Returns list of extracted source file paths and found map URLs.
        """
        print(f"\n{'='*70}")
        print(f"PHASE 1.5: SOURCE MAP HARVESTING")
        print(f"{'='*70}")
        
        # Step 1: Detect source maps (passive only)
        print(f"\n[STEP 1] Detection")
        self._detect_enhanced_manifests()
        self._detect_from_js_files(js_files)
        self._derive_passive_maps(js_files)  # NEW: Passive Rule
        
        if not self.source_map_urls:
            print(f"  [!] No source maps found")
            return [], []
        
        print(f"  [+] Found {len(self.source_map_urls)} source map(s)")
        
        # Step 2: Download source maps
        print(f"\n[STEP 2] Download")
        downloaded = self._download_maps()
        print(f"  [+] Downloaded {downloaded} map file(s)")
        
        # Step 3: Check for inline maps
        print(f"\n[STEP 3] Inline Maps")
        self._extract_inline_source_maps(js_files)
        
        # Step 4: Extract source code
        print(f"\n[STEP 4] Extraction")
        self._extract_all_maps()
        print(f"  [+] Extracted {len(self.extracted_files)} source file(s)")
        
        return self.extracted_files, self.source_map_urls
    
    def _derive_passive_maps(self, js_files):
        """
        Deterministically derive .map URLs, but only for files where heuristics
        suggest a source map likely exists. Skips known CDN/library domains entirely.
        NO new HTTP requests — purely URL manipulation.
        """
        CDN_DOMAINS = {
            'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
            'fonts.googleapis.com', 'ajax.googleapis.com',
            'code.jquery.com', 'maxcdn.bootstrapcdn.com',
        }
        
        print(f"  [*] Checking {len(js_files)} JS files for heuristic map candidates...")
        count = 0
        
        for js_url in js_files:
            # Skip known CDN/library hosts — they never serve app source maps
            try:
                domain = urllib.parse.urlparse(js_url).netloc
            except Exception:
                continue
            if any(cdn in domain for cdn in CDN_DOMAINS):
                continue
            
            filename = js_url.rstrip('/').split('/')[-1].lower()
            
            # Heuristic 1: URL contains a content hash (webpack prod bundle pattern)
            # e.g. main.abc123ef.chunk.js, app.7b57cd2c.js
            has_hash = bool(re.search(r'\.[a-f0-9]{7,}(?:\.chunk)?\.js(?:\?|$)', js_url, re.IGNORECASE))
            
            # Heuristic 2: filename contains 'chunk' (webpack lazy-loaded chunk)
            has_chunk = 'chunk' in filename
            
            # Heuristic 3: common app bundle names
            has_bundle_name = any(x in filename for x in ['main.', 'bundle.', 'app.', 'vendor.', 'runtime.', 'index.'])
            
            if has_hash or has_chunk or has_bundle_name:
                map_url = js_url + ".map"
                if map_url not in self.source_map_urls:
                    self.source_map_urls.append(map_url)
                    count += 1
        
        print(f"  [+] Derived {count} heuristic map URL candidates (from {len(js_files)} files)")

    def _detect_enhanced_manifests(self):
        """
        [NEW] Parse HTML for manifest links and check common SPA paths.
        """
        # 1. Fetch root HTML to look for <link rel="manifest">
        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            if resp.status_code == 200:
                # Regex for manifest link
                link_match = re.search(r'<link[^>]+rel=["\']manifest["\'][^>]+href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                if link_match:
                    manifest_href = link_match.group(1)
                    full_url = self._build_absolute_url(manifest_href)
                    print(f"  [+] Found manifest in HTML: {manifest_href}")
                    self._check_and_parse_manifest(full_url)
        except:
            pass

        # 2. Check common paths
        common_paths = [
            "manifest.json", "asset-manifest.json",
            "static/manifest.json", "static/asset-manifest.json",
            "build/manifest.json", "build/asset-manifest.json",
            "assets/manifest.json", "assets/asset-manifest.json",
            "dist/manifest.json", "public/manifest.json",
            "static/js/manifest.json", "static/js/asset-manifest.json"
        ]
        
        for path in common_paths:
            full_url = f"{self.base_url}/{path}"
            self._check_and_parse_manifest(full_url)

    def _check_and_parse_manifest(self, manifest_url):
        """Fetch and parse manifest file for .map references"""
        try:
            resp = self.session.get(manifest_url, timeout=5, verify=False)
            if resp.status_code == 200:
                try:
                    manifest = resp.json()
                    files = manifest.get('files', manifest)
                    
                    found = False
                    for key, value in files.items():
                        if isinstance(value, str) and value.endswith('.map'):
                            map_url = self._build_absolute_url(value)
                            if map_url not in self.source_map_urls:
                                self.source_map_urls.append(map_url)
                                found = True
                    
                    if found:
                        print(f"  [+] Found source maps in manifest: {manifest_url}")
                except:
                    pass
        except:
            pass
    
    def _detect_from_js_files(self, js_files):
        """Detect source maps from //# sourceMappingURL comments"""
        print(f"  [*] Scanning {len(js_files)} JS files for sourceMappingURL...")
        
        for js_url in js_files[:50]:  # Limit to first 50 files
            try:
                resp = self.session.get(js_url, timeout=10, verify=False)
                if resp.status_code == 200:
                    content = resp.text[-500:]  # Check last 500 chars only
                    
                    # Look for sourceMappingURL
                    matches = re.findall(r'//[@#]\s*sourceMappingURL=(.+?)(?:\s|$)', content)
                    
                    for match in matches:
                        match = match.strip()
                        
                        # Skip data URIs (handled separately)
                        if match.startswith('data:'):
                            continue
                        
                        # Build absolute URL
                        if match.startswith('http'):
                            map_url = match
                        elif match.startswith('/'):
                            map_url = f"{self.base_url}{match}"
                        else:
                            # Relative to JS file
                            js_base = js_url.rsplit('/', 1)[0]
                            map_url = f"{js_base}/{match}"
                        
                        if map_url not in self.source_map_urls:
                            self.source_map_urls.append(map_url)
            except:
                continue
    
    def _extract_inline_source_maps(self, js_files):
        """Extract source maps embedded as base64 data URIs"""
        import base64
        
        for js_url in js_files[:50]:
            try:
                resp = self.session.get(js_url, timeout=10, verify=False)
                if resp.status_code != 200:
                    continue
                
                # Look for data URI source maps
                match = re.search(
                    r'//[@#]\s*sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)',
                    resp.text
                )
                
                if match:
                    try:
                        decoded = base64.b64decode(match.group(1))
                        source_map = json.loads(decoded)
                        
                        # Save to file
                        filename = hashlib.md5(js_url.encode()).hexdigest() + '_inline.js.map'
                        filepath = os.path.join(self.maps_dir, filename)
                        
                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump(source_map, f, indent=2)
                        
                        print(f"    ✓ INLINE MAP: {os.path.basename(js_url)}")
                        
                        # Extract immediately
                        self._extract_single_map(filepath)
                    except:
                        continue
            except:
                continue
    
    def _download_maps(self):
        """Download all detected source maps"""
        downloaded = 0
        
        # De-duplicate URLs
        unique_urls = list(set(self.source_map_urls))
        self.source_map_urls = unique_urls
        
        for map_url in self.source_map_urls:
            try:
                resp = self.session.get(map_url, timeout=15, verify=False)
                if resp.status_code == 200:
                    # Generate filename from URL
                    filename = hashlib.md5(map_url.encode()).hexdigest() + '.js.map'
                    filepath = os.path.join(self.maps_dir, filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(resp.text)
                    
                    downloaded += 1
                    print(f"    ✓ {map_url.split('/')[-1]}")
            except Exception as e:
                # Silent fail for speculative maps is fine, show only if verbose or errors matter
                # print(f"    ✗ Failed: {map_url.split('/')[-1]}")
                pass
        
        return downloaded
    
    def _extract_all_maps(self):
        """Extract source code from all downloaded .map files"""
        map_files = [f for f in os.listdir(self.maps_dir) if f.endswith('.js.map')]
        
        for map_file in map_files:
            map_path = os.path.join(self.maps_dir, map_file)
            self._extract_single_map(map_path)
    
    def _extract_single_map(self, map_path):
        """Extract source code from a single .map file"""
        try:
            with open(map_path, 'r', encoding='utf-8') as f:
                source_map = json.load(f)
            
            sources = source_map.get('sources', [])
            contents = source_map.get('sourcesContent', [])
            
            # Handle index maps (v3 spec)
            if 'sections' in source_map:
                self._process_source_map_index(source_map, map_path)
                return
            
            for i, source_path in enumerate(sources):
                if i >= len(contents) or not contents[i]:
                    continue
                
                # Clean and sanitize path
                clean_path = self._sanitize_source_path(source_path)
                if not clean_path:
                    continue
                
                # Build output path
                output_path = os.path.join(self.extracted_dir, clean_path)
                
                # Create directories
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Write source file
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(contents[i])
                    
                    self.extracted_files.append(output_path)
                except:
                    pass  # Skip files that fail to write
        
        except Exception as e:
            # print(f"    ✗ Failed to extract {os.path.basename(map_path)}")
            pass
    
    def _process_source_map_index(self, source_map, map_path):
        """Handle source map index files (v3 spec)"""
        sections = source_map.get('sections', [])
        print(f"    📑 INDEX MAP: {os.path.basename(map_path)} ({len(sections)} sections)")
        
        for section in sections:
            if 'url' in section:
                # Download sub-map
                sub_map_url = self._build_absolute_url(section['url'])
                
                try:
                    resp = self.session.get(sub_map_url, timeout=10, verify=False)
                    if resp.status_code == 200:
                        # Save sub-map
                        sub_filename = hashlib.md5(sub_map_url.encode()).hexdigest() + '.js.map'
                        sub_filepath = os.path.join(self.maps_dir, sub_filename)
                        
                        with open(sub_filepath, 'w', encoding='utf-8') as f:
                            f.write(resp.text)
                        
                        # Recursively extract
                        self._extract_single_map(sub_filepath)
                        print(f"      ✓ SUB-MAP: {section['url']}")
                except:
                    continue
    
    def _sanitize_source_path(self, source_path):
        """
        Clean webpack:// paths and remove invalid characters.
        Returns None for paths we should skip.
        """
        # Remove webpack prefix
        clean = re.sub(r'^webpack:\/\/[^/]*\/', '', source_path)
        clean = re.sub(r'^webpack:\/\/\/', '', clean)
        clean = clean.lstrip('/')
        
        # Skip node_modules - we don't care about dependencies
        if 'node_modules' in clean:
            return None
        
        # Skip webpack internals
        if clean.startswith('webpack/'):
            return None
        
        # Skip if path is too short (likely garbage)
        if len(clean) < 3:
            return None

        # Skip developer absolute paths embedded in source maps.
        # These are local machine paths that got baked into the map's "sources" array.
        # Concatenating them with the base URL produces nonsense like:
        #   https://storex.ril.com/Users/prasad.nandoskar/Documents/...
        if re.match(r'^/?(?:Users|home|[A-Z]:[/\\])', clean, re.IGNORECASE):
            return None
        
        # Remove query params
        clean = clean.split('?')[0]
        
        # Sanitize invalid filename characters
        clean = re.sub(r'[<>:"|*?]', '_', clean)
        
        # Replace backslashes with forward slashes
        clean = clean.replace('\\', '/')
        
        return clean
    
    def _build_absolute_url(self, path):
        """Build absolute URL from relative path"""
        if path.startswith('http'):
            return path
        elif path.startswith('/'):
            return f"{self.base_url}{path}"
        else:
            return f"{self.base_url}/{path}"


# ==============================================================================
# HELPER FUNCTION TO INJECT SOURCEMAP ENGINE
# ==============================================================================

def run_sourcemap_harvest(session, target, js_files, analyzer):
    """
    Wrapper function to run source map harvesting and feed results
    into the existing analyzer pipeline. NON-INTRUSIVE.
    """
    engine = SourceMapEngine(session, target)
    extracted_files, found_maps = engine.harvest(js_files)
    
    if extracted_files:
        print(f"\n[SOURCEMAP] Feeding {len(extracted_files)} files into analyzer...")
        
        for filepath in extracted_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                # Use existing analyzer method - NO NEW LOGIC
                analyzer.analyze_code_from_dynamic(code, filepath)
            except:
                pass  # Skip files that fail to read
        
        print(f"[SOURCEMAP] Integration complete")
    
    return extracted_files, found_maps


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced Endpoint Scanner - Enhanced Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python scanner.py --target https://example.com
  
  # Scan with cookies
  python scanner.py --target https://example.com
  
  # Deep scan with more routes and depth
  python scanner.py --target https://example.com --max-routes 50 --max-depth 5
  
  # Quick scan (fewer routes, less depth)
  python scanner.py --target https://example.com --max-routes 10 --max-depth 2 --no-cookies
        """
    )
    
    parser.add_argument('--target', type=str, help='Target URL')
    parser.add_argument('--no-cookies', action='store_true', help='Skip cookie input')
    # 💎 COOKIE FIX 1: Add --cookies command-line argument
    parser.add_argument('--cookies', type=str, help='Cookies for authenticated scanning (format: "name=value; name2=value2")', default=None)
    parser.add_argument('--output', type=str, default='results.json', help='Output file path')
    parser.add_argument('--max-routes', type=int, default=25, help='Max routes to visit per depth (default: 25)')
    parser.add_argument('--max-depth', type=int, default=3, help='Max navigation depth (default: 3)')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')
    
    return parser.parse_args()

# ==============================================================================
# MAIN (WITH COMPREHENSIVE ERROR HANDLING)
# ==============================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("ADVANCED ENDPOINT SCANNER - ENHANCED EDITION")
    print("Recursive lazy-loading discovery for modern SPAs")
    print("=" * 70 + "\n")
    
    try:
        # Parse command-line arguments
        args = parse_args()
        
        # Get target URL
        if args.target:
            target = args.target
            print(f"Target: {target}")
        else:
            target = input("Target URL: ").strip()
            if not target:
                print("[X] No URL provided")
                sys.exit(1)
        
        if not target.startswith("http"):
            target = "https://" + target
        
        # DEBUG: Test connection BEFORE starting scan
        print(f"\n[DEBUG] Testing connection to {target}...")
        try:
            test_resp = requests.get(target, timeout=10, verify=False)
            print(f"[DEBUG] ✓ Connection successful (Status: {test_resp.status_code})")
            if test_resp.status_code == 403:
                print(f"[!] WARNING: Got 403 Forbidden. Site may block python-requests.")
                print(f"[!] Consider using different User-Agent or checking for WAF/Cloudflare.")
        except requests.exceptions.SSLError as e:
            print(f"[!] SSL Error: {e}")
            print(f"[!] Continuing with verify=False...")
        except requests.exceptions.ConnectionError as e:
            print(f"[X] FATAL: Cannot connect to target: {e}")
            print(f"[X] Check your internet connection or if the site is down.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Connection test error: {e}")
            print(f"[!] Attempting to continue anyway...")
        
        # Handle cookies
        cookies = {}
        # 💎 COOKIE FIX 2: Check if --cookies argument was provided
        if args.cookies:
            # Parse cookies from command line (format: "name=value; name2=value2")
            print(f"\n[COOKIES] Using cookies from command line")
            for cookie_pair in args.cookies.split(';'):
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    name, value = cookie_pair.split('=', 1)
                    cookies[name.strip()] = value.strip()
                    print(f"  • {name.strip()}")
        elif not args.no_cookies:
            cookie_choice = input("\nAdd cookies? (y/n): ").strip().lower()
            if cookie_choice == 'y':
                print("Enter cookies (press Enter with empty name to finish):")
                while True:
                    name = input("  Cookie name: ").strip()
                    if not name:
                        break
                    value = input("  Cookie value: ").strip()
                    cookies[name] = value
        
        # Setup session with realistic User-Agent
        session = requests.Session()
        session.cookies.update(cookies)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        start_time = time.time()
        
        print("\n" + "="*70)
        print("STARTING ENHANCED SCAN")
        print("="*70)
        
        # Phase 1: Discovery
        hunter = EnhancedFederationHunter(session, target)
        js_files, json_files = hunter.run()
        
        # DEBUG CHECK: Warn if no JS files found
        if len(js_files) == 0:
            print("\n" + "!"*70)
            print("WARNING: No JavaScript files were found in Phase 1!")
            print("!"*70)
            print("\nPossible causes:")
            print("  1. The site is a pure SPA that renders <script> tags dynamically")
            print("  2. The site blocked the scraper (WAF/Cloudflare/403)")
            print("  3. The URL points to a directory listing, not an HTML page")
            print("  4. The site requires authentication cookies")
            
            if PLAYWRIGHT_AVAILABLE:
                print("\n[*] Playwright is available - continuing to Phase 3 for dynamic discovery")
            else:
                print("\n[!] Playwright not installed. Install it for better SPA support:")
                print("    pip install playwright")
                print("    python -m playwright install chromium")
            
            print("\nContinuing scan with limited data...\n")
        
        # ⭐ PHASE 1.5: SOURCE MAP HARVESTING (NEW - PURE ADDITION)
        # Create analyzer instance BEFORE sourcemap harvest
        analyzer = EnhancedStaticAnalyzer(session, target)

        # Run source map harvest (non-intrusive)
        extracted_files, found_maps = run_sourcemap_harvest(session, target, js_files, analyzer)

        # Phase 2: Static Analysis
        # analyzer already created above, just run scan
        static_endpoints = analyzer.scan(js_files, json_files)
        
        if len(static_endpoints) == 0 and len(js_files) > 0:
            print("\n[!] WARNING: Found JS files but extracted 0 endpoints")
            print("[!] The JavaScript might be heavily obfuscated or use dynamic imports")
        
        # Phase 3: Dynamic Interception with Feedback Loop
        interceptor = DynamicInterceptor(
            target, 
            analyzer,  # Pass analyzer for feedback loop
            cookies,
            max_routes=args.max_routes,
            max_depth=args.max_depth
        )
        dynamic_endpoints = interceptor.run(static_endpoints)
        
        # Add any endpoints discovered during dynamic phase back to static
        static_endpoints.extend(analyzer.endpoints)
        
        elapsed = time.time() - start_time
        print(f"\n[TIME] Total scan time: {elapsed:.1f}s")
        
        # Phase 4 & 5: Save results
        output_file = args.output if hasattr(args, 'output') else 'results.json'
        save_report(static_endpoints, dynamic_endpoints, output_file, source_maps=found_maps, interceptor=interceptor)
        
        # Print absolute path to results
        abs_path = os.path.abspath(output_file)
        print(f"\n[RESULTS] Saved to: {abs_path}")
        
        # Final summary
        total = len(set([f"{e['method']}:{e['endpoint']}" for e in static_endpoints + dynamic_endpoints]))
        if total == 0:
            print("\n" + "="*70)
            print("NO ENDPOINTS FOUND - TROUBLESHOOTING")
            print("="*70)
            print("\nThe scan completed but found 0 endpoints. This usually means:")
            print("  1. The target blocks automated scrapers (check for 403 errors above)")
            print("  2. The site is a pure SPA with no initial JavaScript in HTML")
            print("  3. All endpoints are dynamically loaded and Playwright is not installed")
            print("\nSolutions:")
            print("  • Add authentication cookies if the site requires login")
            print("  • Install Playwright: pip install playwright && python -m playwright install chromium")
            print("  • Try a different target URL (e.g., a specific page instead of root)")
            print("  • Check if the site has a WAF/Cloudflare protection")
        
    except KeyboardInterrupt:
        print("\n\n[X] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[X] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)