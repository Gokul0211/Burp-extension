#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Endpoint Scanner - Burp Suite Extension
Integrates the Advanced Endpoint Scanner with Burp Suite
Supports cookie extraction and authentication
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JButton, JTextField, JLabel, JScrollPane, 
                          JTable, JSplitPane, JMenuItem, JTextArea, JCheckBox,
                          BoxLayout, BorderFactory, JFileChooser, SwingUtilities,
                          JProgressBar, Box)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, GridLayout, Dimension, Color, Font
from java.awt.event import ActionListener
from java.io import File
import json
import subprocess
import os
import sys
import threading
import time

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    """Main Burp extension class"""
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Endpoint Scanner")
        
        # Initialize storage
        self.endpoints = []
        self.scan_history = []
        self.js_queue = []
        self.config = {
            'auto_scan': False,
            'scanner_path': None,
            'python_path': 'python3' # Ensure python3 is in your system PATH or provide full path here
        }
        
        # Find scanner script
        self._find_scanner_script()
        
        # Create UI
        self._create_ui()
        
        # Register callbacks
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        
        # Add custom tab
        callbacks.addSuiteTab(self)
        
        # Print status
        self._print_to_output("=" * 70)
        self._print_to_output("ENDPOINT SCANNER - Burp Suite Extension")
        self._print_to_output("=" * 70)
        self._print_to_output("[+] Extension loaded successfully")
        if self.config['scanner_path']:
            self._print_to_output("[+] Scanner found: %s" % self.config['scanner_path'])
        else:
            self._print_to_output("[-] WARNING: Scanner script not found!")
            self._print_to_output("[-] Please place endpoint_scanner.py in the same directory")
        self._print_to_output("=" * 70)
        
    def _print_to_output(self, message):
        """Print to Burp's extension output"""
        try:
            print(message)
        except:
            pass
    
    def _find_scanner_script(self):
        """Find the endpoint scanner script"""
        # Get extension directory
        try:
            ext_file = sys.argv[0] if sys.argv else __file__
            ext_dir = os.path.dirname(os.path.abspath(ext_file))
        except:
            ext_dir = os.getcwd()
        
        # Check common locations
        search_paths = [
            os.path.join(ext_dir, 'stoic.py'),
            os.path.join(ext_dir, 'endpoint_scanner.py'),
            os.path.join(ext_dir, 'endpoint_scanner_core.py'),
            os.path.expanduser('~/stoic.py'),
            os.path.expanduser('~/endpoint_scanner.py'),
            os.path.expanduser('~/Desktop/endpoint_scanner.py'),
            './stoic.py',
            './endpoint_scanner.py'
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                self.config['scanner_path'] = os.path.abspath(path)
                self._print_to_output("[+] Found scanner: %s" % path)
                return
        
        self._print_to_output("[-] Scanner not found in: %s" % ext_dir)
    
    def _create_ui(self):
        """Create the extension UI"""
        self.panel = JPanel(BorderLayout())
        
        # Top panel - Controls
        top_panel = self._create_control_panel()
        self.panel.add(top_panel, BorderLayout.NORTH)
        
        # Center panel - Results
        center_panel = self._create_results_panel()
        self.panel.add(center_panel, BorderLayout.CENTER)
        
        # Bottom panel - Actions
        bottom_panel = self._create_action_panel()
        self.panel.add(bottom_panel, BorderLayout.SOUTH)
    
    def _create_control_panel(self):
        """Create control panel with inputs"""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Scan Configuration"))
        
        # URL input row
        url_panel = JPanel(BorderLayout())
        url_panel.add(JLabel("Target URL: "), BorderLayout.WEST)
        self.url_field = JTextField(40)
        url_panel.add(self.url_field, BorderLayout.CENTER)
        
        # Scan button
        self.scan_button = JButton("Start Scan", actionPerformed=self.on_scan_clicked)
        self.scan_button.setBackground(Color(0, 120, 215))
        self.scan_button.setForeground(Color.WHITE)
        url_panel.add(self.scan_button, BorderLayout.EAST)
        
        panel.add(url_panel)
        panel.add(Box.createRigidArea(Dimension(0, 5)))
        
        # Cookie input row
        cookie_panel = JPanel(BorderLayout())
        cookie_panel.add(JLabel("Cookies (optional): "), BorderLayout.WEST)
        self.cookie_field = JTextField(40)
        self.cookie_field.setToolTipText("Format: name1=value1; name2=value2")
        cookie_panel.add(self.cookie_field, BorderLayout.CENTER)
        
        # Button to extract cookies from Burp
        extract_cookies_btn = JButton("Extract from Burp", actionPerformed=self.on_extract_cookies)
        extract_cookies_btn.setToolTipText("Extract cookies from selected request in Burp")
        cookie_panel.add(extract_cookies_btn, BorderLayout.EAST)
        
        panel.add(cookie_panel)
        panel.add(Box.createRigidArea(Dimension(0, 5)))
        
        # Options row
        options_panel = JPanel(GridLayout(1, 3))
        self.auto_scan_checkbox = JCheckBox("Auto-scan JS files", False)
        # FIX: Added the listener class at the bottom of the file
        self.auto_scan_checkbox.addActionListener(AutoScanListener(self))
        self.skip_dynamic_checkbox = JCheckBox("Skip dynamic analysis (faster)", True)
        self.verbose_checkbox = JCheckBox("Verbose output", False)
        
        options_panel.add(self.auto_scan_checkbox)
        options_panel.add(self.skip_dynamic_checkbox)
        options_panel.add(self.verbose_checkbox)
        
        panel.add(options_panel)
        panel.add(Box.createRigidArea(Dimension(0, 5)))
        
        # Max routes / max depth row
        scan_params_panel = JPanel()
        scan_params_panel.setLayout(BoxLayout(scan_params_panel, BoxLayout.X_AXIS))
        scan_params_panel.add(JLabel("Max Routes: "))
        self.max_routes_field = JTextField("25", 5)
        self.max_routes_field.setMaximumSize(Dimension(60, 25))
        self.max_routes_field.setToolTipText("Max routes to visit per depth (default: 25)")
        scan_params_panel.add(self.max_routes_field)
        scan_params_panel.add(Box.createRigidArea(Dimension(15, 0)))
        scan_params_panel.add(JLabel("Max Depth: "))
        self.max_depth_field = JTextField("3", 3)
        self.max_depth_field.setMaximumSize(Dimension(60, 25))
        self.max_depth_field.setToolTipText("Max navigation depth (default: 3)")
        scan_params_panel.add(self.max_depth_field)
        scan_params_panel.add(Box.createHorizontalGlue())
        
        panel.add(scan_params_panel)
        panel.add(Box.createRigidArea(Dimension(0, 5)))
        
        # Progress bar
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setStringPainted(True)
        self.progress_bar.setString("Ready")
        panel.add(self.progress_bar)
        
        # Status label
        self.status_label = JLabel("Status: Ready")
        self.status_label.setFont(Font("Dialog", Font.BOLD, 12))
        panel.add(self.status_label)
        
        return panel
    
    def _create_results_panel(self):
        """Create results table panel"""
        # Column names
        columns = ["Method", "Endpoint", "Type", "Classification", "Source", "Parameters"]
        self.table_model = DefaultTableModel(columns, 0)
        
        # Table
        self.results_table = JTable(self.table_model)
        self.results_table.setAutoCreateRowSorter(True)
        self.results_table.setFillsViewportHeight(True)
        
        # Set column widths
        column_model = self.results_table.getColumnModel()
        column_model.getColumn(0).setPreferredWidth(70)   # Method
        column_model.getColumn(1).setPreferredWidth(400)  # Endpoint
        column_model.getColumn(2).setPreferredWidth(150)  # Type
        column_model.getColumn(3).setPreferredWidth(120)  # Classification
        column_model.getColumn(4).setPreferredWidth(200)  # Source
        column_model.getColumn(5).setPreferredWidth(150)  # Parameters
        
        # Scroll pane for table
        table_scroll = JScrollPane(self.results_table)
        
        # Details panel
        details_panel = JPanel(BorderLayout())
        details_panel.setBorder(BorderFactory.createTitledBorder("Scan Output"))
        self.output_text = JTextArea(10, 40)
        self.output_text.setEditable(False)
        self.output_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        details_scroll = JScrollPane(self.output_text)
        details_panel.add(details_scroll, BorderLayout.CENTER)
        
        # Split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, details_panel)
        split_pane.setResizeWeight(0.7)
        
        return split_pane
    
    def _create_action_panel(self):
        """Create action buttons panel"""
        panel = JPanel()
        
        # Export buttons
        self.export_json_button = JButton("Export JSON", actionPerformed=self.on_export_json)
        self.export_txt_button = JButton("Export TXT", actionPerformed=self.on_export_txt)
        self.send_to_sitemap_button = JButton("Add to Site Map", actionPerformed=self.on_send_to_sitemap)
        self.send_to_repeater_button = JButton("Send to Repeater", actionPerformed=self.on_send_to_repeater)
        self.clear_button = JButton("Clear Results", actionPerformed=self.on_clear_results)
        
        panel.add(self.export_json_button)
        panel.add(self.export_txt_button)
        panel.add(self.send_to_sitemap_button)
        panel.add(self.send_to_repeater_button)
        panel.add(self.clear_button)
        
        # Stats label
        self.stats_label = JLabel("Total endpoints: 0")
        self.stats_label.setFont(Font("Dialog", Font.BOLD, 11))
        panel.add(self.stats_label)
        
        return panel
    
    # ITab implementation
    def getTabCaption(self):
        """Return tab name"""
        return "Endpoint Scanner"
    
    def getUiComponent(self):
        """Return UI component"""
        return self.panel
    
    # IHttpListener implementation
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages (passive scanning)"""
        if not self.auto_scan_checkbox.isSelected():
            return
        
        if messageIsRequest:
            return
        
        # Get response
        response = messageInfo.getResponse()
        if response is None:
            return
        
        # Check if it's JavaScript
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        is_javascript = False
        for header in headers:
            header_lower = str(header).lower()
            if 'content-type' in header_lower:
                if 'javascript' in header_lower or 'application/json' in header_lower:
                    is_javascript = True
                    break
        
        if not is_javascript:
            url = str(messageInfo.getUrl())
            if not url.endswith('.js'):
                return
        
        # Queue for scanning
        url = str(messageInfo.getUrl())
        if url not in [item['url'] for item in self.js_queue]:
            self.js_queue.append({'url': url, 'time': time.time()})
            self._append_output("[Auto] Queued: %s" % url)
    
    # IContextMenuFactory implementation
    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []
        
        # Get selected messages
        messages = invocation.getSelectedMessages()
        if messages is None or len(messages) == 0:
            return None
        
        # Add "Scan for Endpoints" menu item
        menu_item = JMenuItem("Scan for Endpoints")
        menu_item.addActionListener(ScanActionListener(self, messages))
        menu_items.append(menu_item)
        
        return menu_items
    
    # Action handlers
    def on_extract_cookies(self, event):
        """Extract cookies from selected Burp request"""
        try:
            # Get the currently selected message in Burp
            http_traffic = self._callbacks.getSelectedMessages()
            
            if not http_traffic or len(http_traffic) == 0:
                self._update_status("No request selected in Burp", True)
                self._append_output("\n[!] Please select a request in Burp first")
                return
            
            # Get the first selected message
            message = http_traffic[0]
            request_info = self._helpers.analyzeRequest(message)
            headers = request_info.getHeaders()
            
            # Extract Cookie header
            cookie_value = None
            for header in headers:
                header_str = str(header)
                if header_str.lower().startswith('cookie:'):
                    cookie_value = header_str[7:].strip()  # Remove "Cookie: " prefix
                    break
            
            if cookie_value:
                self.cookie_field.setText(cookie_value)
                self._append_output("\n[+] Extracted cookies from selected request")
                self._update_status("Cookies extracted successfully", False)
            else:
                self._update_status("No cookies found in selected request", True)
                self._append_output("\n[!] No Cookie header found in selected request")
        
        except Exception as e:
            self._update_status("Failed to extract cookies: %s" % str(e), True)
            self._append_output("\n[!] Error extracting cookies: %s" % str(e))
    
    def on_scan_clicked(self, event):
        """Handle scan button click"""
        target_url = self.url_field.getText().strip()
        
        if not target_url:
            self._update_status("Error: Please enter a target URL", True)
            return
        
        if not target_url.startswith('http'):
            target_url = 'https://' + target_url
            self.url_field.setText(target_url)
        
        # Check scanner availability
        if not self.config['scanner_path']:
            self._update_status("Error: Scanner script not found", True)
            self._append_output("\n[ERROR] Scanner script not found!")
            self._append_output("[FIX] Place endpoint_scanner.py in the same directory as this extension")
            return
        
        # Run scan in background thread
        self._append_output("\n" + "="*50)
        self._append_output("STARTING SCAN: %s" % target_url)
        self._append_output("="*50)
        
        thread = threading.Thread(target=self._run_scan, args=(target_url,))
        thread.daemon = True
        thread.start()
        
        # Also drain any auto-queued JS URLs
        if self.js_queue:
            self._append_output("\n[*] Also draining %d queued JS URLs from auto-scan..." % len(self.js_queue))
            drain_thread = threading.Thread(target=self._process_js_queue)
            drain_thread.daemon = True
            drain_thread.start()
    
    def _run_scan(self, target_url):
        """Run the endpoint scanner with cookie support"""
        try:
            self._update_status("Scanning: %s" % target_url, False)
            self._update_progress(10, "Starting scan...")
            
            # Get the directory where results will be saved
            scanner_dir = os.path.dirname(self.config['scanner_path'])
            results_file = os.path.join(scanner_dir, 'burp_scan_results.json')
            
            # Get cookies from the cookie field
            cookie_string = self.cookie_field.getText().strip()
            
            # Prepare command with arguments
            cmd = [
                self.config['python_path'],
                self.config['scanner_path'],
                '--target', target_url,
                '--output', results_file  # Specify output file
            ]
            
            # Add cookie handling - FIXED: pass --cookies directly, no temp file needed
            if cookie_string:
                cmd.extend(['--cookies', cookie_string])
                self._append_output("\n[+] Passing cookies directly to scanner")
            else:
                cmd.append('--no-cookies')
                self._append_output("\n[*] No cookies provided - scanning public endpoints only")
            
            # Wire up skip-dynamic checkbox
            if self.skip_dynamic_checkbox.isSelected():
                cmd.append('--skip-dynamic')
                self._append_output("\n[*] Dynamic analysis disabled (faster mode)")
            
            # Wire up max-routes and max-depth
            try:
                max_routes_val = self.max_routes_field.getText().strip()
                if max_routes_val:
                    cmd.extend(['--max-routes', max_routes_val])
            except:
                pass
            try:
                max_depth_val = self.max_depth_field.getText().strip()
                if max_depth_val:
                    cmd.extend(['--max-depth', max_depth_val])
            except:
                pass
            
            self._append_output("\n[CMD] %s" % ' '.join(cmd))
            self._append_output("[INFO] Running scanner with automated inputs...")
            self._update_progress(20, "Executing scanner...")
            
            # Run the scanner
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output line by line
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line_str = line.rstrip()
                    self._append_output(line_str)
                    
                    # Update progress based on structured BURP_PROGRESS markers
                    if "[BURP_PROGRESS:" in line_str:
                        try:
                            val = int(line_str.split("[BURP_PROGRESS:")[1].split("]")[0])
                            label = line_str.split("]", 1)[1].strip() if "]" in line_str else "Running..."
                            self._update_progress(val, label)
                        except:
                            pass
                    # Fallback: match against actual stoic.py output strings
                    elif "STARTING ENHANCED SCAN" in line_str:
                        self._update_progress(20, "Scan started...")
                    elif "Phase 1" in line_str or "JS Discovery" in line_str or "EnhancedFederation" in line_str:
                        self._update_progress(30, "Discovering JS files...")
                    elif "Phase 1.5" in line_str or "sourcemap" in line_str.lower() or "source map" in line_str.lower():
                        self._update_progress(45, "Harvesting source maps...")
                    elif "Phase 2" in line_str or "Static Analysis" in line_str or "analyzer.scan" in line_str:
                        self._update_progress(55, "Analyzing code...")
                    elif "Phase 3" in line_str or "Dynamic" in line_str or "Playwright" in line_str:
                        self._update_progress(70, "Dynamic analysis...")
                    elif "save_report" in line_str or "Generating" in line_str or "RESULTS" in line_str:
                        self._update_progress(88, "Generating report...")
            
            process.wait()
            
            if process.returncode != 0 and process.returncode != 1:
                self._update_status("Scanner failed with error code: %d" % process.returncode, True)
                self._append_output("\n[ERROR] Scanner exited with code: %d" % process.returncode)
                return
            
            self._update_progress(90, "Processing results...")
            
            # Load results from the specified file
            if os.path.exists(results_file):
                try:
                    with open(results_file, 'r') as f:
                        data = json.load(f)
                        
                    if isinstance(data, dict) and 'endpoints' in data:
                        results = data['endpoints']
                        self._append_output("\n[+] Loaded %d endpoints from: %s" % (len(results), results_file))
                        self._add_results(results)
                        self._update_progress(100, "Complete - %d endpoints found" % len(results))
                        self._update_status("Found %d endpoints" % len(results), False)
                    else:
                        self._update_status("Invalid results format", True)
                        self._append_output("[!] Results file has unexpected format")
                        
                except Exception as e:
                    self._update_status("Failed to parse results: %s" % str(e), True)
                    self._append_output("[!] Error parsing results: %s" % str(e))
            else:
                # Try fallback locations
                self._append_output("[!] Results file not found at: %s" % results_file)
                self._append_output("[*] Searching fallback locations...")
                
                fallback_paths = [
                    os.path.join(scanner_dir, 'results.json'),
                    'results.json',
                    os.path.expanduser('~/results.json')
                ]
                
                found = False
                for path in fallback_paths:
                    if os.path.exists(path):
                        try:
                            with open(path, 'r') as f:
                                data = json.load(f)
                            
                            if isinstance(data, dict) and 'endpoints' in data:
                                results = data['endpoints']
                            elif isinstance(data, list):
                                results = data
                            else:
                                continue
                            
                            self._append_output("[+] Found results at: %s" % path)
                            self._add_results(results)
                            self._update_progress(100, "Complete - %d endpoints found" % len(results))
                            self._update_status("Found %d endpoints" % len(results), False)
                            found = True
                            break
                        except:
                            continue
                
                if not found:
                    self._update_status("Results file not found", True)
                    self._append_output("[!] Could not find results file in any location")
                    self._append_output("[!] Scanner may have failed - check output above")
                    self._update_progress(0, "Failed")
            
        except Exception as e:
            self._update_status("Error: %s" % str(e), True)
            self._update_progress(0, "Error")
            self._append_output("\n[ERROR] %s" % str(e))
            import traceback
            self._append_output(traceback.format_exc())
    
    def _add_results(self, endpoints):
        """Add scan results to the table"""
        count = 0
        for endpoint in endpoints:
            params = endpoint.get('parameters', [])
            if isinstance(params, list):
                params_str = ', '.join(params)
            else:
                params_str = str(params)
            
            row = [
                endpoint.get('method', 'GET'),
                endpoint.get('endpoint', ''),
                endpoint.get('type', ''),
                endpoint.get('classification', ''),
                endpoint.get('source', ''),
                params_str
            ]
            
            # Add to model on EDT
            def add_row(r=row):
                self.table_model.addRow(r)
            SwingUtilities.invokeLater(add_row)
            
            # Store full endpoint data
            self.endpoints.append(endpoint)
            count += 1
        
        # Update stats
        self._update_stats()
        self._append_output("\n[+] Added %d endpoints to results table" % count)
    
    def _update_stats(self):
        """Update statistics label"""
        total = len(self.endpoints)
        backend = len([e for e in self.endpoints if e.get('classification') == 'BACKEND_API'])
        frontend = len([e for e in self.endpoints if e.get('classification') == 'FRONTEND_ROUTE'])
        verified = len([e for e in self.endpoints if e.get('classification') == 'VERIFIED_API'])
        rpc = len([e for e in self.endpoints if e.get('classification') == 'RPC_ENDPOINT'])
        
        stats_text = "Total: %d | Backend: %d | Frontend: %d | Verified: %d | RPC: %d" % (total, backend, frontend, verified, rpc)
        
        def update():
            self.stats_label.setText(stats_text)
        SwingUtilities.invokeLater(update)
    
    def on_export_json(self, event):
        """Export results to JSON"""
        if not self.endpoints:
            self._update_status("No results to export", True)
            return
        
        # File chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save JSON Results")
        chooser.setSelectedFile(File("endpoints.json"))
        
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            if not file_path.endswith('.json'):
                file_path += '.json'
            
            try:
                with open(file_path, 'w') as f:
                    json.dump({
                        'scan_metadata': {
                            'scanner': 'Endpoint Scanner - Burp Extension',
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'total_endpoints': len(self.endpoints)
                        },
                        'endpoints': self.endpoints
                    }, f, indent=2)
                
                self._update_status("Exported to: %s" % file_path, False)
                self._append_output("\n[+] Exported to: %s" % file_path)
            except Exception as e:
                self._update_status("Export failed: %s" % str(e), True)
    
    def on_export_txt(self, event):
        """Export results to TXT"""
        if not self.endpoints:
            self._update_status("No results to export", True)
            return
        
        chooser = JFileChooser()
        chooser.setDialogTitle("Save TXT Results")
        chooser.setSelectedFile(File("endpoints.txt"))
        
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            if not file_path.endswith('.txt'):
                file_path += '.txt'
            
            try:
                with open(file_path, 'w') as f:
                    f.write("ENDPOINT SCANNER RESULTS\n")
                    f.write("=" * 70 + "\n\n")
                    
                    for ep in self.endpoints:
                        f.write("[%s] %s\n" % (ep.get('method', 'GET'), ep.get('endpoint', '')))
                        if ep.get('parameters'):
                            f.write("  Params: %s\n" % ', '.join(ep['parameters']))
                        f.write("  Type: %s\n" % ep.get('type', 'N/A'))
                        f.write("  Classification: %s\n" % ep.get('classification', 'N/A'))
                        f.write("  Source: %s\n" % ep.get('source', 'N/A'))
                        f.write("\n")
                
                self._update_status("Exported to: %s" % file_path, False)
                self._append_output("\n[+] Exported to: %s" % file_path)
            except Exception as e:
                self._update_status("Export failed: %s" % str(e), True)
    
    def on_send_to_sitemap(self, event):
        """Send discovered endpoints to Burp's Site Map"""
        if not self.endpoints:
            self._update_status("No endpoints to send", True)
            return
        
        count = 0
        for ep in self.endpoints:
            try:
                url = ep.get('endpoint', '')
                if url and url.startswith('http'):
                    # Build a minimal HTTP request
                    method = ep.get('method', 'GET')
                    
                    # Parse URL
                    from java.net import URL
                    jurl = URL(url)
                    
                    # Create request line
                    path = jurl.getPath()
                    if not path:
                        path = '/'
                    query = jurl.getQuery()
                    if query:
                        path = path + '?' + query
                    
                    request_line = "%s %s HTTP/1.1\r\n" % (method, path)
                    headers = "Host: %s\r\n" % jurl.getHost()
                    headers += "User-Agent: Burp Scanner\r\n"
                    headers += "Connection: close\r\n\r\n"
                    
                    request = request_line + headers
                    
                    # Add to site map
                    http_service = self._helpers.buildHttpService(jurl.getHost(), jurl.getPort(), jurl.getProtocol())
                    self._callbacks.addToSiteMap(
                        self._helpers.buildHttpRequest(http_service, request.encode('utf-8'))
                    )
                    count += 1
            except Exception as e:
                self._append_output("[!] Failed to add endpoint: %s - %s" % (ep.get('endpoint', ''), str(e)))
        
        self._update_status("Added %d endpoints to Site Map" % count, False)
        self._append_output("\n[+] Added %d endpoints to Burp Site Map" % count)
    
    def on_send_to_repeater(self, event):
        """Send selected endpoint(s) to Burp Repeater"""
        selected_rows = self.results_table.getSelectedRows()
        if len(selected_rows) == 0:
            self._update_status("No endpoint selected - click a row in the table first", True)
            self._append_output("\n[!] Select one or more rows in the table to send to Repeater")
            return
        
        count = 0
        for view_row in selected_rows:
            # Convert view row index to model row index (handles sorting)
            model_row = self.results_table.convertRowIndexToModel(view_row)
            try:
                endpoint_url = str(self.table_model.getValueAt(model_row, 1))
                method = str(self.table_model.getValueAt(model_row, 0))
                
                if not endpoint_url or not endpoint_url.startswith('http'):
                    # Try prepending target base URL
                    base = self.url_field.getText().strip()
                    if base and endpoint_url.startswith('/'):
                        endpoint_url = base.rstrip('/') + endpoint_url
                    else:
                        self._append_output("[!] Skipping non-absolute URL: %s" % endpoint_url)
                        continue
                
                from java.net import URL
                jurl = URL(endpoint_url)
                
                path = jurl.getPath() or '/'
                query = jurl.getQuery()
                if query:
                    path = path + '?' + query
                
                port = jurl.getPort()
                if port == -1:
                    port = 443 if jurl.getProtocol() == 'https' else 80
                use_https = (jurl.getProtocol() == 'https')
                
                request_str = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n" % (
                    method, path, jurl.getHost()
                )
                
                http_service = self._helpers.buildHttpService(jurl.getHost(), port, use_https)
                self._callbacks.sendToRepeater(
                    jurl.getHost(),
                    port,
                    use_https,
                    request_str.encode('utf-8'),
                    "%s %s" % (method, path)
                )
                count += 1
            except Exception as e:
                self._append_output("[!] Failed to send to Repeater: %s" % str(e))
        
        self._update_status("Sent %d endpoint(s) to Repeater" % count, False)
        self._append_output("\n[+] Sent %d endpoint(s) to Burp Repeater" % count)
    
    def _process_js_queue(self):
        """Drain the auto-scan JS queue - scan each queued URL"""
        if not self.js_queue:
            self._append_output("\n[*] JS queue is empty")
            return
        
        self._append_output("\n[*] Processing %d queued JS URLs..." % len(self.js_queue))
        items = self.js_queue[:]
        self.js_queue = []
        
        for item in items:
            self._append_output("\n[Auto] Scanning queued URL: %s" % item['url'])
            thread = threading.Thread(target=self._run_scan, args=(item['url'],))
            thread.daemon = True
            thread.start()
            # Brief pause between scans to avoid hammering
            time.sleep(1)

    def on_clear_results(self, event):
        """Clear all results"""
        self.table_model.setRowCount(0)
        self.endpoints = []
        self.output_text.setText("")
        self._update_status("Results cleared", False)
        self._update_progress(0, "Ready")
        self._update_stats()
    
    def _update_status(self, message, is_error):
        """Update status label"""
        def update():
            self.status_label.setText("Status: %s" % message)
            if is_error:
                self.status_label.setForeground(Color.RED)
            else:
                self.status_label.setForeground(Color(0, 128, 0))
        SwingUtilities.invokeLater(update)
    
    def _update_progress(self, value, text):
        """Update progress bar"""
        def update():
            self.progress_bar.setValue(value)
            self.progress_bar.setString(text)
        SwingUtilities.invokeLater(update)
    
    def _append_output(self, text):
        """Append text to output area"""
        def append():
            current = self.output_text.getText()
            self.output_text.setText(current + text + "\n")
            self.output_text.setCaretPosition(self.output_text.getDocument().getLength())
        SwingUtilities.invokeLater(append)


# FIX: Added the missing AutoScanListener class
class AutoScanListener(ActionListener):
    """Listener for the Auto-scan checkbox"""
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        # Update config based on checkbox state
        is_selected = self.extender.auto_scan_checkbox.isSelected()
        self.extender.config['auto_scan'] = is_selected
        
        status = "enabled" if is_selected else "disabled"
        self.extender._append_output("\n[*] Auto-scan %s" % status)

# FIX: Fixed the incomplete ScanActionListener class
class ScanActionListener(ActionListener):
    """Handles the 'Scan for Endpoints' context menu click"""
    def __init__(self, extender, messages):
        self.extender = extender
        self.messages = messages
    
    def actionPerformed(self, event):
        if not self.messages:
            return
        
        # Get the URL from the selected message
        message = self.messages[0]
        url = str(message.getUrl())
        
        # Switch focus to our tab
        self.extender.panel.requestFocus()
        
        # Populate the URL field
        self.extender.url_field.setText(url)
        
        # Extract and populate cookies automatically from the request
        try:
            request_info = self.extender._helpers.analyzeRequest(message)
            headers = request_info.getHeaders()
            for header in headers:
                if str(header).lower().startswith('cookie:'):
                    # Remove 'Cookie:' prefix and whitespace
                    cookie_val = str(header)[7:].strip()
                    self.extender.cookie_field.setText(cookie_val)
                    self.extender._append_output("[+] Auto-filled cookies from request")
                    break
        except:
            pass
            
        self.extender._append_output("\n[+] Target set: %s" % url)
        self.extender._append_output("[*] Click 'Start Scan' to begin")