import requests
import json
import sys
import os
import time
import hashlib
import socket
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    RESET = '\033[0m'
    
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_PURPLE = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

class RAEYSCAN:
    def __init__(self, target):
        self.target = target
        self.start_time = time.time()
        self.output = {
            "tool": "RAEYSCAN",
            "version": "v2.0",
            "developer": "Eng RaeYS",
            "license": "All Rights Reserved - Eng RaeYS",
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scan_duration": 0,
            "hits": [],
            "statistics": {
                "total_scanned": 0,
                "found": 0,
                "failed": 0
            }
        }
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.discovered_emails = []
        self.discovered_domains = []
        self.discovered_ips = []

    def _banner(self):
        print(f"""
{Colors.RED}    ╔══════════════════════════════════════════════════════════════════╗
{Colors.RED}    ║{Colors.RESET}{Colors.BOLD}                                                                  {Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.CYAN}     ██████╗  █████╗ ███████╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗{Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.CYAN}     ██╔══██╗██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║{Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.CYAN}     ██████╔╝███████║█████╗   ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║{Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.CYAN}     ██╔══██╗██╔══██║██╔══╝    ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║{Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.CYAN}     ██║  ██║██║  ██║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║{Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.CYAN}     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.BOLD}                                                                  {Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.GREEN}                    RAEYSCAN v2.0                                 {Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.GREEN}              Developed by: Eng RaeYS                           {Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.GREEN}              All Rights Reserved                                {Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.GREEN}              "Scan the void. Find the truth."                   {Colors.RED}║{Colors.RESET}
{Colors.RED}    ║{Colors.RESET}{Colors.BOLD}                                                                  {Colors.RED}║{Colors.RESET}
{Colors.RED}    ╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """)

    def _menu(self):
        print(f"""
{Colors.CYAN}    ╔══════════════════════════════════════════════════════════════════╗
{Colors.CYAN}    ║{Colors.RESET}{Colors.BOLD}                      RAEYSCAN v2.0 MENU                         {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}                                                                  {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[1]{Colors.RESET} Full Scan (All Platforms)                      {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[2]{Colors.RESET} Social Media Only                             {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[3]{Colors.RESET} Developer Platforms Only                      {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[4]{Colors.RESET} Media/Creative Platforms Only                 {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[5]{Colors.RESET} Email & Domain Discovery                     {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[6]{Colors.RESET} DNS & IP Enumeration                         {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[7]{Colors.RESET} Dark Web & Pastebin Search                  {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[8]{Colors.RESET} Custom Platform Selection                    {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.YELLOW}[9]{Colors.RESET} Generate Report Only                        {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.RED}[0]{Colors.RESET} Exit                                            {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}                                                                  {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ║{Colors.RESET}    {Colors.DIM}Eng RaeYS - RAEYSCAN v2.0{Colors.RESET}                         {Colors.CYAN}║{Colors.RESET}
{Colors.CYAN}    ╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
        """)

    def _progress_bar(self, current, total, prefix=""):
        bar_length = 40
        progress = current / total
        filled = int(bar_length * progress)
        bar = f"{Colors.GREEN}{'█' * filled}{Colors.RESET}{Colors.DIM}{'░' * (bar_length - filled)}{Colors.RESET}"
        percent = progress * 100
        print(f"\r{prefix} [{bar}] {percent:.1f}% ({current}/{total})", end="")
        if current == total:
            print()

    def _social_platforms(self):
        return [
            ("Twitter", f"https://twitter.com/{self.target}"),
            ("Instagram", f"https://www.instagram.com/{self.target}/"),
            ("Facebook", f"https://www.facebook.com/{self.target}"),
            ("TikTok", f"https://www.tiktok.com/@{self.target}"),
            ("Snapchat", f"https://www.snapchat.com/add/{self.target}"),
            ("Telegram", f"https://t.me/{self.target}"),
            ("Reddit", f"https://www.reddit.com/user/{self.target}"),
            ("Pinterest", f"https://www.pinterest.com/{self.target}/"),
            ("Tumblr", f"https://{self.target}.tumblr.com/"),
            ("VK", f"https://vk.com/{self.target}"),
            ("LinkedIn", f"https://www.linkedin.com/in/{self.target}"),
            ("WhatsApp", f"https://wa.me/{self.target}"),
            ("WeChat", f"https://www.wechat.com/{self.target}"),
            ("Signal", f"https://signal.me/{self.target}"),
            ("Discord", f"https://discord.com/users/{self.target}"),
        ]

    def _dev_platforms(self):
        return [
            ("GitHub", f"https://github.com/{self.target}"),
            ("GitLab", f"https://gitlab.com/{self.target}"),
            ("Bitbucket", f"https://bitbucket.org/{self.target}/"),
            ("StackOverflow", f"https://stackoverflow.com/users?search={self.target}"),
            ("Medium", f"https://medium.com/@{self.target}"),
            ("DevTo", f"https://dev.to/{self.target}"),
            ("HackerRank", f"https://www.hackerrank.com/{self.target}"),
            ("LeetCode", f"https://leetcode.com/{self.target}"),
            ("CodePen", f"https://codepen.io/{self.target}"),
            ("Replit", f"https://replit.com/@{self.target}"),
            ("CodeSandbox", f"https://codesandbox.io/u/{self.target}"),
            ("SourceForge", f"https://sourceforge.net/u/{self.target}/"),
            ("HackerOne", f"https://hackerone.com/{self.target}"),
            ("Bugcrowd", f"https://bugcrowd.com/{self.target}"),
        ]

    def _media_platforms(self):
        return [
            ("YouTube", f"https://www.youtube.com/@{self.target}"),
            ("Vimeo", f"https://vimeo.com/{self.target}"),
            ("Spotify", f"https://open.spotify.com/user/{self.target}"),
            ("SoundCloud", f"https://soundcloud.com/{self.target}"),
            ("Dribbble", f"https://dribbble.com/{self.target}"),
            ("DeviantArt", f"https://www.deviantart.com/{self.target}"),
            ("Flickr", f"https://www.flickr.com/people/{self.target}/"),
            ("Patreon", f"https://www.patreon.com/{self.target}"),
            ("Quora", f"https://www.quora.com/profile/{self.target}"),
            ("Goodreads", f"https://www.goodreads.com/user/show/{self.target}"),
            ("Etsy", f"https://www.etsy.com/shop/{self.target}"),
            ("Behance", f"https://www.behance.net/{self.target}"),
            ("ArtStation", f"https://www.artstation.com/{self.target}"),
            ("Mixcloud", f"https://www.mixcloud.com/{self.target}/"),
            ("Twitch", f"https://www.twitch.tv/{self.target}"),
        ]

    def _forums_platforms(self):
        return [
            ("ProductHunt", f"https://www.producthunt.com/@{self.target}"),
            ("IndieHackers", f"https://www.indiehackers.com/{self.target}"),
            ("GrowthHackers", f"https://growthhackers.com/members/{self.target}"),
            ("Wix", f"https://{self.target}.wixsite.com/mysite"),
            ("WordPress", f"https://{self.target}.wordpress.com/"),
            ("Blogger", f"https://{self.target}.blogger.com/"),
            ("Ghost", f"https://{self.target}.ghost.io/"),
        ]

    def _all_platforms(self):
        return (self._social_platforms() + self._dev_platforms() + 
                self._media_platforms() + self._forums_platforms())

    def _email_discovery(self):
        emails = [
            f"{self.target}@gmail.com",
            f"{self.target}@outlook.com",
            f"{self.target}@yahoo.com",
            f"{self.target}@protonmail.com",
            f"{self.target}@hotmail.com",
            f"{self.target}@icloud.com",
            f"{self.target}@aol.com",
            f"{self.target}@mail.com",
            f"{self.target}@yandex.com",
            f"{self.target}@zoho.com",
            f"{self.target}@hey.com",
            f"{self.target}@fastmail.com",
            f"{self.target}@tutanota.com",
            f"{self.target}@mailfence.com",
            f"{self.target}@startmail.com",
            f"{self.target}@pm.me"
        ]
        
        domains = [
            f"{self.target}.com",
            f"{self.target}.net",
            f"{self.target}.org",
            f"{self.target}.io",
            f"{self.target}.dev",
            f"{self.target}.tech",
            f"{self.target}.ai",
            f"{self.target}.me",
            f"{self.target}.xyz",
            f"{self.target}.club"
        ]
        
        self.discovered_emails.extend(emails)
        self.discovered_domains.extend(domains)
        
        self.output["hits"].append({
            "platform": "Email_Discovery",
            "emails": emails,
            "domains": domains,
            "note": "Potential email addresses and domains"
        })
        
        return emails, domains

    def _dns_enumeration(self):
        results = []
        try:
            ip = socket.gethostbyname(f"{self.target}.com")
            results.append({"type": "A_Record", "value": ip})
            self.discovered_ips.append(ip)
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(f"{self.target}.com", 'MX')
            for rdata in answers:
                results.append({"type": "MX_Record", "value": str(rdata.exchange)})
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(f"{self.target}.com", 'NS')
            for rdata in answers:
                results.append({"type": "NS_Record", "value": str(rdata)})
        except:
            pass
        
        try:
            answers = dns.resolver.resolve(f"{self.target}.com", 'TXT')
            for rdata in answers:
                results.append({"type": "TXT_Record", "value": str(rdata)})
        except:
            pass
        
        if results:
            self.output["hits"].append({
                "platform": "DNS_Enumeration",
                "records": results
            })
        
        return results

    def _dark_web_search(self):
        pastebin_urls = [
            f"https://pastebin.com/search?q={self.target}",
            f"https://slexy.org/?s={self.target}",
            f"https://privatebin.net/?q={self.target}",
        ]
        
        self.output["hits"].append({
            "platform": "Dark_Web_Pastebin",
            "search_urls": pastebin_urls,
            "note": "Manual check required for these sources"
        })
        
        return pastebin_urls

    def _check(self, platform, url):
        try:
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                self.output["hits"].append({
                    "platform": platform,
                    "url": url,
                    "status": "active",
                    "status_code": r.status_code
                })
                return True
            else:
                self.output["statistics"]["failed"] += 1
                return False
        except:
            self.output["statistics"]["failed"] += 1
            return False

    def scan(self, mode=1):
        print(f"\n{Colors.CYAN}[RAEYSCAN]{Colors.RESET} Target: {Colors.BOLD}{self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}[RAEYSCAN]{Colors.RESET} Mode: {mode}")
        print(f"{Colors.CYAN}[RAEYSCAN]{Colors.RESET} Developer: {Colors.GREEN}Eng RaeYS{Colors.RESET}")
        print(f"{Colors.CYAN}[RAEYSCAN]{Colors.RESET} Version: {Colors.YELLOW}v2.0{Colors.RESET}\n")

        if mode == 1:
            platforms = self._all_platforms()
        elif mode == 2:
            platforms = self._social_platforms()
        elif mode == 3:
            platforms = self._dev_platforms()
        elif mode == 4:
            platforms = self._media_platforms()
        elif mode == 5:
            self._email_discovery()
            return self.output
        elif mode == 6:
            self._dns_enumeration()
            return self.output
        elif mode == 7:
            self._dark_web_search()
            return self.output
        elif mode == 8:
            platforms = self._custom_scan()
        elif mode == 9:
            return self.output
        else:
            print(f"{Colors.RED}[!] Invalid mode.{Colors.RESET}")
            sys.exit(1)

        if mode not in [5, 6, 7, 9]:
            total = len(platforms)
            found = 0
            failed = 0
            
            print(f"{Colors.YELLOW}[RAEYSCAN]{Colors.RESET} Scanning {total} platforms...\n")
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(self._check, p, u): p for p, u in platforms}
                
                for idx, future in enumerate(as_completed(futures), 1):
                    platform = futures[future]
                    try:
                        if future.result():
                            found += 1
                            print(f"{Colors.GREEN}[+]{Colors.RESET} FOUND: {platform}")
                        else:
                            failed += 1
                            print(f"{Colors.RED}[-]{Colors.RESET} FAILED: {platform}")
                    except:
                        failed += 1
                        print(f"{Colors.RED}[!]{Colors.RESET} ERROR: {platform}")
                    
                    self._progress_bar(idx, total, "Scanning Progress")
                    
            self.output["statistics"]["total_scanned"] = total
            self.output["statistics"]["found"] = found
            self.output["statistics"]["failed"] = failed
            
            print(f"\n\n{Colors.GREEN}[✓]{Colors.RESET} Scan complete.")
            print(f"{Colors.GREEN}[✓]{Colors.RESET} Found: {Colors.BOLD}{found}{Colors.RESET}/{total}")
            print(f"{Colors.RED}[✗]{Colors.RESET} Failed: {failed}")
            
            if found == 0:
                print(f"\n{Colors.YELLOW}[!]{Colors.RESET} No results found for '{self.target}'")
                print(f"{Colors.YELLOW}[!]{Colors.RESET} Try checking the username or using a different target.")

        return self.output

    def _custom_scan(self):
        print(f"\n{Colors.CYAN}[RAEYSCAN]{Colors.RESET} Available Platforms:\n")
        all_platforms = self._all_platforms()
        
        for idx, (name, _) in enumerate(all_platforms, 1):
            if idx % 2 == 0:
                print(f"{Colors.GREEN}    {idx:2d}. {name}{Colors.RESET}", end="")
            else:
                print(f"{Colors.PURPLE}    {idx:2d}. {name}{Colors.RESET}", end="")
            if idx % 2 == 0:
                print()
        
        if len(all_platforms) % 2 != 0:
            print()
        
        print(f"\n{Colors.YELLOW}[?]{Colors.RESET} Enter platform numbers (comma separated): ", end="")
        try:
            choice = input().strip()
            indices = [int(x.strip()) - 1 for x in choice.split(",")]
            selected = [all_platforms[i] for i in indices if 0 <= i < len(all_platforms)]
            if not selected:
                print(f"{Colors.RED}[!] No valid platforms selected. Running full scan.{Colors.RESET}")
                return self._all_platforms()
            return selected
        except:
            print(f"{Colors.RED}[!] Invalid input. Running full scan.{Colors.RESET}")
            return self._all_platforms()

    def save(self):
        self.output["scan_duration"] = time.time() - self.start_time
        
        filename = f"{self.target}_RAEYSCAN_v2.0.json"
        with open(filename, "w") as f:
            json.dump(self.output, f, indent=2)
        
        txt_filename = f"{self.target}_RAEYSCAN_v2.0.txt"
        with open(txt_filename, "w") as f:
            f.write("=" * 80 + "\n")
            f.write(" RAEYSCAN v2.0 - Report\n")
            f.write(" Developed by: Eng RaeYS\n")
            f.write(" All Rights Reserved\n")
            f.write("=" * 80 + "\n\n")
            f.write(f" Target: {self.target}\n")
            f.write(f" Timestamp: {self.output['timestamp']}\n")
            f.write(f" Scan Duration: {self.output['scan_duration']:.2f} seconds\n")
            f.write(f" Total Hits: {len(self.output['hits'])}\n\n")
            
            if "statistics" in self.output:
                f.write(" Statistics:\n")
                f.write(f"   Total Scanned: {self.output['statistics']['total_scanned']}\n")
                f.write(f"   Found: {self.output['statistics']['found']}\n")
                f.write(f"   Failed: {self.output['statistics']['failed']}\n\n")
            
            f.write("=" * 80 + "\n\n")
            
            for hit in self.output["hits"]:
                f.write(f"[+] Platform: {hit.get('platform')}\n")
                for key, val in hit.items():
                    if key != "platform":
                        if isinstance(val, list):
                            f.write(f"    {key}:\n")
                            for item in val:
                                f.write(f"        - {item}\n")
                        elif isinstance(val, dict):
                            f.write(f"    {key}:\n")
                            for k, v in val.items():
                                f.write(f"        {k}: {v}\n")
                        else:
                            f.write(f"    {key}: {val}\n")
                f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write(" RAEYSCAN v2.0 by Eng RaeYS\n")
            f.write(" All Rights Reserved\n")
        
        with open("RAEYSCAN_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] {self.target} | Hits: {len(self.output['hits'])} | Duration: {self.output['scan_duration']:.2f}s | RAEYSCAN v2.0 | Eng RaeYS\n")
        
        print(f"\n{Colors.GREEN}[√]{Colors.RESET} JSON Report: {filename}")
        print(f"{Colors.GREEN}[√]{Colors.RESET} TXT Report: {txt_filename}")
        print(f"{Colors.GREEN}[√]{Colors.RESET} Total Hits: {Colors.BOLD}{len(self.output['hits'])}{Colors.RESET}")
        print(f"{Colors.GREEN}[√]{Colors.RESET} Scan Duration: {self.output['scan_duration']:.2f} seconds")
        print(f"{Colors.GREEN}[√]{Colors.RESET} RAEYSCAN v2.0 by {Colors.BOLD}Eng RaeYS{Colors.RESET}")

    def export_html(self):
        html_filename = f"{self.target}_RAEYSCAN_v2.0.html"
        with open(html_filename, "w") as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>RAEYSCAN Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0a0a0a; color: #00ff00; margin: 20px; }}
        .header {{ background: linear-gradient(90deg, #ff0000, #00ff00, #0000ff); padding: 20px; text-align: center; color: white; }}
        .hit {{ background: #1a1a1a; margin: 10px 0; padding: 15px; border-left: 4px solid #00ff00; }}
        .platform {{ color: #00ffff; font-weight: bold; font-size: 18px; }}
        .details {{ color: #cccccc; margin-left: 20px; }}
        .statistics {{ background: #111; padding: 10px; border: 1px solid #333; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; border-top: 1px solid #333; padding: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RAEYSCAN v2.0</h1>
        <p>Developed by: Eng RaeYS</p>
        <p>Target: {self.target}</p>
        <p>Timestamp: {self.output['timestamp']}</p>
    </div>
    <div class="statistics">
        <h3>Statistics</h3>
        <p>Total Hits: {len(self.output['hits'])}</p>
        <p>Scan Duration: {self.output['scan_duration']:.2f} seconds</p>
    </div>
    <div style="margin-top: 20px;">""")
            
            for hit in self.output["hits"]:
                f.write(f"""
    <div class="hit">
        <div class="platform">[+] {hit.get('platform')}</div>
        <div class="details">""")
                for key, val in hit.items():
                    if key != "platform":
                        if isinstance(val, list):
                            f.write(f"<div>{key}:</div><ul>")
                            for item in val:
                                f.write(f"<li>{item}</li>")
                            f.write("</ul>")
                        else:
                            f.write(f"<div>{key}: {val}</div>")
                f.write("""
        </div>
    </div>""")
            
            f.write(f"""
    </div>
    <div class="footer">
        RAEYSCAN v2.0 by Eng RaeYS - All Rights Reserved
    </div>
</body>
</html>""")
        
        print(f"{Colors.GREEN}[√]{Colors.RESET} HTML Report: {html_filename}")

if __name__ == "__main__":
    scanner = RAEYSCAN("")
    scanner._banner()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scanner.target = target
        
        scanner._menu()
        try:
            choice = int(input(f"{Colors.YELLOW}[?] RAEYSCAN v2.0 > {Colors.RESET}").strip())
            if choice == 0:
                print(f"{Colors.RED}[!] Exiting RAEYSCAN...{Colors.RESET}")
                sys.exit(0)
            scanner.scan(choice)
            scanner.save()
            scanner.export_html()
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input. Running full scan.{Colors.RESET}")
            scanner.scan(1)
            scanner.save()
            scanner.export_html()
    else:
        print(f"\n{Colors.YELLOW}[?] Enter target username: {Colors.RESET}", end="")
        target = input().strip()
        if not target:
            print(f"{Colors.RED}[!] Username required.{Colors.RESET}")
            sys.exit(1)
        
        scanner.target = target
        scanner._menu()
        
        try:
            choice = int(input(f"{Colors.YELLOW}[?] RAEYSCAN v2.0 > {Colors.RESET}").strip())
            if choice == 0:
                print(f"{Colors.RED}[!] Exiting RAEYSCAN...{Colors.RESET}")
                sys.exit(0)
            scanner.scan(choice)
            scanner.save()
            scanner.export_html()
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input. Running full scan.{Colors.RESET}")
            scanner.scan(1)
            scanner.save()
            scanner.export_html()