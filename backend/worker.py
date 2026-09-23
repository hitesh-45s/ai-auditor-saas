"""
The 0.1% God-Tier Factory Worker.
Implements a Recursive Spider to deep-crawl websites using a Fast Lane / Slow Lane architecture.
Forces Gemini to pinpoint exact URLs and bugs in a structured Vulnerability Array.
Includes Enterprise Exponential Backoff for AI reliability.
"""
import os
import time
import json
import asyncio
import socket
from urllib.parse import urljoin, urlparse
from dotenv import load_dotenv
from upstash_redis import Redis
from supabase import create_client, Client
from google import genai
from google.genai import types
from playwright.sync_api import sync_playwright
import httpx
from bs4 import BeautifulSoup

# pylint: disable=broad-exception-caught

# Load environment variables
load_dotenv(dotenv_path="../.env")

# 1. Connect to Upstash (The Conveyor Belt)
REDIS_URL = os.getenv("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
REDIS_CLIENT = Redis(url=REDIS_URL, token=REDIS_TOKEN)

# 2. Connect to Supabase (The Vault)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
SUPABASE_CLIENT: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# 3. Connect the Modern Gemini Brain
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
ai_client = genai.Client(api_key=GEMINI_KEY)

# ==========================================
# THE 0.1% CONFIGURATION (Optimized for Free-Tier Stability)
# ==========================================
MAX_PAGES_TO_CRAWL = 40 
THROTTLE_SLEEP_SECONDS = 1.0 # Sped up slightly for async batching
AI_MAX_RETRIES = 5 # The Heavy-Duty Battering Ram

print("🕷️ Bulletproof Forensic Spider started. Staring at the queue...")

def is_safe_url(url):
    """Prevents Server-Side Request Forgery (SSRF) against internal networks."""
    try:
        hostname = urlparse(url).hostname
        if not hostname: return False
        ip = socket.gethostbyname(hostname)
        if ip.startswith('127.') or ip.startswith('10.') or ip.startswith('169.254.') or ip.startswith('192.168.'):
            return False
        return True
    except:
        return False

def is_valid_internal_link(base_url, link_url):
    """The Normalizer: Ensures we only crawl internal pages, no external sites or junk links."""
    parsed_base = urlparse(base_url)
    parsed_link = urlparse(link_url)
    
    if not link_url or link_url.startswith(('mailto:', 'tel:', 'javascript:')):
        return False
    if parsed_link.netloc and parsed_link.netloc != parsed_base.netloc:
        return False
        
    return is_safe_url(link_url)


async def async_deep_crawl(target_url, max_pages):
    """The Fast Lane: Asynchronously crawls multiple pages at once to save massive amounts of time."""
    visited_urls = set()
    queue = [target_url]
    
    parsed_target = urlparse(target_url)
    base_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"
    aggregated_website_data = ""
    
    # We use a single async client session for connection pooling and speed
    async with httpx.AsyncClient(headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, timeout=15.0, follow_redirects=True) as client:
        while queue and len(visited_urls) < max_pages:
            # Process URLs in small batches concurrently
            batch = queue[:5] 
            queue = queue[5:]
            tasks = []
            
            for current_url in batch:
                if current_url not in visited_urls:
                    visited_urls.add(current_url)
                    tasks.append(client.get(current_url))
                    
            if not tasks: 
                continue
            
            # Execute batch concurrently
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, response in enumerate(responses):
                current_url = batch[i]
                
                if isinstance(response, Exception):
                    print(f"   ⚠️ Could not read {current_url}: {response}")
                    continue
                    
                if response.status_code == 200:
                    try:
                        soup = BeautifulSoup(response.text, "html.parser")
                        
                        # Keep the HTML, but remove massive scripts and SVGs to save tokens
                     # 1. Remove all noise
                        for element in soup(["script", "style", "video"]):
                            element.extract()
                            
                        # 2. Replace SVG math with placeholder
                        for shape in soup.find_all(["path", "polygon", "polyline", "g"]):
                            shape.replace_with("<!-- SVG_PATHS_COMPRESSED -->")
                        # 3. SMART EXTRACTION: Pull only audit-critical sections
                        audit_data = ""
                        # Extract HEAD (contains all SEO data)
                        if soup.head:
                            audit_data += f"[HEAD/SEO TAGS]:\n{str(soup.head)[:1000]}\n\n"

                        # Extract all links with their attributes (Accessibility + SEO)
                        links = soup.find_all('a', href=True)
                        link_data = " ".join([str(link) for link in links[:20]])
                        audit_data += f"[LINKS/NAV STRUCTURE]:\n{link_data[:800]}\n\n"

                        # Extract all images with their attributes (Accessibility)
                        images = soup.find_all('img')
                        img_data = " ".join([str(img) for img in images[:20]])
                        audit_data += f"[IMAGES]:\n{img_data[:500]}\n\n"

                        # Extract all interactive elements (Hydration + Accessibility)
                        interactive = soup.find_all(['button', 'form', 'input', 'select'])
                        interactive_data = " ".join([str(el) for el in interactive[:15]])
                        audit_data += f"[INTERACTIVE ELEMENTS]:\n{interactive_data[:800]}\n\n"
                        
                        # Extract headings structure (SEO + Accessibility)
                        headings = soup.find_all(['h1', 'h2', 'h3'])
                        heading_data = " ".join([str(h) for h in headings[:15]])
                        audit_data += f"[HEADING STRUCTURE]:\n{heading_data[:400]}\n\n"
                        aggregated_website_data += f"--- PAGE: {current_url} ---\n{audit_data}\n\n"
                        
                        # Extract links for the queue
                        for link in soup.find_all('a', href=True):
                            raw_href = link['href'].split('#')[0]
                            full_link = urljoin(base_domain, raw_href)
                            
                            if is_valid_internal_link(base_domain, full_link) and full_link not in visited_urls and full_link not in queue:
                                queue.append(full_link)
                                
                    except Exception as e:
                        print(f"   ⚠️ Parse error on {current_url}: {e}")
                        
            # Respect target firewalls between batches
            await asyncio.sleep(THROTTLE_SLEEP_SECONDS) 
            print(f"   ({len(visited_urls)}/{max_pages}) Deep Crawl Progress...")
            
    return aggregated_website_data, list(visited_urls)


def process_queue():
    """The Infinite Loop checking Redis for new jobs."""
    while True:
        scan_id = None
        try:
            ticket = REDIS_CLIENT.rpop("scan_queue")
            
            if ticket:
                if isinstance(ticket, str):
                    ticket = json.loads(ticket)
                
                scan_id = ticket['scan_id']
                target_url = ticket['target_url']
                
                print(f"\n🎯 FORENSIC TICKET GRABBED: {scan_id}")
                print(f"🕸️ Deploying Bulletproof Spider to: {target_url}")
                
                if not is_safe_url(target_url):
                    print(f"❌ Security Block: Refusing to crawl internal/invalid URL {target_url}")
                    SUPABASE_CLIENT.table("scans").update({"status": "failed"}).eq("id", scan_id).execute()
                    continue
                
                SUPABASE_CLIENT.table("scans").update({"status": "crawling"}).eq("id", scan_id).execute()
                
                # --- STEP 1: The Slow Lane (Homepage Visuals) ---
                print("📸 [SLOW Lane] Taking Homepage Screenshot...")
                screenshot_path = f"screenshot_{scan_id}.png"
                homepage_text = ""
                
                try:
                    with sync_playwright() as p:
                        browser = p.chromium.launch(headless=True)
                        page = browser.new_page()
                        page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                        page.wait_for_timeout(3000)
                        
                        page.screenshot(path=screenshot_path, full_page=False)
                        homepage_text = page.evaluate("document.body.innerText")
                        browser.close()
                        
                    # Upload screenshot to Supabase The Vault
                    with open(screenshot_path, "rb") as f:
                        SUPABASE_CLIENT.storage.from_("screenshots").upload(screenshot_path, f)
                        
                    public_url = SUPABASE_CLIENT.storage.from_("screenshots").get_public_url(screenshot_path)
                    SUPABASE_CLIENT.table("scans").update({"screenshot_url": public_url}).eq("id", scan_id).execute()
                    
                    # Clean up local image
                    if os.path.exists(screenshot_path):
                        os.remove(screenshot_path)
                except Exception as e:
                    print(f"   ⚠️ Playwright/Screenshot visual extraction failed: {e}")

                # --- STEP 2: The Fast Lane (Recursive Crawler) ---
                print("⚡ [FAST LANE] Unleashing the Async Deep Crawler...")
                aggregated_website_data, visited_urls = asyncio.run(async_deep_crawl(target_url, MAX_PAGES_TO_CRAWL))
                
                # Prepend homepage text if Playwright got it successfully
                if homepage_text:
                    aggregated_website_data = f"--- PAGE: {target_url} (Homepage) ---\n{homepage_text}\n\n" + aggregated_website_data


                # --- STEP 3: The AI Aggregator (RAG) with Heavy-Duty Backoff ---
                print(f"🧠 Feeding {len(visited_urls)} pages of aggregated data to Gemini for Granular Auditing...")
                
                # FIXED: The logic contract for localized remediation and strict scoring
                ai_prompt = f"""
                You are a highly paid, expert Enterprise Web Auditor.
                I have crawled {len(visited_urls)} pages of a website. Below is the massive, aggregated text from all pages.
                
                CRITICAL SCORING RUBRIC (STRICT MATHEMATICAL CALCULATION):
                1. Start at a baseline score of 100.
                2. For each "High" severity defect found, subtract 15 points.
                3. For each "Medium" severity defect found, subtract 5 points.
                4. For each "Low" severity defect found, subtract 1 point.
                5. The minimum possible score is 10.
                Example: A site with 0 High, 1 Medium, and 2 Low defects MUST receive a score of 93.

                Analyze the entire structure and content, and return a strict JSON dictionary matching this exact structure (no markdown wrappers):
                {{
                  "global_score": <calculated integer based strictly on the rubric>,
                  "executive_summary": "<string>",
                  "top_global_issue": "<string>",
                  "critical_vulnerabilities": [
                    {{
                      "id": "vuln-1",
                      "url": "<exact page URL where defect was discovered>",
                      "issue_type": "<Accessibility | Code Error | Hydration | Performance | SEO>",
                      "severity": "<High | Medium | Low>",
                      "file_target": "<suggested file path>",
                      "description": "<precise architectural defect description>",
                      "remediation_code": "<Write the code snippet to fix the issue. Include 2-3 lines of existing surrounding code and use comments like '// ... existing code ...' so the developer knows exactly where to paste this fix, but do NOT write out the entire file.>"
                    }}
                  ]
                }}
                
                Website Aggregated Data:
                {aggregated_website_data[:500000]} 
                """
                
                ai_data = None
                
                # Heavy-Duty Exponential Backoff (The Battering Ram)
                for attempt in range(AI_MAX_RETRIES):
                    try:
                        ai_response = ai_client.models.generate_content(
                            model='gemini-3.5-flash',
                            contents=ai_prompt,
                            config=types.GenerateContentConfig(
                                response_mime_type="application/json",
                                temperature=0.0
                            )
                        )
                        ai_data = json.loads(ai_response.text)
                        
                        # Inject the scanned URLs into the payload for the React UI
                        ai_data["scanned_urls"] = visited_urls
                        
                        break # Success!
                        
                    except Exception as ai_error:
                        error_str = str(ai_error).upper()
                        if "503" in error_str or "429" in error_str or "UNAVAILABLE" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                            if attempt < AI_MAX_RETRIES - 1:
                                sleep_time = 10 * (2 ** attempt) # Waits 10s, then 20s, then 40s, 80s
                                print(f"   ⚠️ Google AI is busy. Retrying in {sleep_time} seconds... (Attempt {attempt + 2}/{AI_MAX_RETRIES})")
                                time.sleep(sleep_time)
                            else:
                                raise Exception(f"AI failed after {AI_MAX_RETRIES} attempts due to Google rate limits.") from ai_error
                        else:
                            raise ai_error

                if ai_data:
                    print(f"✅ AI Global Score: {ai_data.get('global_score')}/100")
                    print(f"✅ Issue Found: {ai_data.get('top_global_issue')}")
                    
                    # --- STEP 4: Mission Complete ---
                    print("💾 Saving massive AI audit to The Vault...")
                    SUPABASE_CLIENT.table("audit_results").insert({
                        "scan_id": scan_id,
                        "category": "ai_audit_deep_crawl",
                        "raw_data": ai_data
                    }).execute()
                    
                    SUPABASE_CLIENT.table("scans").update({"status": "completed"}).eq("id", scan_id).execute()
                    print("🎉 Spider mission accomplished! Waiting for next job...")
                
            else:
                time.sleep(2)
                
        except Exception as e:
            print(f"❌ Worker hit a critical error: {e}")
            try:
                if scan_id:
                    SUPABASE_CLIENT.table("scans").update({"status": "failed"}).eq("id", scan_id).execute()
            except Exception:
                pass
            time.sleep(5)

if __name__ == "__main__":
    process_queue()